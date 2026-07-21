import { describe, it, expect, afterAll } from 'vitest';
import app from '../../app.js';
import { disconnectRedis } from '../../services/redis.service.js';
import { SprauthClient, decodeTokenPayload } from './sprauthClient.js';

/**
 * POST /session/auth — the security-critical endpoint. These exercise the ways a
 * challenge-response can legitimately fail: bad signatures, wrong keys, replays,
 * and tampered/forged challenge tokens. Every failure must yield 401 and mint no
 * tokens or session.
 */
describe('Session auth failures (E2E)', () => {
    afterAll(async () => {
        await disconnectRedis();
    });

    const expectRejected = (body: any) => {
        expect(body.challengePassed).toBeFalsy();
        expect(body.accessToken).toBeFalsy();
        expect(body.refreshToken).toBeFalsy();
        expect(body.sessionId).toBeFalsy();
    };

    it('accepts a valid challenge-response (control / happy path)', async () => {
        const client = new SprauthClient(app);
        const init = await client.initChallenge('login');
        const res = await client.authenticate(init.body.challengeToken);

        expect(res.status).toBe(200);
        expect(res.body.challengePassed).toBe(true);
    });

    it('rejects a signature over the wrong message', async () => {
        const client = new SprauthClient(app);
        const init = await client.initChallenge('login');

        // Correct identity + public key, but signature is over a different string.
        const res = await client.postAuth({
            challengeJwt: init.body.challengeToken,
            signature: client.sign('not-the-real-challenge'),
            publicKey: client.publicKeyBase64
        });

        expect(res.status).toBe(401);
        expectRejected(res.body);
    });

    it('rejects a signature made with a different keypair (address mismatch)', async () => {
        const victim = new SprauthClient(app);
        const attacker = new SprauthClient(app);
        const init = await victim.initChallenge('login');
        const { challenge } = decodeTokenPayload(init.body.challengeToken);

        // Attacker signs the real challenge with their own key and presents their
        // own public key — but the challenge token's identity is the victim's, so
        // the derived address won't match.
        const res = await victim.postAuth({
            challengeJwt: init.body.challengeToken,
            signature: attacker.sign(challenge),
            publicKey: attacker.publicKeyBase64
        });

        expect(res.status).toBe(401);
        expectRejected(res.body);
    });

    it('rejects a valid signature presented with the wrong public key', async () => {
        const client = new SprauthClient(app);
        const other = new SprauthClient(app);
        const init = await client.initChallenge('login');
        const { challenge } = decodeTokenPayload(init.body.challengeToken);

        // Signature is genuinely the client's, but the public key sent belongs to
        // someone else -> address derived from it won't match the token identity.
        const res = await client.postAuth({
            challengeJwt: init.body.challengeToken,
            signature: client.sign(challenge),
            publicKey: other.publicKeyBase64
        });

        expect(res.status).toBe(401);
        expectRejected(res.body);
    });

    it('rejects a replayed challenge (single use)', async () => {
        const client = new SprauthClient(app);
        const init = await client.initChallenge('login');

        const first = await client.authenticate(init.body.challengeToken);
        expect(first.status).toBe(200);
        expect(first.body.challengePassed).toBe(true);

        // Same challenge token, second time -> already consumed in Redis -> 401.
        const replay = await client.authenticate(init.body.challengeToken);
        expect(replay.status).toBe(401);
        expectRejected(replay.body);
    });

    it('rejects a challenge token with a tampered payload', async () => {
        const client = new SprauthClient(app);
        const init = await client.initChallenge('login');
        const [header, payloadB64, signature] = init.body.challengeToken.split('.');

        // Flip the intent inside the payload; the server signature no longer matches.
        const payload = decodeTokenPayload(init.body.challengeToken);
        payload.intent = 'transfer-funds';
        const forgedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const tamperedToken = `${header}.${forgedPayload}.${signature}`;

        const res = await client.postAuth({
            challengeJwt: tamperedToken,
            signature: client.sign(payload.challenge),
            publicKey: client.publicKeyBase64
        });

        expect(res.status).toBe(401);
        expectRejected(res.body);
    });

    it('rejects a completely malformed challenge token', async () => {
        const client = new SprauthClient(app);
        const res = await client.postAuth({
            challengeJwt: 'not-a-real-token',
            signature: client.sign('whatever'),
            publicKey: client.publicKeyBase64
        });

        expect(res.status).toBe(401);
        expectRejected(res.body);
    });

    it('rejects an unsolicited challenge that was never issued by the server', async () => {
        const client = new SprauthClient(app);
        // A structurally plausible but never-issued token: three base64url segments.
        const fakePayload = Buffer.from(
            JSON.stringify({
                iat: Date.now(),
                identity: client.identity,
                intent: 'login',
                challenge: 'self-made-challenge',
                tokenId: crypto.randomUUID()
            })
        ).toString('base64url');
        const fakeToken = `${Buffer.from('{}').toString('base64url')}.${fakePayload}.${Buffer.from('sig').toString('base64url')}`;

        const res = await client.postAuth({
            challengeJwt: fakeToken,
            signature: client.sign('self-made-challenge'),
            publicKey: client.publicKeyBase64
        });

        expect(res.status).toBe(401);
        expectRejected(res.body);
    });
});
