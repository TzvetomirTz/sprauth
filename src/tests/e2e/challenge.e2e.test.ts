import { describe, it, expect, afterAll } from 'vitest';
import supertest from 'supertest';
import app from '../../app.js';
import { disconnectRedis } from '../../services/redis.service.js';
import { SprauthClient, decodeTokenPayload } from './sprauthClient.js';

const api = supertest(app);

/**
 * /challenge/init and /challenge/valid — happy paths, validation, and edge cases.
 */
describe('Challenge endpoints (E2E)', () => {
    afterAll(async () => {
        await disconnectRedis();
    });

    describe('POST /challenge/init', () => {
        it('issues a signed challenge for a well-formed request', async () => {
            const client = new SprauthClient(app);
            const res = await client.initChallenge('login');

            expect(res.status).toBe(200);
            const payload = decodeTokenPayload(res.body.challengeToken);
            expect(payload.identity).toBe(client.identity);
            expect(payload.intent).toBe('login');
            expect(typeof payload.challenge).toBe('string');
            expect(typeof payload.tokenId).toBe('string');
            expect(typeof payload.iat).toBe('number');
        });

        it('carries arbitrary customClaims into the challenge payload', async () => {
            const client = new SprauthClient(app);
            const res = await client.initChallenge('login', { tier: 'premium', foo: 42 });

            expect(res.status).toBe(200);
            const payload = decodeTokenPayload(res.body.challengeToken);
            expect(payload.tier).toBe('premium');
            expect(payload.foo).toBe(42);
        });

        it('does not let customClaims override reserved claims', async () => {
            const client = new SprauthClient(app);
            const res = await client.initChallenge('login', {
                identity: 'pqc1deadbeef',
                intent: 'evil',
                challenge: 'forged-challenge',
                tokenId: 'forged-token-id'
            });

            expect(res.status).toBe(200);
            const payload = decodeTokenPayload(res.body.challengeToken);
            // Reserved fields win over the malicious customClaims.
            expect(payload.identity).toBe(client.identity);
            expect(payload.intent).toBe('login');
            expect(payload.challenge).not.toBe('forged-challenge');
            expect(payload.tokenId).not.toBe('forged-token-id');
        });

        it('rejects a missing identity with 400', async () => {
            const res = await api.post('/challenge/init').send({ intent: 'login' });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/identity/i);
        });

        it('rejects an empty identity with 400', async () => {
            const res = await api
                .post('/challenge/init')
                .send({ identity: '   ', intent: 'login' });
            expect(res.status).toBe(400);
        });

        it('rejects a missing intent with 400', async () => {
            const res = await api
                .post('/challenge/init')
                .send({ identity: 'pqc1abc' });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/intent/i);
        });

        it('rejects a non-string identity with 400', async () => {
            const res = await api
                .post('/challenge/init')
                .send({ identity: 12345, intent: 'login' });
            expect(res.status).toBe(400);
        });
    });

    describe('POST /challenge/valid', () => {
        it('reports a pending challenge as valid without consuming it', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');

            const first = await client.checkChallenge(init.body.challengeToken, false);
            expect(first.status).toBe(200);
            expect(first.body.valid).toBe(true);

            // Non-consuming poll is repeatable.
            const second = await client.checkChallenge(init.body.challengeToken, false);
            expect(second.body.valid).toBe(true);
        });

        it('reports an already-consumed challenge as invalid', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');

            const consume = await client.checkChallenge(init.body.challengeToken, true);
            expect(consume.body.valid).toBe(true);

            const afterConsume = await client.checkChallenge(init.body.challengeToken, false);
            expect(afterConsume.status).toBe(200);
            expect(afterConsume.body.valid).toBe(false);
        });

        it('consuming a challenge removes it (single use)', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');

            const consume = await client.checkChallenge(init.body.challengeToken, true);
            expect(consume.body.valid).toBe(true);

            const afterConsume = await client.checkChallenge(init.body.challengeToken, true);
            expect(afterConsume.body.valid).toBe(false);
        });

        it('rejects a challenge whose client signature does not match with 401', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');

            const res = await client.postCheckChallenge({
                challengeJwt: init.body.challengeToken,
                signature: client.sign('not-the-challenge'),
                publicKey: client.publicKeyBase64,
                consume: false
            });

            expect(res.status).toBe(401);
            expect(res.body.valid).toBe(false);
        });

        it("rejects a challenge signed by a different key than the challenge's identity with 401", async () => {
            const owner = new SprauthClient(app);
            const attacker = new SprauthClient(app);
            const init = await owner.initChallenge('login');
            const { challenge } = decodeTokenPayload(init.body.challengeToken);

            // Attacker signs the correct challenge but presents their own key,
            // which derives a different address than the challenge's identity.
            const res = await attacker.postCheckChallenge({
                challengeJwt: init.body.challengeToken,
                signature: attacker.sign(challenge),
                publicKey: attacker.publicKeyBase64,
                consume: false
            });

            expect(res.status).toBe(401);
            expect(res.body.valid).toBe(false);
        });

        it('rejects a tampered challenge JWT with 401', async () => {
            const client = new SprauthClient(app);
            const res = await client.postCheckChallenge({
                challengeJwt: 'not.a.jwt',
                signature: client.sign('whatever'),
                publicKey: client.publicKeyBase64,
                consume: false
            });

            expect(res.status).toBe(401);
            expect(res.body.valid).toBe(false);
        });

        it('rejects a missing challengeJwt with 400', async () => {
            const client = new SprauthClient(app);
            const res = await client.postCheckChallenge({
                signature: client.sign('x'),
                publicKey: client.publicKeyBase64
            });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/challengeJwt/i);
        });

        it('rejects a missing signature with 400', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');
            const res = await client.postCheckChallenge({
                challengeJwt: init.body.challengeToken,
                publicKey: client.publicKeyBase64
            });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/signature/i);
        });

        it('rejects a missing publicKey with 400', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');
            const res = await client.postCheckChallenge({
                challengeJwt: init.body.challengeToken,
                signature: client.sign('x')
            });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/publicKey/i);
        });

        it('rejects a non-boolean consume flag with 400', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');
            const res = await client.postCheckChallenge({
                challengeJwt: init.body.challengeToken,
                signature: client.sign('x'),
                publicKey: client.publicKeyBase64,
                consume: 'yes'
            });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/consume/i);
        });
    });
});
