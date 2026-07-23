import { describe, it, expect, afterAll } from 'vitest';
import app from '../../app.js';
import { disconnectRedis } from '../../services/redis.service.js';
import { SprauthClient, decodeTokenPayload } from './sprauthClient.js';

/**
 * API scenario (E2E) tests.
 *
 * Instead of poking endpoints in isolation, each test walks a full user journey,
 * chaining real HTTP calls through Supertest and feeding each response into the
 * next request. Real ML-DSA-65 signing and a real Redis instance are exercised —
 * nothing in the auth/session path is mocked.
 *
 * Every test spins up a fresh `SprauthClient` (its own keypair => its own unique
 * `pqc1...` identity), so journeys are isolated from one another even though they
 * share one Redis database.
 */
describe('Auth journeys (E2E)', () => {
    afterAll(async () => {
        await disconnectRedis();
    });

    it('Journey: init a challenge, then consume it', async () => {
        const client = new SprauthClient(app);

        // 1. Init challenge
        const initRes = await client.initChallenge('login');
        expect(initRes.status).toBe(200);
        expect(typeof initRes.body.challengeToken).toBe('string');

        const challenge = decodeTokenPayload(initRes.body.challengeToken);
        expect(challenge.identity).toBe(client.identity);
        expect(challenge.intent).toBe('login');
        expect(typeof challenge.tokenId).toBe('string');

        // The freshly-issued challenge is pending — a non-consuming poll sees it.
        const pollRes = await client.checkChallenge(initRes.body.challengeToken, false);
        expect(pollRes.status).toBe(200);
        expect(pollRes.body.valid).toBe(true);

        // 2. Consume challenge — still reported valid, but atomically removed.
        const consumeRes = await client.checkChallenge(initRes.body.challengeToken, true);
        expect(consumeRes.status).toBe(200);
        expect(consumeRes.body.valid).toBe(true);

        // Once consumed, the challenge is gone: a follow-up poll is no longer valid.
        const afterConsumeRes = await client.checkChallenge(initRes.body.challengeToken, false);
        expect(afterConsumeRes.status).toBe(200);
        expect(afterConsumeRes.body.valid).toBe(false);
    });

    it('Journey: init a challenge, authenticate, then refresh the session', async () => {
        const client = new SprauthClient(app);

        // 1. Init challenge
        const initRes = await client.initChallenge('login');
        expect(initRes.status).toBe(200);

        // 2. Authenticate with the challenge (client signs the challenge string).
        const authRes = await client.authenticate(initRes.body.challengeToken);
        expect(authRes.status).toBe(200);
        expect(authRes.body.challengePassed).toBe(true);
        expect(typeof authRes.body.accessToken).toBe('string');
        expect(typeof authRes.body.refreshToken).toBe('string');
        expect(typeof authRes.body.sessionId).toBe('string');

        const { sessionId, refreshToken } = authRes.body;

        // The session id is baked into the issued tokens, not just the JSON body.
        const accessPayload = decodeTokenPayload(authRes.body.accessToken);
        expect(accessPayload.sessionId).toBe(sessionId);
        expect(accessPayload.identity).toBe(client.identity);
        expect(accessPayload.tokenType).toBe('accessToken');

        const refreshPayload = decodeTokenPayload(refreshToken);
        expect(refreshPayload.tokenType).toBe('refreshToken');

        // Authentication opened a real session.
        const validBefore = await client.checkSession(sessionId);
        expect(validBefore.status).toBe(200);
        expect(validBefore.body.valid).toBe(true);

        // 3. Refresh the session with the refresh token.
        const refreshRes = await client.refresh(refreshToken);
        expect(refreshRes.status).toBe(200);
        expect(refreshRes.body.sessionId).toBe(sessionId);
        expect(typeof refreshRes.body.accessToken).toBe('string');
        expect(typeof refreshRes.body.refreshToken).toBe('string');

        // The refreshed access token still points at the same live session.
        const refreshedAccess = decodeTokenPayload(refreshRes.body.accessToken);
        expect(refreshedAccess.sessionId).toBe(sessionId);
        expect(refreshedAccess.identity).toBe(client.identity);
        expect(refreshedAccess.tokenType).toBe('accessToken');

        const validAfter = await client.checkSession(sessionId);
        expect(validAfter.body.valid).toBe(true);
    });

    it('Journey: init a challenge, authenticate, then end the session', async () => {
        const client = new SprauthClient(app);

        // 1. Init challenge  +  2. Authenticate
        const initRes = await client.initChallenge('login');
        const authRes = await client.authenticate(initRes.body.challengeToken);
        expect(authRes.status).toBe(200);
        expect(authRes.body.challengePassed).toBe(true);

        const { sessionId, refreshToken } = authRes.body;

        const validBefore = await client.checkSession(sessionId);
        expect(validBefore.body.valid).toBe(true);

        // 3. End the session.
        const endRes = await client.endSession(sessionId);
        expect(endRes.status).toBe(200);
        expect(endRes.body.ended).toBe(true);

        // The session is gone...
        const validAfter = await client.checkSession(sessionId);
        expect(validAfter.body.valid).toBe(false);

        // ...so its refresh token can no longer mint new tokens.
        const refreshRes = await client.refresh(refreshToken);
        expect(refreshRes.status).toBe(401);
    });

    it('Journey: two sessions for one identity, then revoke all but the latest', async () => {
        const client = new SprauthClient(app);

        // 1. Init challenge  +  2. Authenticate  => first session (e.g. "device A")
        const firstInit = await client.initChallenge('login');
        const firstAuth = await client.authenticate(firstInit.body.challengeToken);
        expect(firstAuth.status).toBe(200);
        const firstSessionId: string = firstAuth.body.sessionId;

        // 3. Init challenge  +  4. Authenticate again => second session ("device B").
        // A fresh challenge is required each time; challenges are single-use.
        const secondInit = await client.initChallenge('login');
        const secondAuth = await client.authenticate(secondInit.body.challengeToken);
        expect(secondAuth.status).toBe(200);
        const secondSessionId: string = secondAuth.body.sessionId;

        expect(firstSessionId).not.toBe(secondSessionId);

        // Both sessions are live before revocation.
        const listBefore = await client.listSessions();
        expect(listBefore.status).toBe(200);
        expect(listBefore.body.sessions).toHaveLength(2);
        expect(listBefore.body.sessions).toEqual(
            expect.arrayContaining([firstSessionId, secondSessionId])
        );

        const countBefore = await client.countActiveSessions();
        expect(countBefore.body.count).toBe(2);

        // 5. Revoke all sessions except the latest one.
        const revokeRes = await client.revokeOtherSessions([secondSessionId]);
        expect(revokeRes.status).toBe(200);
        expect(revokeRes.body.revokedCount).toBe(1);

        // The older session is invalidated; the kept one survives.
        const firstValid = await client.checkSession(firstSessionId);
        expect(firstValid.body.valid).toBe(false);

        const secondValid = await client.checkSession(secondSessionId);
        expect(secondValid.body.valid).toBe(true);

        const listAfter = await client.listSessions();
        expect(listAfter.body.sessions).toEqual([secondSessionId]);
    });
});
