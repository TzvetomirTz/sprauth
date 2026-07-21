import { describe, it, expect, afterAll } from 'vitest';
import supertest from 'supertest';
import app from '../../app.js';
import { disconnectRedis } from '../../services/redis.service.js';
import { SprauthClient } from './sprauthClient.js';

const api = supertest(app);

/**
 * POST /session/refresh — validation and the ways a refresh can be rejected:
 * wrong token type, garbage tokens, and tokens for sessions that have ended.
 */
describe('Session refresh (E2E)', () => {
    afterAll(async () => {
        await disconnectRedis();
    });

    /** Authenticate a fresh client and return its issued tokens + sessionId. */
    const authenticate = async () => {
        const client = new SprauthClient(app);
        const init = await client.initChallenge('login');
        const auth = await client.authenticate(init.body.challengeToken);
        expect(auth.status).toBe(200);
        return { client, ...auth.body as {
            accessToken: string;
            refreshToken: string;
            sessionId: string;
        } };
    };

    it('happy path: a valid refresh token mints a new token pair for the session', async () => {
        const { client, refreshToken, sessionId } = await authenticate();

        const res = await client.refresh(refreshToken);
        expect(res.status).toBe(200);
        expect(res.body.sessionId).toBe(sessionId);
        expect(typeof res.body.accessToken).toBe('string');
        expect(typeof res.body.refreshToken).toBe('string');
    });

    it('a refresh token is single-use: replaying the same token is rejected', async () => {
        const { client, refreshToken } = await authenticate();

        const first = await client.refresh(refreshToken);
        expect(first.status).toBe(200);

        // Refresh tokens are single-use — replaying the consumed token fails.
        const second = await client.refresh(refreshToken);
        expect(second.status).toBe(401);
        expect(second.body.error).toMatch(/already been used|revoked/i);
    });

    it('rotates the refresh token: the newly issued token works after the old one is consumed', async () => {
        const { client, refreshToken } = await authenticate();

        const first = await client.refresh(refreshToken);
        expect(first.status).toBe(200);

        // The rotated refresh token returned by the first refresh is now the valid one.
        const second = await client.refresh(first.body.refreshToken);
        expect(second.status).toBe(200);
        expect(typeof second.body.refreshToken).toBe('string');
    });

    it('rejects a missing refreshToken with 400', async () => {
        const res = await api.post('/session/refresh').send({});
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/refreshToken/i);
    });

    it('rejects an empty refreshToken with 400', async () => {
        const res = await api.post('/session/refresh').send({ refreshToken: '   ' });
        expect(res.status).toBe(400);
    });

    it('rejects a non-string refreshToken with 400', async () => {
        const res = await api.post('/session/refresh').send({ refreshToken: 12345 });
        expect(res.status).toBe(400);
    });

    it('rejects an access token used as a refresh token', async () => {
        const { client, accessToken } = await authenticate();

        const res = await client.refresh(accessToken);
        expect(res.status).toBe(401);
        expect(res.body.error).toMatch(/not a refresh token/i);
    });

    it('rejects a garbage / unverifiable token', async () => {
        const res = await api
            .post('/session/refresh')
            .send({ refreshToken: 'aaa.bbb.ccc' });
        expect(res.status).toBe(401);
    });

    it('rejects a refresh token whose session has been ended', async () => {
        const { client, refreshToken, sessionId } = await authenticate();

        // End the underlying session first.
        const end = await client.endSession(sessionId);
        expect(end.body.ended).toBe(true);

        const res = await client.refresh(refreshToken);
        expect(res.status).toBe(401);
        expect(res.body.error).toMatch(/session/i);
    });
});
