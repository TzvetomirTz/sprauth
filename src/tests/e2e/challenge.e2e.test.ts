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
            const { tokenId } = decodeTokenPayload(init.body.challengeToken);

            const first = await client.checkChallenge(tokenId, false);
            expect(first.status).toBe(200);
            expect(first.body.valid).toBe(true);

            // Non-consuming poll is repeatable.
            const second = await client.checkChallenge(tokenId, false);
            expect(second.body.valid).toBe(true);
        });

        it('reports an unknown tokenId as invalid', async () => {
            const client = new SprauthClient(app);
            const res = await client.checkChallenge('does-not-exist', false);
            expect(res.status).toBe(200);
            expect(res.body.valid).toBe(false);
        });

        it('consuming a challenge removes it (single use)', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');
            const { tokenId } = decodeTokenPayload(init.body.challengeToken);

            const consume = await client.checkChallenge(tokenId, true);
            expect(consume.body.valid).toBe(true);

            const afterConsume = await client.checkChallenge(tokenId, true);
            expect(afterConsume.body.valid).toBe(false);
        });

        it('rejects a missing identity with 400', async () => {
            const res = await api.post('/challenge/valid').send({ tokenId: 'x' });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/identity/i);
        });

        it('rejects a missing tokenId with 400', async () => {
            const res = await api
                .post('/challenge/valid')
                .send({ identity: 'pqc1abc' });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/tokenId/i);
        });

        it('rejects a non-boolean consume flag with 400', async () => {
            const res = await api
                .post('/challenge/valid')
                .send({ identity: 'pqc1abc', tokenId: 'x', consume: 'yes' });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/consume/i);
        });
    });
});
