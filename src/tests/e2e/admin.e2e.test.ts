import { describe, it, expect, afterAll } from 'vitest';
import supertest from 'supertest';
import app from '../../app.js';
import { disconnectRedis } from '../../services/redis.service.js';
import { SprauthClient } from './sprauthClient.js';

const api = supertest(app);

/**
 * /admin/challenges/count[/all] and /admin/sessions/count[/all] — operational
 * counters. Asserted per-identity so they're deterministic in a shared Redis
 * (the system-wide /all counts only get monotonicity/shape checks).
 *
 * NB: these routes are currently unauthenticated.
 */
describe('Admin counters (E2E)', () => {
    afterAll(async () => {
        await disconnectRedis();
    });

    describe('GET /admin/challenges/count', () => {
        it('tracks outstanding challenges for an identity across its lifecycle', async () => {
            const client = new SprauthClient(app);

            expect((await client.countActiveChallenges()).body.count).toBe(0);

            await client.initChallenge('login');
            expect((await client.countActiveChallenges()).body.count).toBe(1);

            await client.initChallenge('login');
            expect((await client.countActiveChallenges()).body.count).toBe(2);
        });

        it('drops the count once a challenge is consumed by authentication', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');
            expect((await client.countActiveChallenges()).body.count).toBe(1);

            const auth = await client.authenticate(init.body.challengeToken);
            expect(auth.status).toBe(200);

            // Authentication consumes the challenge.
            expect((await client.countActiveChallenges()).body.count).toBe(0);
        });

        it('rejects a missing identity with 400', async () => {
            const res = await api.get('/admin/challenges/count');
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/identity/i);
        });
    });

    describe('GET /admin/sessions/count', () => {
        it('tracks active sessions for an identity', async () => {
            const client = new SprauthClient(app);
            expect((await client.countActiveSessions()).body.count).toBe(0);

            for (let i = 0; i < 2; i++) {
                const init = await client.initChallenge('login');
                await client.authenticate(init.body.challengeToken);
            }
            expect((await client.countActiveSessions()).body.count).toBe(2);

            // Ending a session decrements the counter.
            const [firstSession] = (await client.listSessions()).body.sessions;
            await client.endSession(firstSession);
            expect((await client.countActiveSessions()).body.count).toBe(1);
        });

        it('rejects a missing identity with 400', async () => {
            const res = await api.get('/admin/sessions/count');
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/identity/i);
        });
    });

    // The system-wide /all counts share one Redis with every other suite running
    // in parallel, so absolute before/after deltas are non-deterministic. Instead
    // we assert the invariant that always holds: /all is a superset of a single
    // identity's (deterministic) count.
    describe('GET /admin/*/count/all', () => {
        it('returns a system-wide challenge count that is a superset of one identity', async () => {
            const client = new SprauthClient(app);
            await client.initChallenge('login');
            await client.initChallenge('login');

            const identityCount = (await client.countActiveChallenges()).body.count;
            expect(identityCount).toBe(2);

            const allCount = (await api.get('/admin/challenges/count/all')).body.count;
            expect(typeof allCount).toBe('number');
            expect(allCount).toBeGreaterThanOrEqual(identityCount);
        });

        it('returns a system-wide session count that is a superset of one identity', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');
            await client.authenticate(init.body.challengeToken);

            const identityCount = (await client.countActiveSessions()).body.count;
            expect(identityCount).toBe(1);

            const allCount = (await api.get('/admin/sessions/count/all')).body.count;
            expect(typeof allCount).toBe('number');
            expect(allCount).toBeGreaterThanOrEqual(identityCount);
        });
    });
});
