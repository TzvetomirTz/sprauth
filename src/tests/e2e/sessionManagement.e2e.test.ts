import { describe, it, expect, afterAll } from 'vitest';
import supertest from 'supertest';
import app from '../../app.js';
import { disconnectRedis } from '../../services/redis.service.js';
import { SprauthClient } from './sprauthClient.js';

const api = supertest(app);

/**
 * /session/ (list), /session/valid, /session/end, /session/revoke — the session
 * management surface. Covers happy behaviour, validation, and idempotency edges.
 *
 * NB: /session/ (list) and /session/valid remain unauthenticated (identity is taken
 * as-is). /session/end and /session/revoke require a `Bearer` access token and derive
 * the caller identity from it, so those tests exercise the authorization model too.
 */
describe('Session management (E2E)', () => {
    afterAll(async () => {
        await disconnectRedis();
    });

    /** Authenticate `count` separate sessions for one identity, return the client + session ids. */
    const openSessions = async (count: number) => {
        const client = new SprauthClient(app);
        const sessionIds: string[] = [];

        for (let i = 0; i < count; i++) {
            const init = await client.initChallenge('login');
            const auth = await client.authenticate(init.body.challengeToken);
            expect(auth.status).toBe(200);
            sessionIds.push(auth.body.sessionId);
        }

        return { client, sessionIds };
    };

    describe('GET /session/ (list)', () => {
        it('lists all active sessions for an identity', async () => {
            const { client, sessionIds } = await openSessions(3);

            const res = await client.listSessions();
            expect(res.status).toBe(200);
            expect(res.body.sessions).toHaveLength(3);
            expect(res.body.sessions).toEqual(expect.arrayContaining(sessionIds));
        });

        it('returns an empty list for an identity with no sessions', async () => {
            const client = new SprauthClient(app);
            const res = await client.listSessions();
            expect(res.status).toBe(200);
            expect(res.body.sessions).toEqual([]);
        });

        it('rejects a missing identity with 400', async () => {
            const res = await api.get('/session/');
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/identity/i);
        });
    });

    describe('GET /session/valid', () => {
        it('reports a live session as valid', async () => {
            const { client, sessionIds } = await openSessions(1);
            const res = await client.checkSession(sessionIds[0]!);
            expect(res.status).toBe(200);
            expect(res.body.valid).toBe(true);
        });

        it('reports an unknown session as invalid', async () => {
            const client = new SprauthClient(app);
            const res = await client.checkSession('no-such-session');
            expect(res.status).toBe(200);
            expect(res.body.valid).toBe(false);
        });

        it('renews the session TTL when renewTtl=true and keeps it valid', async () => {
            const { client, sessionIds } = await openSessions(1);
            const res = await client.checkSession(sessionIds[0]!, true);
            expect(res.status).toBe(200);
            expect(res.body.valid).toBe(true);
        });

        it('rejects a missing identity with 400', async () => {
            const res = await api.get('/session/valid').query({ sessionId: 'x' });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/identity/i);
        });

        it('rejects a missing sessionId with 400', async () => {
            const res = await api.get('/session/valid').query({ identity: 'pqc1abc' });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/sessionId/i);
        });
    });

    describe('POST /session/end', () => {
        it('ends a specific session and leaves the others intact', async () => {
            const { client, sessionIds } = await openSessions(2);

            const end = await client.endSession(sessionIds[0]!);
            expect(end.status).toBe(200);
            expect(end.body.ended).toBe(true);

            expect((await client.checkSession(sessionIds[0]!)).body.valid).toBe(false);
            expect((await client.checkSession(sessionIds[1]!)).body.valid).toBe(true);
        });

        it('is idempotent — ending an unknown session still reports ended', async () => {
            const { client } = await openSessions(1);
            const res = await client.endSession('never-existed');
            expect(res.status).toBe(200);
            expect(res.body.ended).toBe(true);
        });

        it('rejects a request with no access token with 401', async () => {
            const { sessionIds } = await openSessions(1);
            const res = await api.post('/session/end').send({ sessionId: sessionIds[0] });
            expect(res.status).toBe(401);
        });

        it('rejects a missing sessionId with 400', async () => {
            const { client } = await openSessions(1);
            const res = await client.endSession('');
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/sessionId/i);
        });

        it("cannot end another identity's session", async () => {
            const { client: attacker } = await openSessions(1);
            const { client: victim, sessionIds: victimSessions } = await openSessions(1);

            // Attacker presents their own valid access token; identity is derived from it,
            // so the victim's session is untouched.
            const res = await attacker.endSession(victimSessions[0]!);
            expect(res.status).toBe(200);
            expect((await victim.checkSession(victimSessions[0]!)).body.valid).toBe(true);
        });
    });

    describe('POST /session/revoke', () => {
        it('revokes every session when no keep-list is given', async () => {
            const { client } = await openSessions(3);

            const res = await client.revokeOtherSessions([]);
            expect(res.status).toBe(200);
            expect(res.body.revokedCount).toBe(3);

            expect((await client.listSessions()).body.sessions).toEqual([]);
        });

        it('revokes all sessions except the ones in the keep-list', async () => {
            const { client, sessionIds } = await openSessions(3);
            const keep = sessionIds[2]!;

            const res = await client.revokeOtherSessions([keep]);
            expect(res.status).toBe(200);
            expect(res.body.revokedCount).toBe(2);

            const remaining = (await client.listSessions()).body.sessions;
            expect(remaining).toEqual([keep]);
        });

        it('revokes nothing when the keep-list covers every session', async () => {
            const { client, sessionIds } = await openSessions(2);

            const res = await client.revokeOtherSessions(sessionIds);
            expect(res.status).toBe(200);
            expect(res.body.revokedCount).toBe(0);
            expect((await client.listSessions()).body.sessions).toHaveLength(2);
        });

        it('rejects a request with no access token with 401', async () => {
            await openSessions(1);
            const res = await api.post('/session/revoke').send({ except: [] });
            expect(res.status).toBe(401);
        });

        it('rejects a non-array except with 400', async () => {
            const { client } = await openSessions(1);
            const res = await client.revokeOtherSessions('not-an-array' as unknown as string[]);
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/except/i);
        });

        it("only revokes the caller's own sessions, not another identity's", async () => {
            const { client: attacker } = await openSessions(1);
            const { client: victim } = await openSessions(2);

            const res = await attacker.revokeOtherSessions([]);
            expect(res.status).toBe(200);
            expect(res.body.revokedCount).toBe(1);
            expect((await victim.listSessions()).body.sessions).toHaveLength(2);
        });
    });

    describe('Access-token gating on /session/end & /session/revoke', () => {
        it('rejects a malformed bearer token with 401', async () => {
            const res = await api
                .post('/session/end')
                .set('Authorization', 'Bearer not-a-real-token')
                .send({ sessionId: 'x' });
            expect(res.status).toBe(401);
        });

        it('revokes the access token when its session is ended', async () => {
            const { client, sessionIds } = await openSessions(1);

            // The end call itself is authorized (token still live at check time)...
            const end = await client.endSession(sessionIds[0]!);
            expect(end.status).toBe(200);

            // ...but ending the session deletes its access-token entry, so the same token
            // can no longer authorize a follow-up privileged call.
            const second = await client.endSession(sessionIds[0]!);
            expect(second.status).toBe(401);
            expect(second.body.error).toMatch(/expired|revoked/i);
        });

        it('revokes the access token when its session is revoked', async () => {
            const { client } = await openSessions(1);

            const revoke = await client.revokeOtherSessions([]);
            expect(revoke.status).toBe(200);
            expect(revoke.body.revokedCount).toBe(1);

            const after = await client.endSession('any-session');
            expect(after.status).toBe(401);
            expect(after.body.error).toMatch(/expired|revoked/i);
        });

        it('rejects a refresh token used as an access token with 401', async () => {
            const client = new SprauthClient(app);
            const init = await client.initChallenge('login');
            const auth = await client.authenticate(init.body.challengeToken);
            const refreshToken = auth.body.refreshToken as string;

            const res = await api
                .post('/session/end')
                .set('Authorization', `Bearer ${refreshToken}`)
                .send({ sessionId: auth.body.sessionId });
            expect(res.status).toBe(401);
            expect(res.body.error).toMatch(/access token/i);
        });
    });
});
