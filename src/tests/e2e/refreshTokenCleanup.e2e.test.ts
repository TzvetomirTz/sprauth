import { describe, it, expect, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import {
    storeRefreshToken,
    consumeRefreshToken,
    startSession,
    endSession,
    endUserSessions,
    disconnectRedis
} from '../../services/redis.service.js';

/**
 * Ending a session must proactively delete that session's outstanding refresh
 * token ids (keyed `refresh:<identity>:<sessionId>:<tokenId>`), not just leave
 * them to expire. Asserted at the Redis layer because the /session/refresh route
 * short-circuits on session validity before it ever reaches consumeRefreshToken.
 */
describe('Refresh token cleanup on session end (E2E)', () => {
    afterAll(async () => {
        await disconnectRedis();
    });

    const uniqueIdentity = () => `pqc1${randomUUID().replace(/-/g, '')}`;

    it('endSession deletes the refresh tokens for that session', async () => {
        const identity = uniqueIdentity();
        const sessionId = randomUUID();
        const tokenId = randomUUID();

        await startSession(identity, sessionId);
        await storeRefreshToken(identity, sessionId, tokenId);

        await endSession(identity, sessionId);

        // The token id is gone — consuming it now reports it was not present.
        expect(await consumeRefreshToken(identity, sessionId, tokenId)).toBe(false);
    });

    it('endSession leaves other sessions\' refresh tokens intact', async () => {
        const identity = uniqueIdentity();
        const doomedSession = randomUUID();
        const keptSession = randomUUID();
        const doomedToken = randomUUID();
        const keptToken = randomUUID();

        await startSession(identity, doomedSession);
        await startSession(identity, keptSession);
        await storeRefreshToken(identity, doomedSession, doomedToken);
        await storeRefreshToken(identity, keptSession, keptToken);

        await endSession(identity, doomedSession);

        expect(await consumeRefreshToken(identity, doomedSession, doomedToken)).toBe(false);
        expect(await consumeRefreshToken(identity, keptSession, keptToken)).toBe(true);
    });

    it('endUserSessions deletes refresh tokens except for kept sessions', async () => {
        const identity = uniqueIdentity();
        const revokedSession = randomUUID();
        const keptSession = randomUUID();
        const revokedToken = randomUUID();
        const keptToken = randomUUID();

        await startSession(identity, revokedSession);
        await startSession(identity, keptSession);
        await storeRefreshToken(identity, revokedSession, revokedToken);
        await storeRefreshToken(identity, keptSession, keptToken);

        const revokedCount = await endUserSessions(identity, [keptSession]);
        expect(revokedCount).toBe(1);

        expect(await consumeRefreshToken(identity, revokedSession, revokedToken)).toBe(false);
        expect(await consumeRefreshToken(identity, keptSession, keptToken)).toBe(true);
    });
});
