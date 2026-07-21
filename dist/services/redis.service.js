import { createClient } from 'redis';
const redisUrl = process.env.SPRAUTH_REDIS_URL || 'redis://localhost:6379';
const challengeTtl = parseInt(process.env.SPRAUTH_CHALLENGE_TTL || '600', 10); // 10 mins default
const sessionTtl = parseInt(process.env.SPRAUTH_SESSION_TTL || '2592000', 10); // 30 days default
const accessTokenTtl = parseInt(process.env.SPRAUTH_ACCESS_TOKEN_TTL || '3600', 10); // 1hr default
const refreshTokenTtl = parseInt(process.env.SPRAUTH_REFRESH_TOKEN_TTL || '604800', 10); // 1wk default
const redisChallengeNamespace = 'challenge';
const redisSessionNamespace = 'session';
const redisRefreshNamespace = 'refresh';
const redisAccessNamespace = 'access';
const redisClient = createClient({
    url: redisUrl
});
redisClient.on('error', (err) => console.error('Redis Client Error', err));
(async () => {
    try {
        await redisClient.connect();
        console.log('Connected to Redis successfully');
    }
    catch (err) {
        console.error('Failed to connect to Redis', err);
    }
})();
export const disconnectRedis = async () => {
    if (redisClient.isOpen) {
        await redisClient.close();
    }
};
const countKeysByPattern = async (pattern) => {
    let count = 0;
    for await (const keysBatch of redisClient.scanIterator({ MATCH: pattern })) {
        count += keysBatch.length;
    }
    return count;
};
const scanKeys = async (pattern) => {
    const keys = [];
    for await (const keysBatch of redisClient.scanIterator({ MATCH: pattern })) {
        keys.push(...keysBatch);
    }
    return keys;
};
const unlinkKeys = async (keys) => {
    if (keys.length > 0) {
        await redisClient.unlink(keys);
    }
    return keys.length;
};
export const storeChallenge = async (identity, tokenId) => {
    await redisClient.set(`${redisChallengeNamespace}:${identity}:${tokenId}`, tokenId, {
        expiration: { type: 'EX', value: challengeTtl }
    });
};
export const checkIsChallengeValid = async (identity, tokenId, consume = false) => {
    const key = `${redisChallengeNamespace}:${identity}:${tokenId}`;
    const challenge = consume
        ? await redisClient.getDel(key)
        : await redisClient.get(key);
    return challenge !== null;
};
export const consumeChallenge = async (identity, tokenId) => {
    const challenge = await redisClient.getDel(`${redisChallengeNamespace}:${identity}:${tokenId}`);
    if (challenge === null) {
        throw new Error(`Challenge ${tokenId} not found or already consumed`);
    }
    return challenge;
};
export const countUserActiveChallenges = async (identity) => {
    return countKeysByPattern(`${redisChallengeNamespace}:${identity}:*`);
};
export const countAllActiveChallenges = async () => {
    return countKeysByPattern(`${redisChallengeNamespace}:*`);
};
export const storeRefreshToken = async (identity, sessionId, tokenId) => {
    await redisClient.set(`${redisRefreshNamespace}:${identity}:${sessionId}:${tokenId}`, tokenId, {
        expiration: { type: 'EX', value: refreshTokenTtl }
    });
};
export const consumeRefreshToken = async (identity, sessionId, tokenId) => {
    const token = await redisClient.getDel(`${redisRefreshNamespace}:${identity}:${sessionId}:${tokenId}`);
    return token !== null;
};
const deleteSessionRefreshTokens = async (identity, sessionId) => {
    const keys = await scanKeys(`${redisRefreshNamespace}:${identity}:${sessionId}:*`);
    await unlinkKeys(keys);
};
export const storeAccessToken = async (identity, sessionId, tokenId) => {
    await redisClient.set(`${redisAccessNamespace}:${identity}:${sessionId}:${tokenId}`, tokenId, {
        expiration: { type: 'EX', value: accessTokenTtl }
    });
};
export const checkIsAccessTokenValid = async (identity, sessionId, tokenId) => {
    // A plain read — access tokens are multi-use, so (unlike consumeRefreshToken) this does
    // not delete the entry. Presence means the token is neither expired (Redis TTL) nor
    // revoked (deleted when the session ends).
    const token = await redisClient.get(`${redisAccessNamespace}:${identity}:${sessionId}:${tokenId}`);
    return token !== null;
};
const deleteSessionAccessTokens = async (identity, sessionId) => {
    const keys = await scanKeys(`${redisAccessNamespace}:${identity}:${sessionId}:*`);
    await unlinkKeys(keys);
};
export const startSession = async (identity, sessionId) => {
    await redisClient.set(`${redisSessionNamespace}:${identity}:${sessionId}`, sessionId, {
        expiration: { type: 'EX', value: sessionTtl }
    });
};
export const getAllUserSessions = async (identity) => {
    const sessionKeys = await scanKeys(`${redisSessionNamespace}:${identity}:*`);
    if (sessionKeys.length === 0) {
        return [];
    }
    const sessions = await redisClient.mGet(sessionKeys);
    return sessions.filter((session) => session !== null);
};
export const checkIsSessionValid = async (identity, sessionId, renewTtl) => {
    const sessionKey = `${redisSessionNamespace}:${identity}:${sessionId}`;
    const session = await redisClient.get(sessionKey);
    if (!session) {
        return false;
    }
    if (renewTtl) {
        await redisClient.expire(sessionKey, sessionTtl);
    }
    return true;
};
// Renew a session's TTL. `expire` on a missing key is a no-op (returns 0), so this is safe
// to call without re-checking existence.
export const renewSession = async (identity, sessionId) => {
    await redisClient.expire(`${redisSessionNamespace}:${identity}:${sessionId}`, sessionTtl);
};
export const endSession = async (identity, sessionId) => {
    await redisClient.del(`${redisSessionNamespace}:${identity}:${sessionId}`);
    await deleteSessionRefreshTokens(identity, sessionId);
    await deleteSessionAccessTokens(identity, sessionId);
};
export const endUserSessions = async (identity, except) => {
    // A session id lives at index 2 of the `session:<identity>:<sessionId>`,
    // `refresh:<identity>:<sessionId>:<tokenId>` and `access:<identity>:<sessionId>:<tokenId>`
    // keys, so the same keep-list filters all three.
    const sessionIdOf = (key) => key.split(':')[2];
    const keptSessionIds = new Set(except);
    const sessionKeys = await scanKeys(`${redisSessionNamespace}:${identity}:*`);
    const sessionKeysToDelete = sessionKeys.filter(key => !keptSessionIds.has(sessionIdOf(key)));
    const refreshKeys = await scanKeys(`${redisRefreshNamespace}:${identity}:*`);
    const refreshKeysToDelete = refreshKeys.filter(key => !keptSessionIds.has(sessionIdOf(key)));
    const accessKeys = await scanKeys(`${redisAccessNamespace}:${identity}:*`);
    const accessKeysToDelete = accessKeys.filter(key => !keptSessionIds.has(sessionIdOf(key)));
    await unlinkKeys([...sessionKeysToDelete, ...refreshKeysToDelete, ...accessKeysToDelete]);
    return sessionKeysToDelete.length;
};
export const countUserActiveSessions = async (identity) => {
    return countKeysByPattern(`${redisSessionNamespace}:${identity}:*`);
};
export const countAllActiveSessions = async () => {
    return countKeysByPattern(`${redisSessionNamespace}:*`);
};
//# sourceMappingURL=redis.service.js.map