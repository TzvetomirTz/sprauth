import { createClient } from 'redis';

const redisUrl = process.env.SPRAUTH_REDIS_URL || 'redis://localhost:6379';
const challengeTtl = parseInt(process.env.SPRAUTH_CHALLENGE_TTL || '600', 10) // 10 mins default
const sessionTtl = parseInt(process.env.SPRAUTH_SESSION_TTL || '2592000', 10) // 30 days default

const redisChallengeNamespace = 'challenge';
const redisSessionNamespace = 'session';

const redisClient = createClient({
  url: redisUrl
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));

(async () => {
  await redisClient.connect();
  console.log('Connected to Redis successfully');
})();


export const storeChallenge = async (identity: string, tokenId: string) => {
    await redisClient.set(`${redisChallengeNamespace}:${identity}:${tokenId}`, tokenId, {
        expiration: { type: 'EX', value: challengeTtl }
    });
}

export const checkIsChallengeValid = async (identity: string, tokenId: string, consume: boolean = false) : Promise<boolean> => {
    const key = `${redisChallengeNamespace}:${identity}:${tokenId}`;
    const challenge = consume
        ? await redisClient.getDel(key)
        : await redisClient.get(key);

    return challenge !== null;
}

export const consumeChallenge = async (identity: string, tokenId: string) => {
    const challenge = await redisClient.getDel(`${redisChallengeNamespace}:${identity}:${tokenId}`);

    if (challenge === null) {
        throw new Error(`Challenge ${tokenId} not found or already consumed`);
    }

    return challenge;
}

export const startSession = async (identity:string, sessionId: string) => {
    await redisClient.set(`${redisSessionNamespace}:${identity}:${sessionId}`, sessionId, {
        expiration: { type: 'EX', value: sessionTtl }
    });
}

export const getAllUserSessions = async (identity: string): Promise<string[]> => {
    const pattern = `${redisSessionNamespace}:${identity}:*`;
    const sessionKeys: string[] = [];

    for await (const keysBatch of redisClient.scanIterator({ MATCH: pattern })) {
        sessionKeys.push(...keysBatch);
    }

    if (sessionKeys.length === 0) {
        return [];
    }

    const sessions = await redisClient.mGet(sessionKeys);

    return sessions.filter((session): session is string => session !== null);
};

export const checkIsSessionValid = async (identity:string, sessionId: string, renewTtl: boolean) : Promise<boolean> => {
    const sessionKey = `${redisSessionNamespace}:${identity}:${sessionId}`;
    const session = await redisClient.get(sessionKey);

    if (!session) {
        return false;
    }

    if (renewTtl) {
        await redisClient.expire(sessionKey, sessionTtl);
    }

    return true;
}

export const endSession = async (identity:string, sessionId: string) => {
    await redisClient.del(`${redisSessionNamespace}:${identity}:${sessionId}`);
}

export const endUserSessions = async (identity: string, except: string[]): Promise<number> => {
    const pattern = `${redisSessionNamespace}:${identity}:*`;
    const keysToDelete: string[] = [];

    const keysToKeep = new Set(
        except.map(sessionId => `${redisSessionNamespace}:${identity}:${sessionId}`)
    );

    for await (const keysBatch of redisClient.scanIterator({ MATCH: pattern })) {
        const filteredBatch = keysBatch.filter(key => !keysToKeep.has(key));
        
        keysToDelete.push(...filteredBatch);
    }

    if (keysToDelete.length > 0) {
        await redisClient.unlink(keysToDelete as [string, ...string[]]);
    }

    return keysToDelete.length;
};
