import { createClient } from 'redis';

const redisUrl = process.env.SPRAUTH_REDIS_URL || 'redis://localhost:6379';
const challengeTtl = parseInt(process.env.SPRAUTH_CHALLENGE_TTL || '600', 10) // 10min default

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


export const storeChallenge = (tokenId: string) => {
    redisClient.set(`${redisChallengeNamespace}:${tokenId}`, tokenId, {
        expiration: { type: 'EX', value: challengeTtl }
    });
}

export const consumeChallenge = async (tokenId: string) => {
    const challenge = await redisClient.getDel(`${redisChallengeNamespace}:${tokenId}`);

    if (challenge === null) {
        throw new Error(`Challenge ${tokenId} not found or already consumed`);
    }

    return challenge;
}
