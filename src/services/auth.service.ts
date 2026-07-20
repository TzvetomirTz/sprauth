import { generateSafeRandomString, getSecretKey, sign } from './sec.service.js';
import { storeChallenge } from './redis.service.js'

// const accessTokenTtl = process.env.SPRAUTH_ACCESS_TOKEN_TTL || 3600000; // 1hr default
// const refreshTokenTtl = process.env.SPRAUTH_REFRESH_TOKEN_TTL || 604800000; // 1wk default

export const generateChallengeToken = async (identity: string, intent: string, customClaims: object) => {
    const issuedAtUnixMs = Date.now();
    const challengeString = generateSafeRandomString();
    const secretKey = getSecretKey();
    const tokenId = crypto.randomUUID();

    const challenge = sign({
        ...customClaims,
        iat: issuedAtUnixMs,
        identity,
        intent,
        challenge: challengeString,
        tokenId
    }, secretKey);

    await storeChallenge(identity, tokenId);

    return challenge;
}

export const generateAuthToken = (challengeToken: object, tokenType: string) => {
    const issuedAtUnixMs = Date.now();
    const secretKey = getSecretKey();

    const token = sign({
        ...challengeToken,
        intent: undefined,
        challenge: undefined,
        iat: issuedAtUnixMs,
        tokenType
    }, secretKey);

    return token;
}
