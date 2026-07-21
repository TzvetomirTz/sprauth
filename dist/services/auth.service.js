import { generateSafeRandomString, getSecretKey, sign } from './sec.service.js';
import { storeChallenge, storeRefreshToken, storeAccessToken } from './redis.service.js';
// Token liveness is entirely Redis-backed — access and refresh tokens each get an entry
// (`access:`/`refresh:` namespaces in redis.service, TTL'd by SPRAUTH_ACCESS_TOKEN_TTL /
// SPRAUTH_REFRESH_TOKEN_TTL) that expires and is revoked on session end. Payloads still carry
// an `iat`, but nothing checks it.
export const generateChallengeToken = async (identity, intent, customClaims) => {
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
};
export const generateAuthToken = (challengeToken, tokenType, extraClaims = {}) => {
    const issuedAtUnixMs = Date.now();
    const secretKey = getSecretKey();
    const token = sign({
        ...challengeToken,
        intent: undefined,
        challenge: undefined,
        accessTokenId: undefined,
        refreshTokenId: undefined,
        iat: issuedAtUnixMs,
        tokenType,
        ...extraClaims
    }, secretKey);
    return token;
};
export const issueSessionTokens = async (tokenPayload) => {
    const accessTokenId = crypto.randomUUID();
    const refreshTokenId = crypto.randomUUID();
    await storeAccessToken(tokenPayload.identity, tokenPayload.sessionId, accessTokenId);
    await storeRefreshToken(tokenPayload.identity, tokenPayload.sessionId, refreshTokenId);
    return {
        accessToken: generateAuthToken(tokenPayload, "accessToken", { accessTokenId }),
        refreshToken: generateAuthToken(tokenPayload, "refreshToken", { refreshTokenId })
    };
};
//# sourceMappingURL=auth.service.js.map