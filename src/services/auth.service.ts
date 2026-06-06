import { generateSafeRandomString, getSecretKey, sign } from './sec.service.js';

export const generateChallengeToken = async (identity: string, intent: string, customClaims: object) => {
    const issuedAtUnixMs = Date.now();
    const challengeString = generateSafeRandomString();
    const secretKey = getSecretKey();

    const challenge = sign({
        ...customClaims,
        iat: issuedAtUnixMs,
        identity,
        intent,
        challenge: challengeString
    }, secretKey);

    return challenge;
}
