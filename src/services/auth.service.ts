import { generateSafeRandomString, getSecretKey, sign } from './sec.service.js';

// One would think that ": string[]" ensures the parameter is a string array but guess what... It can contain anything </3
export const generateChallengeToken = async (identity: string, intent: string, claims: string[]) => {
    const issuedAtUnixMs = Date.now();
    const challengeString = generateSafeRandomString();
    const secretKey = getSecretKey();

    const challenge = sign({
        iat: issuedAtUnixMs,
        identity,
        intent,
        claims,
        challenge: challengeString
    }, secretKey);

    return challenge;
}
