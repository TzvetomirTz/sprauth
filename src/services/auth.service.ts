import { generateSafeRandomString, getSecretKey, sign } from './sec.service.js';

export const generateChallenge = async (identity: string) => {
    const issuedAtUnixMs = Date.now();
    const challengeString = generateSafeRandomString();
    const secretKey = getSecretKey();

    const challenge = sign({
        iat: issuedAtUnixMs,
        identity,
        challenge: challengeString
    }, secretKey);

    return challenge;
}
