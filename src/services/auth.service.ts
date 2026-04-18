import { sign, verify } from './jwt.service.js'
import { randomBytes } from 'node:crypto';

export const generateAuthChallenge = async () => {
    const issuedAtUnixMs = Date.now();
    const challengeString = generateSafeRandomString();

    const challenge = sign({
        iat: issuedAtUnixMs,
        challenge: challengeString
    });

    return challenge;
}

const generateSafeRandomString = (byteLength: number = 32): string => {
  const buffer: Buffer = randomBytes(byteLength);
  return buffer.toString('base64url'); 
}