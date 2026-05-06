import { sign, verify } from './jwt.service.js'
import { randomBytes } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

// Setup
const envSecretKey = process.env.SPRAUTH_MLDSA_PRIVATE_KEY;

if (!envSecretKey) {
  throw new Error("Please set SPRAUTH_MLDSA_PRIVATE_KEY env var");
}

const secretKey = new Uint8Array(Buffer.from(envSecretKey, 'base64'));
const publicKey = ml_dsa65.getPublicKey(secretKey);

export const getPublicKeyBase64 = () => {
    return Buffer.from(publicKey).toString('base64');
}

export const generateAuthChallenge = async (identity: string) => {
    const issuedAtUnixMs = Date.now();
    const challengeString = generateSafeRandomString();

    const challenge = sign({
        iat: issuedAtUnixMs,
        identity,
        challenge: challengeString
    }, secretKey);

    return challenge;
}

const generateSafeRandomString = (byteLength: number = 32): string => {
  const buffer: Buffer = randomBytes(byteLength);
  return buffer.toString('base64url'); 
}
