import { sign, verify } from './jwt.service.js'
import { createHash, randomBytes } from 'node:crypto';
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

export const verifySprauthSigned = (token: string) => {
    return verify(token, publicKey);
}

export const verifyChallengeSignature = async (
    challenge: string,
    signatureBase64: string,
    publicKeyBase64: string,
    claimedAddress: string
) => {
    try {
        const pubKeyBytes = new Uint8Array(Buffer.from(publicKeyBase64, 'base64'));
        const hash = createHash('sha256').update(pubKeyBytes).digest();
        const last20Bytes = hash.subarray(-20);
        const derivedAddress = `0p${last20Bytes.toString('hex')}`;

        if (derivedAddress !== claimedAddress) {
            throw new Error("Address mismatch: The provided Public Key does not match the identity.");
        }

        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(challenge);
        const signatureBytes = new Uint8Array(Buffer.from(signatureBase64, 'base64'));

        const isValid = ml_dsa65.verify(signatureBytes, messageBytes, pubKeyBytes);

        if (!isValid) {
            throw new Error("Signature verification failed.");
        }

        return { success: true, address: derivedAddress };
    } catch (error: any) {
        console.error("Verification error:", error.message);
        return { success: false, error: error.message };
    }
}
