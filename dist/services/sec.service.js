import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash, randomBytes } from 'node:crypto';
import { consumeChallenge } from './redis.service.js';
// Setup Start
const envSecretKey = process.env.SPRAUTH_MLDSA_PRIVATE_KEY;
if (!envSecretKey) {
    throw new Error("Please set SPRAUTH_MLDSA_PRIVATE_KEY env var");
}
const secretKey = new Uint8Array(Buffer.from(envSecretKey, 'base64'));
const publicKey = ml_dsa65.getPublicKey(secretKey);
export const getPublicKeyBase64 = () => {
    return Buffer.from(publicKey).toString('base64');
};
const HEADER = {
    alg: 'ML-DSA-65',
    typ: 'JWT'
};
// Setup End
export const getSecretKey = () => {
    return secretKey;
};
export const generateSafeRandomString = (byteLength = 32) => {
    const buffer = randomBytes(byteLength);
    return buffer.toString('base64url');
};
export const sign = (payload, secretKey) => {
    const encodedHeader = Buffer.from(JSON.stringify(HEADER)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const messageBytes = new TextEncoder().encode(signingInput);
    const signatureBytes = ml_dsa65.sign(messageBytes, secretKey);
    const encodedSignature = Buffer.from(signatureBytes).toString('base64url');
    return `${signingInput}.${encodedSignature}`;
};
export const verifySelfSigned = (token) => {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }
    const encodedHeader = parts[0];
    const encodedPayload = parts[1];
    const encodedSignature = parts[2];
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const messageBytes = new TextEncoder().encode(signingInput);
    const signatureBytes = new Uint8Array(Buffer.from(encodedSignature, 'base64url'));
    const isValid = ml_dsa65.verify(signatureBytes, messageBytes, publicKey);
    if (!isValid) {
        throw new Error('Signature verification failed');
    }
    const decodedPayload = Buffer.from(encodedPayload, 'base64url').toString('utf8');
    return JSON.parse(decodedPayload);
};
export const verifySprauthSigned = async (token) => {
    const payload = verifySelfSigned(token);
    await consumeChallenge(payload.identity, payload.tokenId);
    return payload;
};
export const verifyChallengeSignature = async (challenge, signatureBase64, publicKeyBase64, claimedAddress) => {
    try {
        const pubKeyBytes = new Uint8Array(Buffer.from(publicKeyBase64, 'base64'));
        // Single source of truth for address derivation — also enforces the 1952-byte
        // ML-DSA-65 key length (throws, caught below as a verification failure).
        const derivedAddress = derivePQCAddress(pubKeyBytes);
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
    }
    catch (error) {
        console.error("Verification error:", error.message);
        return { success: false, error: error.message };
    }
};
export const derivePQCAddress = (publicKey) => {
    if (publicKey.length !== 1952) {
        throw new Error("Invalid ML-DSA-65 public key length. Expected 1952 bytes.");
    }
    const hash = createHash('sha256').update(publicKey).digest();
    const addressBytes = hash.subarray(-20);
    const hexAddress = Buffer.from(addressBytes).toString('hex');
    return `pqc1${hexAddress}`;
};
//# sourceMappingURL=sec.service.js.map