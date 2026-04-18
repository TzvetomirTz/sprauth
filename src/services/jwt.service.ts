import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';

// Setup
const envSecretKey = process.env.SPRAUTH_MLDSA_PRIVATE_KEY;

if (!envSecretKey) {
  throw new Error("Please set SPRAUTH_MLDSA_PRIVATE_KEY env var");
}

const secretKey = new Uint8Array(Buffer.from(envSecretKey, 'base64'));
const publicKey = ml_dsa65.getPublicKey(secretKey);

const HEADER = {
  alg: 'ML-DSA-65',
  typ: 'JWT'
};

// End of setup

export const sign = async (payload: object) => {
  const encodedHeader = Buffer.from(JSON.stringify(HEADER)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const messageBytes = new TextEncoder().encode(signingInput);
  const signatureBytes = ml_dsa65.sign(messageBytes, secretKey);
  const encodedSignature = Buffer.from(signatureBytes).toString('base64url');

  return `${signingInput}.${encodedSignature}`;
}

export const verify = (token: string) => {
  const parts = token.split('.');
  
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const encodedHeader = parts[0]!; 
  const encodedPayload = parts[1]!;
  const encodedSignature = parts[2]!;

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const messageBytes = new TextEncoder().encode(signingInput);

  const signatureBytes = new Uint8Array(Buffer.from(encodedSignature, 'base64url'));

  const isValid = ml_dsa65.verify(signatureBytes, messageBytes, publicKey);

  if (!isValid) {
    throw new Error('Signature verification failed');
  }

  const decodedPayload = Buffer.from(encodedPayload, 'base64url').toString('utf8');
  return JSON.parse(decodedPayload);
}

export const derivePQCAddress = (publicKey: Uint8Array): string => {
    if (publicKey.length !== 1952) {
        throw new Error("Invalid ML-DSA-65 public key length. Expected 1952 bytes.");
    }

    const hash = createHash('sha256').update(publicKey).digest();
    const addressBytes = hash.subarray(-20);
    const hexAddress = Buffer.from(addressBytes).toString('hex');
    
    return `pqc1${hexAddress}`;
}
