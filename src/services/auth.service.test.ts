import { describe, it, expect, vi, beforeAll } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const mockSecret = Buffer.from(ml_dsa65.keygen().secretKey).toString('base64');
vi.stubEnv('SPRAUTH_MLDSA_PRIVATE_KEY', mockSecret);

import * as authService from './auth.service';

describe('auth.service', () => {
  const testIdentity = 'user_123';

  describe('getPublicKeyBase64', () => {
    it('should return a base64 encoded string of the public key', () => {
      const pubKey = authService.getPublicKeyBase64();
      expect(typeof pubKey).toBe('string');
      expect(pubKey.length).toBeGreaterThan(2000); 
    });
  });

  describe('generateAuthChallenge', () => {
    it('should generate a challenge token containing the identity', async () => {
      const token = await authService.generateAuthChallenge(testIdentity);

      const decoded = authService.verifySprauthSigned(token);
      
      expect(decoded.identity).toBe(testIdentity);
      expect(decoded.challenge).toBeDefined();
      expect(decoded.iat).toBeLessThanOrEqual(Date.now());
    });
  });

  describe('verifyChallengeSignature', () => {
    it('should verify a valid signature and return the correct address', async () => {
      const userKeys = ml_dsa65.keygen();
      const userPubKeyBase64 = Buffer.from(userKeys.publicKey).toString('base64');

      const { createHash } = await import('node:crypto');
      const hash = createHash('sha256').update(userKeys.publicKey).digest();
      const expectedAddress = `pqc1${hash.subarray(-20).toString('hex')}`;

      const challenge = "test-challenge-string";
      const signature = ml_dsa65.sign(new TextEncoder().encode(challenge), userKeys.secretKey);
      const signatureBase64 = Buffer.from(signature).toString('base64');

      const result = await authService.verifyChallengeSignature(
        challenge,
        signatureBase64,
        userPubKeyBase64,
        expectedAddress
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.address).toBe(expectedAddress);
      }
    });

    it('should fail if the address does not match the public key', async () => {
      const userKeys = ml_dsa65.keygen();
      const userPubKeyBase64 = Buffer.from(userKeys.publicKey).toString('base64');
      
      const result = await authService.verifyChallengeSignature(
        "challenge",
        "sig",
        userPubKeyBase64,
        "pqc1-wrong-address"
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("Address mismatch");
    });

    it('should fail if the signature is invalid', async () => {
      const userKeys = ml_dsa65.keygen();
      const userPubKeyBase64 = Buffer.from(userKeys.publicKey).toString('base64');

      const { createHash } = await import('node:crypto');
      const hash = createHash('sha256').update(userKeys.publicKey).digest();
      const address = `pqc1${hash.subarray(-20).toString('hex')}`;

      const result = await authService.verifyChallengeSignature(
        "challenge",
        Buffer.from(new Uint8Array(2420)).toString('base64'),
        userPubKeyBase64,
        address
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe("Signature verification failed.");
    });
  });
});