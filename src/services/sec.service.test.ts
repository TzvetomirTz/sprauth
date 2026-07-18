import { describe, it, expect, vi } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import * as secService from './sec.service.js';

vi.mock('./redis.service.js', () => ({
  consumeChallenge: vi.fn().mockResolvedValue(undefined),
}));

describe('Security Service (sec.service.ts)', () => {
  describe('Initialization & Key Management', () => {
    it('should export the public key as a base64 string', () => {
      const pubKeyBase64 = secService.getPublicKeyBase64();
      expect(typeof pubKeyBase64).toBe('string');
      expect(pubKeyBase64.length).toBeGreaterThan(0);
    });

    it('should return the server secret key as a Uint8Array', () => {
      const secretKey = secService.getSecretKey();
      expect(secretKey).toBeInstanceOf(Uint8Array);

      expect(secretKey.length).toBe(4032);
    });
  });

  describe('generateSafeRandomString', () => {
    it('should generate a string of expected byte length', () => {
      const randomStr = secService.generateSafeRandomString(32);
      expect(typeof randomStr).toBe('string');

      expect(randomStr.length).toBeGreaterThanOrEqual(42);
    });

    it('should generate unique strings', () => {
      const str1 = secService.generateSafeRandomString();
      const str2 = secService.generateSafeRandomString();
      expect(str1).not.toBe(str2);
    });
  });

  describe('JWT-style Signing and Verification', () => {
    it('should sign a payload and verify it successfully', async () => {
      const payload = { userId: 123, role: 'admin' };
      const secretKey = secService.getSecretKey();

      const token = await secService.sign(payload, secretKey);

      const parts = token.split('.');
      expect(parts.length).toBe(3);

      const decoded = await secService.verifySprauthSigned(token);
      expect(decoded).toEqual(payload);
    });

    it('should throw an error on invalid JWT format', async () => {
      await expect(secService.verifySprauthSigned('invalid.token'))
        .rejects.toThrow('Invalid JWT format');
    });

    it('should throw an error if the signature is tampered with', async () => {
      const payload = { test: true };
      const secretKey = secService.getSecretKey();

      const token = await secService.sign(payload, secretKey);
      const tamperedToken = token.slice(0, -5) + 'xxxxx';

      await expect(secService.verifySprauthSigned(tamperedToken))
        .rejects.toThrow('Signature verification failed');
    });
  });

  describe('PQC Address Derivation', () => {
    it('should derive a valid pqc1 address from a public key', () => {
      const clientKeys = ml_dsa65.keygen();
      const address = secService.derivePQCAddress(clientKeys.publicKey);
      
      expect(address.startsWith('pqc1')).toBe(true);
      expect(address.length).toBe(44);
    });

    it('should throw an error if the public key length is invalid', () => {
      const invalidPubKey = new Uint8Array(100);
      expect(() => secService.derivePQCAddress(invalidPubKey))
        .toThrow('Invalid ML-DSA-65 public key length. Expected 1952 bytes.');
    });
  });

  describe('Challenge Verification', () => {
    it('should verify a correctly signed client challenge', async () => {
      const clientKeys = ml_dsa65.keygen();
      const claimedAddress = secService.derivePQCAddress(clientKeys.publicKey);
      const challenge = "Login-Request-123456789";
      const messageBytes = new TextEncoder().encode(challenge);
      const signatureBytes = ml_dsa65.sign(messageBytes, clientKeys.secretKey);
      const signatureBase64 = Buffer.from(signatureBytes).toString('base64');
      const publicKeyBase64 = Buffer.from(clientKeys.publicKey).toString('base64');

      const result = await secService.verifyChallengeSignature(
        challenge,
        signatureBase64,
        publicKeyBase64,
        claimedAddress
      );

      expect(result.success).toBe(true);
      expect(result.address).toBe(claimedAddress);
    });

    it('should fail if the claimed address does not match the public key', async () => {
      const clientKeys = ml_dsa65.keygen();
      const wrongAddress = "pqc10000000000000000000000000000000000000000";
      const challenge = "Login-Request-123456789";
      const messageBytes = new TextEncoder().encode(challenge);
      const signatureBytes = ml_dsa65.sign(messageBytes, clientKeys.secretKey);
      const signatureBase64 = Buffer.from(signatureBytes).toString('base64');
      const publicKeyBase64 = Buffer.from(clientKeys.publicKey).toString('base64');
      const result = await secService.verifyChallengeSignature(
        challenge,
        signatureBase64,
        publicKeyBase64,
        wrongAddress
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Address mismatch');
    });

    it('should fail if the signature is invalid for the challenge', async () => {
      const clientKeys = ml_dsa65.keygen();
      const claimedAddress = secService.derivePQCAddress(clientKeys.publicKey);
      const challenge = "Login-Request-123456789";
      const wrongMessageBytes = new TextEncoder().encode("Different-Challenge");
      const signatureBytes = ml_dsa65.sign(wrongMessageBytes, clientKeys.secretKey);
      const signatureBase64 = Buffer.from(signatureBytes).toString('base64');
      const publicKeyBase64 = Buffer.from(clientKeys.publicKey).toString('base64');
      const result = await secService.verifyChallengeSignature(
        challenge,
        signatureBase64,
        publicKeyBase64,
        claimedAddress
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Signature verification failed');
    });
  });
});
