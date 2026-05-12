import { describe, it, expect, beforeAll } from 'vitest';
import { sign, verify, derivePQCAddress } from './jwt.service';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

describe('jwt.service', () => {
  let publicKey: Uint8Array;
  let secretKey: Uint8Array;

  beforeAll(() => {
    const keys = ml_dsa65.keygen();
    publicKey = keys.publicKey;
    secretKey = keys.secretKey;
  });

  describe('sign and verify', () => {
    it('should sign a payload and verify it correctly', async () => {
      const payload = { identity: 'alice', challenge: '12345' };
      
      const token = await sign(payload, secretKey);
      expect(token).toBeDefined();
      expect(token.split('.')).toHaveLength(3);

      const decoded = verify(token, publicKey);
      expect(decoded).toEqual(payload);
    });

    it('should throw an error if the token format is invalid', () => {
      const invalidToken = 'header.payload';
      expect(() => verify(invalidToken, publicKey)).toThrow('Invalid JWT format');
    });

    it('should throw an error if the signature is tampered with', async () => {
      const payload = { identity: 'alice' };
      const token = await sign(payload, secretKey);

      const parts = token.split('.');
      parts[2] = parts[2].substring(0, parts[2].length - 5) + 'xxxxx';
      const tamperedToken = parts.join('.');

      expect(() => verify(tamperedToken, publicKey)).toThrow('Signature verification failed');
    });

    it('should throw an error if the payload is tampered with', async () => {
      const payload = { identity: 'alice' };
      const token = await sign(payload, secretKey);

      const parts = token.split('.');
      const tamperedPayload = Buffer.from(JSON.stringify({ identity: 'attacker' })).toString('base64url');
      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      expect(() => verify(tamperedToken, publicKey)).toThrow('Signature verification failed');
    });
  });

  describe('derivePQCAddress', () => {
    it('should derive a valid pqc1 address from a 1952-byte public key', () => {
      const address = derivePQCAddress(publicKey);
      
      expect(address).toMatch(/^pqc1[a-f0-9]{40}$/);
      expect(publicKey.length).toBe(1952);
    });

    it('should throw if the public key length is incorrect', () => {
      const invalidKey = new Uint8Array(32); // Too short
      expect(() => derivePQCAddress(invalidKey)).toThrow(/Invalid ML-DSA-65 public key length/);
    });
  });
});