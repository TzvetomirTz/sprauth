import { createHash } from 'node:crypto';

export const derivePQCAddress = (publicKey: Uint8Array): string => {
    if (publicKey.length !== 1952) {
        throw new Error("Invalid ML-DSA-65 public key length. Expected 1952 bytes.");
    }

    const hash = createHash('sha256').update(publicKey).digest();
    const addressBytes = hash.subarray(-20);
    const hexAddress = Buffer.from(addressBytes).toString('hex');

    return `pqc1${hexAddress}`;
}
