import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';

export const generateMLDSAKeys = () => {
  const { secretKey, publicKey } = ml_dsa65.keygen();

  const secKeyBase64 = Buffer.from(secretKey).toString('base64');
  const pubKeyBase64 = Buffer.from(publicKey).toString('base64');

  const hash = createHash('sha256').update(publicKey).digest();
  const address = `0p${hash.subarray(-20).toString('hex')}`;

  console.log(`MLDSA_PRIVATE_KEY="${secKeyBase64}"`);
  console.log(`MLDSA_PUBLIC_KEY="${pubKeyBase64}"`);
  console.log(`MLDSA_ADDRESS="${address}"`);
};

generateMLDSAKeys();
