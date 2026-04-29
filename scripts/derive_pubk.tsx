import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';

export const derivePublicKey = () => {
  const envSecretKey = process.env.SPRAUTH_MLDSA_PRIVATE_KEY || "";  
  const derivedPublicKey = ml_dsa65.getPublicKey(new Uint8Array(Buffer.from(envSecretKey, 'base64')));
  
	const pubKeyBase64 = Buffer.from(derivedPublicKey).toString('base64');

  const hash = createHash('sha256').update(derivedPublicKey).digest();
  const address = `0p${hash.subarray(-20).toString('hex')}`;

  console.log(`MLDSA_PUBLIC_KEY: ${pubKeyBase64}`);
  console.log(`MLDSA_ADDRESS="${address}"`);
};

derivePublicKey();
