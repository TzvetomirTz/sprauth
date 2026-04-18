import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

export const derivePublicKey = () => {
  const envSecretKey = process.env.SPRAUTH_MLDSA_PRIVATE_KEY || "";  
  const derivedPublicKey = ml_dsa65.getPublicKey(new Uint8Array(Buffer.from(envSecretKey, 'base64')));
  
	const pubKeyBase64 = Buffer.from(derivedPublicKey).toString('base64');

  console.log(`MLDSA_PUBLIC_KEY: ${pubKeyBase64}`);
};

derivePublicKey();
