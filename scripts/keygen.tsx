import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

export const generateMLDSAKeys = () => {
  const { secretKey, publicKey } = ml_dsa65.keygen();

  const secKeyBase64 = Buffer.from(secretKey).toString('base64');
  const pubKeyBase64 = Buffer.from(publicKey).toString('base64');

  console.log(`MLDSA_PRIVATE_KEY="${secKeyBase64}"`);
  console.log(`MLDSA_PUBLIC_KEY="${pubKeyBase64}"`);
};

generateMLDSAKeys();
