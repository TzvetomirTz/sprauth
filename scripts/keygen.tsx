import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import fs from 'node:fs';

export const generateMLDSAKeys = () => {
  const { secretKey, publicKey } = ml_dsa65.keygen();

  fs.writeFileSync('publicKey.bin', publicKey);
  fs.writeFileSync('secretKey.bin', secretKey);

  console.log('Keys successfully saved to publicKey.bin and secretKey.bin');
};

generateMLDSAKeys();
