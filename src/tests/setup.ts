import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const keys = ml_dsa65.keygen();

process.env.SPRAUTH_MLDSA_PRIVATE_KEY = Buffer.from(keys.secretKey).toString('base64');
