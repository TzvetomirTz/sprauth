import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';

const baseUrl = process.env.SPRAUTH_BASE_URL || 'http://localhost:3000';
const intent = process.argv[2] || 'login';

const decodeJwtPayload = (jwt: string) => {
  const payloadB64Url = jwt.split('.')[1]!;
  return JSON.parse(Buffer.from(payloadB64Url, 'base64url').toString('utf8'));
};

const main = async () => {
  const { secretKey, publicKey } = ml_dsa65.keygen();
  const publicKeyBase64 = Buffer.from(publicKey).toString('base64');

  const hash = createHash('sha256').update(publicKey).digest();
  const identity = `pqc1${hash.subarray(-20).toString('hex')}`;

  console.log(`Client identity:   ${identity}`);
  console.log(`Client public key: ${publicKeyBase64}\n`);

  console.log(`POST ${baseUrl}/challenge/init`);
  const initRes = await fetch(`${baseUrl}/challenge/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identity, intent, customClaims: {} })
  });

  if (!initRes.ok) {
    throw new Error(`challenge/init failed: ${initRes.status} ${await initRes.text()}`);
  }

  const { challengeToken } = await initRes.json();
  const challengePayload = decodeJwtPayload(challengeToken);
  console.log(`Challenge string:  ${challengePayload.challenge}\n`);

  const messageBytes = new TextEncoder().encode(challengePayload.challenge);
  const signatureBytes = ml_dsa65.sign(messageBytes, secretKey);
  const signatureBase64 = Buffer.from(signatureBytes).toString('base64');

  console.log(`POST ${baseUrl}/session/auth`);
  const authRes = await fetch(`${baseUrl}/session/auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challengeJwt: challengeToken,
      signature: signatureBase64,
      publicKey: publicKeyBase64
    })
  });

  const authBody = await authRes.json();
  console.log(`Response (${authRes.status}):`, authBody);

  if (authBody.accessToken) {
    console.log('\nDecoded accessToken payload:', decodeJwtPayload(authBody.accessToken));
    console.log(`Session ID:`, authBody.sessionId);
  }

  console.log('\n--- Paste into Postman collection variables to replay Verify/Authenticate manually ---');
  console.log(`identity         = ${identity}`);
  console.log(`clientPublicKey  = ${publicKeyBase64}`);
  console.log(`signature        = ${signatureBase64}`);
  console.log(`challengeJwt     = ${challengeToken}`);
  console.log('(Note: this signature is only valid for the challengeJwt above — don\'t run "Init Challenge" again before using it, that would issue a new challenge.)');
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
