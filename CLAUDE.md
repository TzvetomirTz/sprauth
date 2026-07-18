# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Sprauth is a passwordless authentication API built around post-quantum signatures (ML-DSA-65 / Dilithium via `@noble/post-quantum`) instead of passwords or classical crypto. Clients hold an ML-DSA keypair; their "identity" is a `pqc1<hex>`-prefixed address derived from `sha256(publicKey)`. Auth is a challenge-response flow: the server issues a signed challenge, the client signs it with their private key, and the server verifies the signature and address before minting session tokens.

## Commands

- `npm run dev` — run the API with `nodemon` + `tsx` against `src/app.ts` (auto-reload).
- `npm run build` — type-check and compile `src/` to `dist/` via `tsc` (see `tsconfig.json`).
- `npm start` — run the compiled `dist/app.js`.
- `npm test` — run the Vitest suite (config at repo-root `vitest.config.ts`, `setupFiles` points at `src/tests/setup.ts`).
- `npm run test:coverage` — run tests with coverage.
- Run a single test file: `npx vitest run src/services/sec.service.test.ts`.
- `npx tsx scripts/keygen.tsx` — generate a new ML-DSA-65 keypair and print `MLDSA_PRIVATE_KEY` / `MLDSA_PUBLIC_KEY` / `MLDSA_ADDRESS` (base64/hex) to stdout.
- `npx tsx scripts/derive_pubk.tsx` — derive and print the public key + address from `SPRAUTH_MLDSA_PRIVATE_KEY` in the environment.
- `docker build -t sprauth-api .` / `docker run -p 3000:3000 sprauth-api` — build/run the multi-stage Docker image (builder compiles TS, runner ships only `dist/` + prod deps).

Node 20+ required. This is an ESM package (`"type": "module"`) with `NodeNext` module resolution — relative imports must use `.js` extensions even in `.ts` source files (e.g. `import { x } from './sec.service.js'`).

## Required environment variables

- `SPRAUTH_MLDSA_PRIVATE_KEY` — base64-encoded ML-DSA-65 secret key for the server. **Required**; the process throws on startup (`src/services/sec.service.ts`) if unset. Generate one with `scripts/keygen.tsx`.
- `SPRAUTH_REDIS_URL` — Redis connection string (default `redis://localhost:6379`).
- `SPRAUTH_CHALLENGE_TTL` — challenge expiry in seconds (default `600`).
- `SPRAUTH_SESSION_TTL` — session expiry in seconds (default `2592000`, 30 days).
- `PORT` — HTTP port (default `3000`).

In tests, `src/tests/setup.ts` auto-generates a fresh keypair and sets `SPRAUTH_MLDSA_PRIVATE_KEY` before the suite runs, so no real key is needed locally for `npm test`.

## Architecture

Layered Express app: `routes/` (wire HTTP verbs/paths, attach `express.json()`) → `controllers/` (parse/validate request, call services, shape response, `next(error)` on failure) → `services/` (crypto, business logic, Redis). There is currently no centralized error-handling middleware in `src/app.ts`, so unhandled errors passed to `next()` fall through to Express's default handler.

Four route groups mounted in `src/app.ts`:
- `GET /sec/key/public` — returns the server's ML-DSA public key (base64).
- `POST /challenge/init` — client submits `{ identity, intent, customClaims }`; server generates a signed challenge JWT-like token and stores its `tokenId` in Redis (`challenge:<tokenId>`, TTL-bound). `customClaims` is spread *before* the reserved fields (`iat`, `identity`, `intent`, `challenge`, `tokenId`) so it cannot override them.
- `POST /challenge/verify` — client returns `{ challengeJwt, signature, publicKey }`; server verifies the challenge's own signature (`verifySprauthSigned`, which also consumes/deletes the Redis challenge entry — single use) and then verifies the client's signature over the challenge string against the claimed identity (`verifyChallengeSignature`, which re-derives the `pqc1...` address from the supplied public key and compares).
- `GET /challenge/valid` (query `tokenId`) — checks whether a challenge is still pending/unconsumed in Redis (`checkIsChallengeValid`).
- `POST /auth/` — same verification as `/challenge/verify`, but on success mints `accessToken` and `refreshToken` (also ML-DSA-signed tokens, via `generateAuthToken`) instead of a boolean.
- `POST /session/start`, `GET /session/` (query `identity`), `GET /session/valid` (query `identity`, `sessionId`, `renewTtl`), `POST /session/end`, `POST /session/revoke` — thin wrappers over the Redis session functions (`src/controllers/session.controller.ts`). **These do not verify caller identity** — `identity` is taken as-is from the request, not derived from a verified token. Since `pqc1...` addresses aren't secret, anyone who knows/guesses an address can currently list/end/revoke that identity's sessions. Fine for now since nothing else creates real sessions yet (see below), but gate this behind access-token verification before relying on it.

### Token format

Tokens are a custom JWT-like structure, **not** standard JWT (different alg space): `base64url(header).base64url(payload).base64url(signature)`, signed with ML-DSA-65 (`sign()` / `verifySprauthSigned()` in `src/services/sec.service.ts`). Header is fixed `{ alg: 'ML-DSA-65', typ: 'JWT' }`. Signature verification uses the server's own public key — these tokens are self-issued by the server (challenge tokens, access tokens, refresh tokens), distinct from the client-side signatures over the challenge string (which use the *client's* keypair and are checked in `verifyChallengeSignature`).

`verifySprauthSigned()` always calls `consumeChallenge()` as part of verification — it's built for one-time challenge tokens, not for repeatedly verifying access/refresh tokens. Don't reuse it as-is to authenticate incoming access tokens on other routes; it'll throw "not found or already consumed" the second time. If/when access-token auth is added (e.g. to gate `/session/*` by caller identity), split signature verification from challenge consumption first.

### Identity / address derivation

A client's address is `pqc1` + hex(sha256(publicKey))[-20:]. Computed in two places that must stay in sync: `derivePQCAddress()` and inline in `verifyChallengeSignature()` in `src/services/sec.service.ts`. ML-DSA-65 public keys are expected to be exactly 1952 bytes.

### Redis layer (`src/services/redis.service.ts`)

Single shared client connected at module load. Two key namespaces:
- `challenge:<tokenId>` — one-time challenge tokens, deleted on consumption via `getDel` (`consumeChallenge` throws if already consumed/missing — enforces single use).
- `session:<identity>:<sessionId>` — per-identity sessions; supports listing all sessions for an identity (`getAllUserSessions`, via `scanIterator`), validating with optional TTL renewal (`checkIsSessionValid`), and bulk revocation except a keep-list (`endUserSessions`, uses `unlink`).

Session management (`startSession`, `endSession`, `endUserSessions`, `getAllUserSessions`) is exposed via the `/session` routes above, but nothing calls `startSession` as part of `/auth` — issuing an access/refresh token does not currently create a corresponding Redis session entry, so the session store and the token-issuing flow are still disconnected in practice.

## Testing conventions

Vitest with `environment: 'node'`. `src/services/sec.service.test.ts` exercises real ML-DSA crypto (keygen, sign, verify, address derivation) without mocking. `src/services/auth.service.test.ts` mocks `./sec.service.js` entirely (`vi.mock`) and uses fake timers to assert on the exact payload shape passed to `sign()`, including that `customClaims` cannot clobber reserved claims.

SECURITY RULES: Never run env, printenv, or any command that dumps environment variables. Do not read or output the contents of .env files.