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
- `SPRAUTH_BASE_URL=http://localhost:3000 npx tsx scripts/demo_login.tsx` — generates a fresh client keypair, runs the full `/challenge/init` → sign → `/session/auth` flow against a running server, and prints the resulting tokens plus values you can paste into Postman to replay `Authenticate` manually.
- `docker build -t sprauth-api .` / `docker run -p 3000:3000 sprauth-api` — build/run the multi-stage Docker image (builder compiles TS, runner ships only `dist/` + prod deps).

`postman/sprauth.postman_collection.json` (+ `postman/sprauth.local.postman_environment.json`) covers every route. Postman can't do ML-DSA-65 signing itself, so `Authenticate` needs `clientPublicKey`/`signature` supplied externally — `scripts/demo_login.tsx` produces those.

Node 20+ required. This is an ESM package (`"type": "module"`) with `NodeNext` module resolution — relative imports must use `.js` extensions even in `.ts` source files (e.g. `import { x } from './sec.service.js'`).

## Required environment variables

- `SPRAUTH_MLDSA_PRIVATE_KEY` — base64-encoded ML-DSA-65 secret key for the server. **Required**; the process throws on startup (`src/services/sec.service.ts`) if unset. Generate one with `scripts/keygen.tsx`.
- `SPRAUTH_REDIS_URL` — Redis connection string (default `redis://localhost:6379`).
- `SPRAUTH_CHALLENGE_TTL` — challenge expiry in seconds (default `600`).
- `SPRAUTH_SESSION_TTL` — session expiry in seconds (default `2592000`, 30 days).
- `SPRAUTH_ACCESS_TOKEN_TTL` — access-token lifetime in seconds (default `3600`, 1 hour). Backed by a Redis entry (`access:<identity>:<sessionId>:<accessTokenId>`, `EX` = this TTL, created in `redis.service.ts`); the token is alive only while that entry exists, so it expires with the TTL *and* is revoked when its session ends.
- `SPRAUTH_REFRESH_TOKEN_TTL` — refresh-token lifetime in seconds (default `604800`, 1 week). Backed by a Redis entry (`refresh:<identity>:<sessionId>:<refreshTokenId>`, `EX` = this TTL, created in `redis.service.ts`), independently of the 30-day session TTL; the token expires with the TTL, is single-use, and is revoked when its session ends.
- `PORT` — HTTP port (default `3000`).

In tests, `src/tests/setup.ts` auto-generates a fresh keypair and sets `SPRAUTH_MLDSA_PRIVATE_KEY` before the suite runs, so no real key is needed locally for `npm test`.

## Architecture

Layered Express app: `routes/` (wire HTTP verbs/paths, attach `express.json()`) → `controllers/` (parse/validate request, call services, shape response, `next(error)` on failure) → `services/` (crypto, business logic, Redis). There is currently no centralized error-handling middleware in `src/app.ts`, so unhandled errors passed to `next()` fall through to Express's default handler.

Four route groups mounted in `src/app.ts`:
- `GET /sec/key/public` — returns the server's ML-DSA public key (base64).
- `POST /challenge/init` — client submits `{ identity, intent, customClaims }`; server generates a signed challenge JWT-like token and stores its `tokenId` in Redis (`challenge:<identity>:<tokenId>`, TTL-bound). `customClaims` is spread *before* the reserved fields (`iat`, `identity`, `intent`, `challenge`, `tokenId`) so it cannot override them.
- `POST /challenge/valid` — client submits `{ identity, tokenId, consume }`; checks whether a challenge is still pending/unconsumed in Redis (`checkIsChallengeValid`). `consume` (optional, default `false`) determines whether the check also atomically removes the entry (`getDel`) as part of the same call, vs. a non-destructive status poll (`get`).
- `POST /session/auth` — client submits `{ challengeJwt, signature, publicKey }`; server verifies the challenge's own signature (`verifySprauthSigned`, which also consumes/deletes the Redis challenge entry — single use) and then verifies the client's signature over the challenge string against the claimed identity (`verifyChallengeSignature`, which re-derives the `pqc1...` address from the supplied public key and compares). On success it also mints `accessToken` and `refreshToken` (also ML-DSA-signed tokens, via `generateAuthToken`), starts a Redis session for the identity (`startSession`), records a Redis entry for each issued token (`issueSessionTokens` → `storeAccessToken`/`storeRefreshToken`), and returns the resulting `sessionId` alongside the tokens. The `sessionId` is baked into both issued tokens' payloads (not just the JSON response) so `/session/refresh` can trust it without a client-supplied parameter. Lives under `/session` (not `/auth`) because minting tokens and opening the session are one operation now — there's no standalone "start a session" call.
- `POST /session/refresh` — client submits `{ refreshToken }`; server verifies the token's own ML-DSA signature (`verifySelfSigned`, signature-only), rejects it unless its `tokenType` is `"refreshToken"`, then checks the `sessionId`/`identity` embedded in the token are still a valid session (`checkIsSessionValid`, **without** TTL renewal) and atomically consumes the token's `refresh:<identity>:<sessionId>:<refreshTokenId>` entry (`consumeRefreshToken`, a single-use `getDel` that also fails if the entry has expired past its `SPRAUTH_REFRESH_TOKEN_TTL` or was revoked). Only once both checks pass does it renew the session TTL (`renewSession`) — a doomed request (e.g. a replayed, already-consumed token) must not extend the session's life. On success mints and returns a fresh `accessToken`/`refreshToken` pair for the same session. Refresh tokens **are** single-use and rotated: each issued refresh token carries a unique `refreshTokenId`, and its Redis entry is consumed on use, so replaying the same refresh token fails. A refresh token thus dies when any of: its Redis entry TTLs out (1 week), its session ends/expires, or it's been used once — all Redis-backed, no `iat` check.
- `GET /session/` (query `identity`), `GET /session/valid` (query `identity`, `sessionId`, `renewTtl`) — thin read wrappers over the Redis session functions (`src/controllers/session.controller.ts`). **These do not verify caller identity** — `identity` is taken as-is from the query, not derived from a verified token. Since `pqc1...` addresses aren't secret, anyone who knows/guesses an address can currently list/poll that identity's sessions. Fine for now, but gate this behind access-token verification before relying on it.
- `POST /session/end` (body `sessionId`), `POST /session/revoke` (body `except`) — **require a valid access token** as `Authorization: Bearer <accessToken>`, enforced by `requireAccessToken` (`src/middleware/auth.middleware.ts`) before the controller runs. The middleware verifies the token's own ML-DSA signature via `verifySelfSigned`, checks `tokenType === 'accessToken'`, and checks its `access:<identity>:<sessionId>:<accessTokenId>` entry is still live in Redis (`checkIsAccessTokenValid` — a plain read, since access tokens are multi-use), then attaches the payload to `req.auth`; the controllers take `identity` from `req.auth`, **not** the request body — so a caller can only end/revoke their own sessions. A missing/malformed/expired/revoked/non-access token is `401`. Because the access entry is deleted by `endSession`/`endUserSessions` (alongside the session and refresh entries), ending or revoking a session **immediately** invalidates its access tokens — access-token liveness is Redis-backed, not `iat`-based.
- `GET /admin/challenges/count` (query `identity`), `GET /admin/challenges/count/all`, `GET /admin/sessions/count` (query `identity`), `GET /admin/sessions/count/all` — Redis key counts via `SCAN` (`src/controllers/admin.controller.ts`), for operational visibility into how many challenges/sessions are outstanding, per-identity or system-wide. Like the `/session/` list and `/session/valid` routes (but unlike `/session/end` and `/session/revoke`, which now require an access token), **these are unauthenticated** — no admin/caller-identity check exists yet.

### Token format

Tokens are a custom JWT-like structure, **not** standard JWT (different alg space): `base64url(header).base64url(payload).base64url(signature)`, signed with ML-DSA-65 (`sign()` / `verifySprauthSigned()` in `src/services/sec.service.ts`). Header is fixed `{ alg: 'ML-DSA-65', typ: 'JWT' }`. Signature verification uses the server's own public key — these tokens are self-issued by the server (challenge tokens, access tokens, refresh tokens), distinct from the client-side signatures over the challenge string (which use the *client's* keypair and are checked in `verifyChallengeSignature`).

Payloads carry an `iat` (ms since epoch) but **no `exp` claim**, and nothing ever checks the `iat` — liveness is entirely Redis-backed. Each token type has a Redis entry that must exist for the token to be accepted; the entry's `EX` TTL bounds the token's life and deleting it revokes the token:
- **Access tokens** — `access:<identity>:<sessionId>:<accessTokenId>` (`EX` = `SPRAUTH_ACCESS_TOKEN_TTL`). `requireAccessToken` requires the entry to exist (plain read — multi-use). Deleted on session end/revoke.
- **Refresh tokens** — `refresh:<identity>:<sessionId>:<refreshTokenId>` (`EX` = `SPRAUTH_REFRESH_TOKEN_TTL`). `/session/refresh` consumes the entry (`getDel` — single-use). Deleted on session end/revoke.
- **Challenge tokens** — `challenge:<identity>:<tokenId>` (`EX` = `SPRAUTH_CHALLENGE_TTL`). Consumed single-use by `verifySprauthSigned`.

`verifySprauthSigned()` always calls `consumeChallenge()` as part of verification — it's built for one-time challenge tokens, not for repeatedly verifying access/refresh tokens. `verifySelfSigned()` is the split-out signature-only half (no Redis interaction) — it's what `/session/refresh` uses to verify refresh tokens repeatedly, and it's what `requireAccessToken` (`src/middleware/auth.middleware.ts`) uses to gate `/session/end` and `/session/revoke` by caller identity. Reach for it again to extend that gating to the `/session/` list, `/session/valid`, or `/admin/*` routes.

### Identity / address derivation

A client's address is `pqc1` + hex(sha256(publicKey))[-20:]. Computed in two places that must stay in sync: `derivePQCAddress()` and inline in `verifyChallengeSignature()` in `src/services/sec.service.ts`. ML-DSA-65 public keys are expected to be exactly 1952 bytes.

### Redis layer (`src/services/redis.service.ts`)

Single shared client connected at module load. Four key namespaces:
- `challenge:<identity>:<tokenId>` — one-time challenge tokens. `checkIsChallengeValid(identity, tokenId, consume?)` backs `POST /challenge/valid` and does a plain `get` (or `getDel` when `consume` is true). `consumeChallenge(identity, tokenId)` is the strict counterpart used internally by `verifySprauthSigned` — it always deletes via `getDel` and throws if already consumed/missing, enforcing single use for the `/session/auth` flow.
- `session:<identity>:<sessionId>` — per-identity sessions; supports listing all sessions for an identity (`getAllUserSessions`, via `scanIterator`), validating with optional TTL renewal (`checkIsSessionValid`), and bulk revocation except a keep-list (`endUserSessions`, uses `unlink`).
- `refresh:<identity>:<sessionId>:<tokenId>` — per-refresh-token entries (`EX` = `refreshTokenTtl`, default 1wk). `storeRefreshToken` creates them; `consumeRefreshToken` is a single-use `getDel` (returns whether the entry existed). Deleted for a session by `endSession`/`endUserSessions`, enforcing single-use + revocation for refresh tokens.
- `access:<identity>:<sessionId>:<tokenId>` — per-access-token entries (`EX` = `accessTokenTtl`, default 1hr). `storeAccessToken` creates them; `checkIsAccessTokenValid` is a plain `get` (access tokens are multi-use, so it does **not** delete). Deleted for a session by `endSession`/`endUserSessions`, so ending/revoking a session immediately kills its access tokens.

Session management (`startSession`, `endSession`, `endUserSessions`, `getAllUserSessions`) is exposed via the `/session` routes above. `startSession` is called from `handleAuthReq` (`POST /session/auth`) on successful challenge verification; `issueSessionTokens` then writes the matching `access:` and `refresh:` entries, so issuing tokens creates a session entry plus one entry per issued token. `endSession`/`endUserSessions` delete all three namespaces (`session:`, `refresh:`, `access:`) for the affected session(s).

## Testing conventions

Vitest with `environment: 'node'`. `src/services/sec.service.test.ts` exercises real ML-DSA crypto (keygen, sign, verify, address derivation) without mocking. `src/services/auth.service.test.ts` mocks `./sec.service.js` entirely (`vi.mock`) and uses fake timers to assert on the exact payload shape passed to `sign()`, including that `customClaims` cannot clobber reserved claims.

SECURITY RULES: Never run env, printenv, or any command that dumps environment variables. Do not read or output the contents of .env files.