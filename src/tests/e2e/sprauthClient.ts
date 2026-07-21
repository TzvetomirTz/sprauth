import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
import supertest from 'supertest';
import type { Express } from 'express';

/**
 * Decode the base64url payload of a Sprauth JWT-like token.
 * The token layout is `base64url(header).base64url(payload).base64url(signature)`.
 */
export const decodeTokenPayload = (token: string): Record<string, any> => {
    const payloadB64Url = token.split('.')[1];

    if (!payloadB64Url) {
        throw new Error('Malformed token: missing payload segment.');
    }

    return JSON.parse(Buffer.from(payloadB64Url, 'base64url').toString('utf8'));
};

/**
 * A single ML-DSA-65 client identity paired with Supertest helpers for every
 * step of the auth flow. Each instance owns its own keypair, so tests can model
 * "the same user on two devices" simply by creating two clients (or reusing one
 * for two sessions).
 *
 * The helpers return the raw Supertest responses so scenario tests keep full
 * control over their assertions; they only layer on the ML-DSA signing that
 * Supertest/Postman cannot do on their own.
 */
export class SprauthClient {
    readonly identity: string;
    readonly publicKeyBase64: string;

    private readonly secretKey: Uint8Array;
    private readonly api: supertest.Agent;

    /** Access token from the most recent successful `authenticate`, used to authorize end/revoke. */
    private accessToken?: string;

    constructor(app: Express) {
        const { secretKey, publicKey } = ml_dsa65.keygen();

        this.secretKey = secretKey;
        this.publicKeyBase64 = Buffer.from(publicKey).toString('base64');

        const hash = createHash('sha256').update(publicKey).digest();
        this.identity = `pqc1${hash.subarray(-20).toString('hex')}`;

        this.api = supertest(app);
    }

    /** Sign an arbitrary message with this client's private key (base64). */
    sign(message: string): string {
        const messageBytes = new TextEncoder().encode(message);
        const signatureBytes = ml_dsa65.sign(messageBytes, this.secretKey);
        return Buffer.from(signatureBytes).toString('base64');
    }

    /** POST /challenge/init */
    initChallenge(intent = 'login', customClaims: object = {}) {
        return this.api
            .post('/challenge/init')
            .send({ identity: this.identity, intent, customClaims });
    }

    /** POST /challenge/valid */
    checkChallenge(tokenId: string, consume = false) {
        return this.api
            .post('/challenge/valid')
            .send({ identity: this.identity, tokenId, consume });
    }

    /**
     * POST /session/auth — signs the challenge embedded in `challengeToken`
     * with this client's key and authenticates.
     */
    async authenticate(challengeToken: string) {
        const { challenge } = decodeTokenPayload(challengeToken);

        const res = await this.postAuth({
            challengeJwt: challengeToken,
            signature: this.sign(challenge),
            publicKey: this.publicKeyBase64
        });

        if (res.status === 200 && res.body?.accessToken) {
            this.accessToken = res.body.accessToken;
        }

        return res;
    }

    /** POST /session/auth with a fully custom body (for unhappy-path tests). */
    postAuth(body: { challengeJwt?: unknown; signature?: unknown; publicKey?: unknown }) {
        return this.api.post('/session/auth').send(body);
    }

    /** POST /session/refresh */
    refresh(refreshToken: string) {
        return this.api.post('/session/refresh').send({ refreshToken });
    }

    /** GET /session/?identity=... */
    listSessions() {
        return this.api.get('/session/').query({ identity: this.identity });
    }

    /** GET /session/valid?identity=...&sessionId=...&renewTtl=... */
    checkSession(sessionId: string, renewTtl = false) {
        return this.api
            .get('/session/valid')
            .query({ identity: this.identity, sessionId, renewTtl });
    }

    /**
     * POST /session/end — authorized with a `Bearer` access token. Identity is derived
     * server-side from the token; `accessToken` defaults to this client's stored token
     * but can be overridden (or set to `undefined`) to exercise the auth failure paths.
     */
    endSession(sessionId: string, accessToken: string | undefined = this.accessToken) {
        const req = this.api.post('/session/end');
        if (accessToken !== undefined) req.set('Authorization', `Bearer ${accessToken}`);
        return req.send({ sessionId });
    }

    /**
     * POST /session/revoke — ends every session for this identity except `except`.
     * Authorized with a `Bearer` access token (see `endSession` for the override semantics).
     */
    revokeOtherSessions(except: string[] = [], accessToken: string | undefined = this.accessToken) {
        const req = this.api.post('/session/revoke');
        if (accessToken !== undefined) req.set('Authorization', `Bearer ${accessToken}`);
        return req.send({ except });
    }

    /** GET /admin/sessions/count?identity=... */
    countActiveSessions() {
        return this.api
            .get('/admin/sessions/count')
            .query({ identity: this.identity });
    }

    /** GET /admin/challenges/count?identity=... */
    countActiveChallenges() {
        return this.api
            .get('/admin/challenges/count')
            .query({ identity: this.identity });
    }
}
