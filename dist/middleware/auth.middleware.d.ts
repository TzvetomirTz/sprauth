import type { Request, Response, NextFunction } from 'express';
/**
 * The verified claims we rely on from an access token. `verifySelfSigned` returns
 * the full token payload; these are the fields the authenticated routes trust.
 */
export interface AccessTokenPayload {
    identity: string;
    sessionId: string;
    tokenType: string;
    accessTokenId?: string;
    [key: string]: unknown;
}
declare global {
    namespace Express {
        interface Request {
            /** Set by `requireAccessToken` once a valid access token is verified. */
            auth?: AccessTokenPayload;
        }
    }
}
/**
 * Gate a route behind a valid access token supplied as `Authorization: Bearer <accessToken>`.
 *
 * Verifies the token's own ML-DSA signature (`verifySelfSigned`), that it is an access
 * token, and that its `access:<identity>:<sessionId>:<accessTokenId>` entry is still live
 * in Redis (`checkIsAccessTokenValid`) — the entry expires with its TTL and is deleted when
 * the session ends/is revoked, so ending a session immediately invalidates its access
 * tokens. On success it attaches the verified payload to `req.auth`. Downstream handlers
 * should take the caller identity from `req.auth`, never from client-supplied body/query,
 * so a caller can only act on their own account.
 */
export declare const requireAccessToken: (req: Request, res: Response, next: NextFunction) => Promise<void>;
//# sourceMappingURL=auth.middleware.d.ts.map