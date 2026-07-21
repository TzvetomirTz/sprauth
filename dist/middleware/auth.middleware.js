import { verifySelfSigned } from '../services/sec.service.js';
import { checkIsAccessTokenValid } from '../services/redis.service.js';
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
export const requireAccessToken = async (req, res, next) => {
    const authHeader = req.header('authorization');
    // The auth scheme is case-insensitive per RFC 7235; tolerate any casing and extra spaces.
    const match = authHeader?.match(/^Bearer\s+(.+)$/i);
    if (!match) {
        res.status(401).json({
            error: "Missing or malformed 'Authorization' header. Expected 'Bearer <accessToken>'."
        });
        return;
    }
    const token = match[1].trim();
    if (token === '') {
        res.status(401).json({ error: 'Missing bearer token.' });
        return;
    }
    let payload;
    try {
        payload = verifySelfSigned(token);
    }
    catch {
        res.status(401).json({ error: 'Invalid access token.' });
        return;
    }
    if (payload.tokenType !== 'accessToken') {
        res.status(401).json({ error: 'Token is not an access token.' });
        return;
    }
    if (!payload.identity || !payload.sessionId || !payload.accessTokenId) {
        res.status(401).json({ error: 'Access token is missing identity or session information.' });
        return;
    }
    try {
        const isValid = await checkIsAccessTokenValid(payload.identity, payload.sessionId, payload.accessTokenId);
        if (!isValid) {
            res.status(401).json({ error: 'Access token has expired or been revoked.' });
            return;
        }
    }
    catch (error) {
        next(error);
        return;
    }
    req.auth = payload;
    next();
};
//# sourceMappingURL=auth.middleware.js.map