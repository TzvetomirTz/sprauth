import { startSession, getAllUserSessions, checkIsSessionValid, renewSession, endSession, endUserSessions, consumeRefreshToken } from '../services/redis.service.js';
import { verifyChallengeSignature, verifySelfSigned, verifySprauthSigned } from '../services/sec.service.js';
import { issueSessionTokens } from '../services/auth.service.js';
export const handleAuthReq = async (req, res, next) => {
    try {
        const { challengeJwt, signature, publicKey } = req.body;
        const payload = await verifySprauthSigned(challengeJwt);
        const result = await verifyChallengeSignature(payload.challenge, signature, publicKey, payload.identity);
        if (!result.success) {
            res.status(401).json({
                challengePassed: false,
                accessToken: null,
                refreshToken: null,
                sessionId: null
            });
            return;
        }
        const sessionId = crypto.randomUUID();
        await startSession(payload.identity, sessionId);
        const tokenPayload = { ...payload, sessionId };
        const { accessToken, refreshToken } = await issueSessionTokens(tokenPayload);
        res.status(200).json({
            challengePassed: true,
            accessToken,
            refreshToken,
            sessionId
        });
    }
    catch {
        // Verification threw (invalid/expired/consumed challenge, bad signature, etc.) — this
        // is the expected failure path, so respond 401 and stop. Do NOT also call next(error):
        // the response is already sent, and there is no error middleware to handle it.
        res.status(401).json({
            challengePassed: false,
            accessToken: null,
            refreshToken: null,
            sessionId: null
        });
    }
};
export const handleRefreshReq = async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken || typeof refreshToken !== 'string' || refreshToken.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'refreshToken' body parameter." });
            return;
        }
        const payload = verifySelfSigned(refreshToken);
        if (payload.tokenType !== 'refreshToken') {
            res.status(401).json({ error: 'Token is not a refresh token.' });
            return;
        }
        if (!payload.identity || !payload.sessionId || !payload.refreshTokenId) {
            res.status(401).json({ error: 'Refresh token is missing identity or session information.' });
            return;
        }
        // Check validity WITHOUT renewing — a doomed request (e.g. a replayed, already-consumed
        // refresh token) must not extend the session's TTL.
        const isSessionValid = await checkIsSessionValid(payload.identity, payload.sessionId, false);
        if (!isSessionValid) {
            res.status(401).json({ error: 'Session is not valid or has expired.' });
            return;
        }
        const wasConsumed = await consumeRefreshToken(payload.identity, payload.sessionId, payload.refreshTokenId);
        if (!wasConsumed) {
            res.status(401).json({ error: 'Refresh token has already been used or has been revoked.' });
            return;
        }
        // Only now that the refresh has succeeded do we renew the session TTL.
        await renewSession(payload.identity, payload.sessionId);
        const tokens = await issueSessionTokens(payload);
        res.status(200).json({
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            sessionId: payload.sessionId
        });
    }
    catch {
        // Verification threw (malformed/tampered refresh token) — expected failure path, so
        // respond 401 and stop. See handleAuthReq for why next(error) is intentionally omitted.
        res.status(401).json({
            accessToken: null,
            refreshToken: null,
            sessionId: null
        });
    }
};
export const handleListSessionsReq = async (req, res, next) => {
    try {
        const { identity } = req.query;
        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' query parameter." });
            return;
        }
        const sessions = await getAllUserSessions(identity);
        res.status(200).json({ sessions });
    }
    catch (error) {
        next(error);
    }
};
export const handleCheckSessionValidReq = async (req, res, next) => {
    try {
        const { identity, sessionId, renewTtl } = req.query;
        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' query parameter." });
            return;
        }
        if (!sessionId || typeof sessionId !== 'string' || sessionId.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'sessionId' query parameter." });
            return;
        }
        const isValid = await checkIsSessionValid(identity, sessionId, renewTtl === 'true');
        res.status(200).json({ valid: isValid });
    }
    catch (error) {
        next(error);
    }
};
export const handleEndSessionReq = async (req, res, next) => {
    try {
        // Identity comes from the verified access token (requireAccessToken), never the
        // body — a caller can only end their own sessions.
        const identity = req.auth.identity;
        const { sessionId } = req.body;
        if (!sessionId || typeof sessionId !== 'string' || sessionId.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'sessionId' body parameter." });
            return;
        }
        await endSession(identity, sessionId);
        res.status(200).json({ ended: true });
    }
    catch (error) {
        next(error);
    }
};
export const handleEndUserSessionsReq = async (req, res, next) => {
    try {
        // Identity comes from the verified access token (requireAccessToken), never the
        // body — a caller can only revoke their own sessions.
        const identity = req.auth.identity;
        const { except } = req.body;
        if (except !== undefined && !Array.isArray(except)) {
            res.status(400).json({ error: "Invalid 'except' body parameter, expected an array." });
            return;
        }
        const revokedCount = await endUserSessions(identity, except ?? []);
        res.status(200).json({ revokedCount });
    }
    catch (error) {
        next(error);
    }
};
//# sourceMappingURL=session.controller.js.map