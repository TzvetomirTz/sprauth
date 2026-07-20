import type { Request, Response, NextFunction } from 'express';
import {
    startSession,
    getAllUserSessions,
    checkIsSessionValid,
    endSession,
    endUserSessions
} from '../services/redis.service.js';
import { verifyChallengeSignature, verifySelfSigned, verifySprauthSigned } from '../services/sec.service.js';
import { generateAuthToken } from '../services/auth.service.js';

export const handleAuthReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const {challengeJwt, signature, publicKey} = req.body;
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

        // sessionId is baked into the signed tokens so /session/refresh can trust
        // it without the caller having to (or being able to lie about) supplying it.
        const tokenPayload = { ...payload, sessionId };

        res.status(200).json({
            challengePassed: true,
            accessToken: generateAuthToken(tokenPayload, "accessToken"),
            refreshToken: generateAuthToken(tokenPayload, "refreshToken"),
            sessionId
        });
    } catch (error) {
        res.status(401).json({
            challengePassed: false,
            accessToken: null,
            refreshToken: null,
            sessionId: null
        });

        next(error);
    }
}

export const handleRefreshReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
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

        if (!payload.identity || !payload.sessionId) {
            res.status(401).json({ error: 'Refresh token is missing identity or session information.' });
            return;
        }

        const isSessionValid = await checkIsSessionValid(payload.identity, payload.sessionId, true);

        if (!isSessionValid) {
            res.status(401).json({ error: 'Session is not valid or has expired.' });
            return;
        }

        res.status(200).json({
            accessToken: generateAuthToken(payload, "accessToken"),
            refreshToken: generateAuthToken(payload, "refreshToken"),
            sessionId: payload.sessionId
        });
    } catch (error) {
        res.status(401).json({
            accessToken: null,
            refreshToken: null,
            sessionId: null
        });

        next(error);
    }
}

export const handleListSessionsReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const { identity } = req.query;

        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' query parameter." });
            return;
        }

        const sessions = await getAllUserSessions(identity);

        res.status(200).json({ sessions });
    } catch (error) {
        next(error);
    }
}

export const handleCheckSessionValidReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
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
    } catch (error) {
        next(error);
    }
}

export const handleEndSessionReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const { identity, sessionId } = req.body;

        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' body parameter." });
            return;
        }

        if (!sessionId || typeof sessionId !== 'string' || sessionId.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'sessionId' body parameter." });
            return;
        }

        await endSession(identity, sessionId);

        res.status(200).json({ ended: true });
    } catch (error) {
        next(error);
    }
}

export const handleEndUserSessionsReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const { identity, except } = req.body;

        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' body parameter." });
            return;
        }

        if (except !== undefined && !Array.isArray(except)) {
            res.status(400).json({ error: "Invalid 'except' body parameter, expected an array." });
            return;
        }

        const revokedCount = await endUserSessions(identity, except ?? []);

        res.status(200).json({ revokedCount });
    } catch (error) {
        next(error);
    }
}
