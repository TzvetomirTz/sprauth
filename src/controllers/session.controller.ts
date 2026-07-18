import type { Request, Response, NextFunction } from 'express';
import {
    startSession,
    getAllUserSessions,
    checkIsSessionValid,
    endSession,
    endUserSessions
} from '../services/redis.service.js';

export const handleStartSessionReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const { identity } = req.body;

        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' body parameter." });
            return;
        }

        const sessionId = crypto.randomUUID();
        await startSession(identity, sessionId);

        res.status(200).json({ sessionId });
    } catch (error) {
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
