import type { Request, Response, NextFunction } from 'express';
import { generateChallengeToken } from '../services/auth.service.js';
import { checkIsChallengeValid } from '../services/redis.service.js';

export const handleInitChallengeReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const { identity, intent, customClaims } = req.body;

        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' query parameter." });
            return;
        }

        if (!intent || typeof intent !== 'string' || intent.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'intent' query parameter." });
            return;
        }

        const challengeToken = await generateChallengeToken(identity, intent, customClaims);
        res.status(200).json({ challengeToken });
    } catch (error) {
        next(error);
    }
}

export const handleCheckChallengeValidReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const { identity, tokenId, consume } = req.body;

        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' body parameter." });
            return;
        }

        if (!tokenId || typeof tokenId !== 'string' || tokenId.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'tokenId' body parameter." });
            return;
        }

        if (consume !== undefined && typeof consume !== 'boolean') {
            res.status(400).json({ error: "Invalid 'consume' body parameter, expected a boolean." });
            return;
        }

        const isValid = await checkIsChallengeValid(identity, tokenId, consume === true);

        res.status(200).json({ valid: isValid });
    } catch (error) {
        next(error);
    }
}
