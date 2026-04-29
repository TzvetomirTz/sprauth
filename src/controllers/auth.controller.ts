import type { Request, Response, NextFunction } from 'express';
import { generateAuthChallenge } from '../services/auth.service.js';

export const handleGetAuthChallengeReq = async (
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

        const challengeToken = await generateAuthChallenge(identity);
        res.status(200).json({ challengeToken });
    } catch (error) {
        next(error);
    }
}