import type { Request, Response, NextFunction } from 'express';
import { generateChallengeToken } from '../services/auth.service.js';
import { verifyChallengeSignature, verifySprauthSigned } from '../services/sec.service.js';

export const handleInitChallengeReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const { identity, intent, claims } = req.body;

        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' query parameter." });
            return;
        }

        if (!intent || typeof intent !== 'string' || intent.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'intent' query parameter." });
            return;
        }

        const challengeToken = await generateChallengeToken(identity, intent, claims);
        res.status(200).json({ challengeToken });
    } catch (error) {
        next(error);
    }
}

export const handleVerifyChallengeReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const {challengeJwt, signature, publicKey} = req.body;
        const payload = verifySprauthSigned(challengeJwt);
        const result = await verifyChallengeSignature(payload.challenge, signature, publicKey, payload.identity);

        if (result.success) {
            res.status(200).json({ challengePassed: true });
            return;
        }

        res.status(401).json({ challengePassed: false });
    } catch (error) {
        next(error);
    }
}