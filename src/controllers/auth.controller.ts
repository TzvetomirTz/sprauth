import type { Request, Response, NextFunction } from 'express';
import { verifyChallengeSignature, verifySprauthSigned } from '../services/sec.service.js';
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
                refreshToken: null
            });
            return;
        }

        res.status(200).json({
            challengePassed: true,
            accessToken: generateAuthToken(payload, "accessToken"),
            refreshToken: generateAuthToken(payload, "refreshToken")
        });
    } catch (error) {
        next(error);
    }
}
