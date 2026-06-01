import type { Request, Response, NextFunction } from 'express';
import { verifyChallengeSignature, verifySprauthSigned } from '../services/sec.service.js';

export const handleAuthReq = async (
    req: Request, 
    res: Response, 
    next: NextFunction
): Promise<void> => {
    try {
        const {challengeJwt, signature, publicKey} = req.body;
        const payload = verifySprauthSigned(challengeJwt);
        const result = await verifyChallengeSignature(payload.challenge, signature, publicKey, payload.identity);
        // ToDo: issue JWTs here lol

        if (result.success) {
            res.status(200).json({ "": "" });
            return;
        }

        res.status(400).json({});
    } catch (error) {
        next(error);
    }
}
