import type { Request, Response, NextFunction } from 'express';
import { generateAuthChallenge, getPublicKeyBase64, verifyChallengeSignature, verifySprauthSigned } from '../services/auth.service.js';

export const handleGetPublicKeyReq = async (
    req: Request, 
    res: Response
) => {
    res.status(200).json({publicKey: getPublicKeyBase64()})
}

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

export const handlePostAuthChallengeReq = async (
    req: Request, 
    res: Response, 
    next: NextFunction
): Promise<void> => {
    try {
        const {challengeJwt, signature, publicKey} = req.body;
        const payload = verifySprauthSigned(challengeJwt);

        console.log(payload);
        
        
        const result = await verifyChallengeSignature(payload.challenge, signature, publicKey, payload.identity);

        if (result.success) {
            res.status(200).json({ "": "" });
        }

        res.status(400).json({});
    } catch (error) {
        next(error);
    }
}
