import type { Request, Response } from 'express';
import { generateAuthChallenge } from '../services/auth.service.js';

export const handleGetAuthChallengeReq = async (req: Request, res: Response) => {
    
    res.status(200).json({
        challengeToken: await generateAuthChallenge()
    });
}
