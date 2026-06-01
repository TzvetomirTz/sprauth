import type { Request, Response } from 'express';
import { getPublicKeyBase64 } from '../services/sec.service.js';

export const handleGetPublicKeyReq = async (
    req: Request, 
    res: Response
) => {
    res.status(200).json({publicKey: getPublicKeyBase64()})
}
