import { Router } from 'express';
import { handleGetAuthChallengeReq, handleGetPublicKeyReq } from '../controllers/auth.controller.js';

const authRouter = Router();

authRouter.get('/key/public', handleGetPublicKeyReq);
authRouter.get('/challenge', handleGetAuthChallengeReq);


export default authRouter;
