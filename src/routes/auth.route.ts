import { Router } from 'express';
import express from 'express';
import { handleGetAuthChallengeReq, handleGetPublicKeyReq, handlePostAuthChallengeReq } from '../controllers/auth.controller.js';

const authRouter = Router();

authRouter.get('/key/public', handleGetPublicKeyReq);
authRouter.get('/challenge', handleGetAuthChallengeReq);
authRouter.post('/challenge', express.json(), handlePostAuthChallengeReq);


export default authRouter;
