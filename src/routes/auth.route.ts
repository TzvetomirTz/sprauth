import { Router } from 'express';
import { handleGetAuthChallengeReq } from '../controllers/auth.controller.js';

const authRouter = Router();

authRouter.get('/challenge', handleGetAuthChallengeReq);


export default authRouter;
