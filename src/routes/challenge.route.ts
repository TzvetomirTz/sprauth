import { Router } from 'express';
import express from 'express';
import { handleInitChallengeReq, handleVerifyChallengeReq, handleCheckChallengeValidReq } from '../controllers/challenge.controller.js';

const challengeRouter = Router();

challengeRouter.post('/init', express.json(), handleInitChallengeReq);
challengeRouter.post('/verify', express.json(), handleVerifyChallengeReq);
challengeRouter.get('/valid', handleCheckChallengeValidReq);

export default challengeRouter;
