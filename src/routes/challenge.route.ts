import { Router } from 'express';
import express from 'express';
import { handleInitChallengeReq, handleVerifyChallengeReq } from '../controllers/challenge.controller.js';

const challengeRouter = Router();

challengeRouter.post('/init', express.json(), handleInitChallengeReq);
challengeRouter.post('/verify', express.json(), handleVerifyChallengeReq);

export default challengeRouter;
