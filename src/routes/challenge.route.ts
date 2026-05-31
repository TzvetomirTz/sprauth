import { Router } from 'express';
import express from 'express';
import { handleInitChallengeReq, handlePostAuthChallengeReq } from '../controllers/auth.controller.js';

const challengeRouter = Router();

challengeRouter.post('/init', express.json(), handleInitChallengeReq);
challengeRouter.post('/verify', express.json(), handlePostAuthChallengeReq);

export default challengeRouter;
