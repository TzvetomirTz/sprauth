import { Router } from 'express';
import express from 'express';
import { handleInitChallengeReq, handleCheckChallengeValidReq } from '../controllers/challenge.controller.js';
const challengeRouter = Router();
challengeRouter.post('/init', express.json(), handleInitChallengeReq);
challengeRouter.post('/valid', express.json(), handleCheckChallengeValidReq);
export default challengeRouter;
//# sourceMappingURL=challenge.route.js.map