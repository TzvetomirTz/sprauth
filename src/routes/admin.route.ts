import { Router } from 'express';
import {
    handleCountUserActiveChallengesReq,
    handleCountAllActiveChallengesReq,
    handleCountUserActiveSessionsReq,
    handleCountAllActiveSessionsReq
} from '../controllers/admin.controller.js';

const adminRouter = Router();

adminRouter.get('/challenges/count', handleCountUserActiveChallengesReq);
adminRouter.get('/challenges/count/all', handleCountAllActiveChallengesReq);
adminRouter.get('/sessions/count', handleCountUserActiveSessionsReq);
adminRouter.get('/sessions/count/all', handleCountAllActiveSessionsReq);

export default adminRouter;
