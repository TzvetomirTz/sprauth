import { Router } from 'express';
import express from 'express';
import {
    handleStartSessionReq,
    handleListSessionsReq,
    handleCheckSessionValidReq,
    handleEndSessionReq,
    handleEndUserSessionsReq
} from '../controllers/session.controller.js';

const sessionRouter = Router();

sessionRouter.post('/start', express.json(), handleStartSessionReq);
sessionRouter.get('/', handleListSessionsReq);
sessionRouter.get('/valid', handleCheckSessionValidReq);
sessionRouter.post('/end', express.json(), handleEndSessionReq);
sessionRouter.post('/revoke', express.json(), handleEndUserSessionsReq);

export default sessionRouter;
