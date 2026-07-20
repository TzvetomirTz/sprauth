import { Router } from 'express';
import express from 'express';
import {
    handleAuthReq,
    handleListSessionsReq,
    handleCheckSessionValidReq,
    handleEndSessionReq,
    handleEndUserSessionsReq
} from '../controllers/session.controller.js';

const sessionRouter = Router();

sessionRouter.post('/auth', express.json(), handleAuthReq);
sessionRouter.get('/', handleListSessionsReq);
sessionRouter.get('/valid', handleCheckSessionValidReq);
sessionRouter.post('/end', express.json(), handleEndSessionReq);
sessionRouter.post('/revoke', express.json(), handleEndUserSessionsReq);

export default sessionRouter;
