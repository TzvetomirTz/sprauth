import { Router } from 'express';
import express from 'express';
import { handleAuthReq, handleRefreshReq, handleListSessionsReq, handleCheckSessionValidReq, handleEndSessionReq, handleEndUserSessionsReq } from '../controllers/session.controller.js';
import { requireAccessToken } from '../middleware/auth.middleware.js';
const sessionRouter = Router();
sessionRouter.post('/auth', express.json(), handleAuthReq);
sessionRouter.post('/refresh', express.json(), handleRefreshReq);
sessionRouter.get('/', handleListSessionsReq);
sessionRouter.get('/valid', handleCheckSessionValidReq);
sessionRouter.post('/end', requireAccessToken, express.json(), handleEndSessionReq);
sessionRouter.post('/revoke', requireAccessToken, express.json(), handleEndUserSessionsReq);
export default sessionRouter;
//# sourceMappingURL=session.route.js.map