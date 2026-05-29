import { Router } from 'express';
import { handleGetPublicKeyReq } from '../controllers/auth.controller.js';

const secRouter = Router();

secRouter.get('/key/public', handleGetPublicKeyReq);

export default secRouter;
