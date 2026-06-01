import { Router } from 'express';
import express from 'express';
import { handleAuthReq } from '../controllers/auth.controller.js';

const authRouter = Router();

authRouter.post('/', express.json(), handleAuthReq);

export default authRouter;
