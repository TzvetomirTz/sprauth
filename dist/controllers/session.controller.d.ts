import type { Request, Response, NextFunction } from 'express';
export declare const handleAuthReq: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const handleRefreshReq: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const handleListSessionsReq: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const handleCheckSessionValidReq: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const handleEndSessionReq: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const handleEndUserSessionsReq: (req: Request, res: Response, next: NextFunction) => Promise<void>;
//# sourceMappingURL=session.controller.d.ts.map