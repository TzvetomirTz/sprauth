import { countUserActiveChallenges, countAllActiveChallenges, countUserActiveSessions, countAllActiveSessions } from '../services/redis.service.js';
export const handleCountUserActiveChallengesReq = async (req, res, next) => {
    try {
        const { identity } = req.query;
        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' query parameter." });
            return;
        }
        const count = await countUserActiveChallenges(identity);
        res.status(200).json({ count });
    }
    catch (error) {
        next(error);
    }
};
export const handleCountAllActiveChallengesReq = async (req, res, next) => {
    try {
        const count = await countAllActiveChallenges();
        res.status(200).json({ count });
    }
    catch (error) {
        next(error);
    }
};
export const handleCountUserActiveSessionsReq = async (req, res, next) => {
    try {
        const { identity } = req.query;
        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' query parameter." });
            return;
        }
        const count = await countUserActiveSessions(identity);
        res.status(200).json({ count });
    }
    catch (error) {
        next(error);
    }
};
export const handleCountAllActiveSessionsReq = async (req, res, next) => {
    try {
        const count = await countAllActiveSessions();
        res.status(200).json({ count });
    }
    catch (error) {
        next(error);
    }
};
//# sourceMappingURL=admin.controller.js.map