import { generateChallengeToken } from '../services/auth.service.js';
import { checkIsChallengeValid } from '../services/redis.service.js';
export const handleInitChallengeReq = async (req, res, next) => {
    try {
        const { identity, intent, customClaims } = req.body;
        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' body parameter." });
            return;
        }
        if (!intent || typeof intent !== 'string' || intent.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'intent' body parameter." });
            return;
        }
        if (customClaims !== undefined &&
            (typeof customClaims !== 'object' || customClaims === null || Array.isArray(customClaims))) {
            res.status(400).json({ error: "Invalid 'customClaims' body parameter, expected an object." });
            return;
        }
        const challengeToken = await generateChallengeToken(identity, intent, customClaims ?? {});
        res.status(200).json({ challengeToken });
    }
    catch (error) {
        next(error);
    }
};
export const handleCheckChallengeValidReq = async (req, res, next) => {
    try {
        const { identity, tokenId, consume } = req.body;
        if (!identity || typeof identity !== 'string' || identity.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'identity' body parameter." });
            return;
        }
        if (!tokenId || typeof tokenId !== 'string' || tokenId.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'tokenId' body parameter." });
            return;
        }
        if (consume !== undefined && typeof consume !== 'boolean') {
            res.status(400).json({ error: "Invalid 'consume' body parameter, expected a boolean." });
            return;
        }
        const isValid = await checkIsChallengeValid(identity, tokenId, consume === true);
        res.status(200).json({ valid: isValid });
    }
    catch (error) {
        next(error);
    }
};
//# sourceMappingURL=challenge.controller.js.map