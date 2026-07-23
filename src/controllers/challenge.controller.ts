import type { Request, Response, NextFunction } from 'express';
import { generateChallengeToken } from '../services/auth.service.js';
import { checkIsChallengeValid } from '../services/redis.service.js';
import { verifyChallengeSignature, verifySelfSigned } from '../services/sec.service.js';

export const handleInitChallengeReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
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

        if (
            customClaims !== undefined &&
            (typeof customClaims !== 'object' || customClaims === null || Array.isArray(customClaims))
        ) {
            res.status(400).json({ error: "Invalid 'customClaims' body parameter, expected an object." });
            return;
        }

        const challengeToken = await generateChallengeToken(identity, intent, customClaims ?? {});
        res.status(200).json({ challengeToken });
    } catch (error) {
        next(error);
    }
}

export const handleCheckChallengeValidReq = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const { challengeJwt, signature, publicKey, consume } = req.body;

        if (!challengeJwt || typeof challengeJwt !== 'string' || challengeJwt.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'challengeJwt' body parameter." });
            return;
        }

        if (!signature || typeof signature !== 'string' || signature.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'signature' body parameter." });
            return;
        }

        if (!publicKey || typeof publicKey !== 'string' || publicKey.trim() === '') {
            res.status(400).json({ error: "Missing or invalid 'publicKey' body parameter." });
            return;
        }

        if (consume !== undefined && typeof consume !== 'boolean') {
            res.status(400).json({ error: "Invalid 'consume' body parameter, expected a boolean." });
            return;
        }

        // Verify the challenge JWT's own server signature (signature-only, so the
        // Redis entry is not consumed here — the `consume` param governs that below).
        let payload;
        try {
            payload = verifySelfSigned(challengeJwt);
        } catch {
            res.status(401).json({ valid: false });
            return;
        }

        // Verify the client's signature over the challenge string against the identity.
        const result = await verifyChallengeSignature(
            payload.challenge,
            signature,
            publicKey,
            payload.identity
        );

        if (!result.success) {
            res.status(401).json({ valid: false });
            return;
        }

        const isValid = await checkIsChallengeValid(payload.identity, payload.tokenId, consume === true);

        res.status(200).json({ valid: isValid });
    } catch (error) {
        next(error);
    }
}
