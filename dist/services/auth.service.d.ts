export declare const generateChallengeToken: (identity: string, intent: string, customClaims: object) => Promise<string>;
export declare const generateAuthToken: (challengeToken: object, tokenType: string, extraClaims?: object) => string;
export declare const issueSessionTokens: (tokenPayload: {
    identity: string;
    sessionId: string;
    [key: string]: unknown;
}) => Promise<{
    accessToken: string;
    refreshToken: string;
}>;
//# sourceMappingURL=auth.service.d.ts.map