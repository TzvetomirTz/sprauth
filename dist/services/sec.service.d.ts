export declare const getPublicKeyBase64: () => string;
export declare const getSecretKey: () => Uint8Array<ArrayBuffer>;
export declare const generateSafeRandomString: (byteLength?: number) => string;
export declare const sign: (payload: object, secretKey: Uint8Array) => string;
export declare const verifySelfSigned: (token: string) => any;
export declare const verifySprauthSigned: (token: string) => Promise<any>;
export declare const verifyChallengeSignature: (challenge: string, signatureBase64: string, publicKeyBase64: string, claimedAddress: string) => Promise<{
    success: boolean;
    address: string;
    error?: never;
} | {
    success: boolean;
    error: any;
    address?: never;
}>;
export declare const derivePQCAddress: (publicKey: Uint8Array) => string;
//# sourceMappingURL=sec.service.d.ts.map