import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateChallengeToken } from './auth.service.js';
import * as secService from './sec.service.js';

vi.mock('./sec.service.js', () => ({
    generateSafeRandomString: vi.fn(),
    getSecretKey: vi.fn(),
    sign: vi.fn(),
}));

vi.mock('./redis.service.js', () => ({
    storeChallenge: vi.fn().mockResolvedValue(undefined),
}));

describe('auth.service - generateChallengeToken', () => {
    const MOCK_TIME = 1780775020000;
    const MOCK_RANDOM_STRING = 'mocked-random-challenge-string';
    const MOCK_SECRET_KEY = new Uint8Array(Buffer.from('super-secret-test-key'));
    const MOCK_SIGNED_TOKEN = 'header.payload.signature';

    beforeEach(() => {
        vi.useFakeTimers();
        vi.setSystemTime(MOCK_TIME);

        vi.mocked(secService.generateSafeRandomString).mockReturnValue(MOCK_RANDOM_STRING);
        vi.mocked(secService.getSecretKey).mockReturnValue(MOCK_SECRET_KEY);
        vi.mocked(secService.sign).mockResolvedValue(MOCK_SIGNED_TOKEN);
    });

    afterEach(() => {
        vi.clearAllMocks();
        vi.useRealTimers();
    });

    it('should generate a token with the correct payload and secret key', async () => {
        const customClaims = { metadata: { tier: 'premium' } };
        
        const result = await generateChallengeToken('mock-identity', 'mock-intent', customClaims);

        expect(secService.generateSafeRandomString).toHaveBeenCalledOnce();
        expect(secService.getSecretKey).toHaveBeenCalledOnce();
        expect(secService.sign).toHaveBeenCalledWith(
            {
                metadata: { tier: 'premium' },
                iat: MOCK_TIME,
                identity: 'mock-identity',
                intent: 'mock-intent',
                challenge: MOCK_RANDOM_STRING,
                tokenId: expect.any(String),
            },
            MOCK_SECRET_KEY
        );

        expect(result).toBe(MOCK_SIGNED_TOKEN);
    });

    it('should handle empty customClaims correctly', async () => {
        await generateChallengeToken('mock-identity', 'mock-intent', {});

        expect(secService.sign).toHaveBeenCalledWith(
            {
                iat: MOCK_TIME,
                identity: 'mock-identity',
                intent: 'mock-intent',
                challenge: MOCK_RANDOM_STRING,
                tokenId: expect.any(String),
            },
            MOCK_SECRET_KEY
        );
    });

    it('should prevent customClaims from overwriting reserved core claims', async () => {
        const maliciousClaims = {
            identity: 'fake-identity', 
            intent: 'fake-intent',
            iat: 999999,
            challenge: 'fake-challenge',
            metadata: { theme: 'dark' }
        };

        await generateChallengeToken('real-identity', 'real-intent', maliciousClaims);

        expect(secService.sign).toHaveBeenCalledWith(
            {
                metadata: { theme: 'dark' },
                iat: MOCK_TIME,
                identity: 'real-identity',
                intent: 'real-intent',
                challenge: MOCK_RANDOM_STRING,
                tokenId: expect.any(String),
            },
            MOCK_SECRET_KEY
        );
    });
});