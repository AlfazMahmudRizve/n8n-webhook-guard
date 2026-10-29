export interface WebhookValidationOptions {
    headerName?: string;
    toleranceSeconds?: number;
    timestampHeader?: string;
    algorithm?: 'sha256' | 'sha512';
}
export interface WebhookValidationResult {
    isValid: boolean;
    error?: string;
    timestamp?: number;
}
export interface CircuitBreakerOptions {
    failureThreshold?: number;
    resetTimeoutMs?: number;
}
export type CircuitBreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';
/**
 * Generate a hex HMAC signature for an n8n webhook payload
 */
export declare function generateWebhookSignature(payload: string | Buffer, secret: string, algorithm?: 'sha256' | 'sha512'): string;
/**
 * Timing-safe HMAC verification preventing timing attacks
 */
export declare function verifyWebhookSignature(payload: string | Buffer, expectedSignature: string, secret: string, algorithm?: 'sha256' | 'sha512'): boolean;
/**
 * Validate incoming request headers with replay-attack protection
 */
export declare function validateWebhookRequest(payload: string, headers: Record<string, string | string[] | undefined>, secret: string, options?: WebhookValidationOptions): WebhookValidationResult;
/**
 * In-memory Circuit Breaker to prevent cascading downstream failures
 */
export declare class WebhookCircuitBreaker {
    private state;
    private failureCount;
    private nextAttempt;
    private readonly failureThreshold;
    private readonly resetTimeoutMs;
    constructor(options?: CircuitBreakerOptions);
    getState(): CircuitBreakerState;
    canExecute(): boolean;
    recordSuccess(): void;
    recordFailure(): void;
}
