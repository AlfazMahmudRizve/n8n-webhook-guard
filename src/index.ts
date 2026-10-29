import * as crypto from 'crypto';

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
export function generateWebhookSignature(
  payload: string | Buffer,
  secret: string,
  algorithm: 'sha256' | 'sha512' = 'sha256'
): string {
  return crypto.createHmac(algorithm, secret).update(payload).digest('hex');
}

/**
 * Timing-safe HMAC verification preventing timing attacks
 */
export function verifyWebhookSignature(
  payload: string | Buffer,
  expectedSignature: string,
  secret: string,
  algorithm: 'sha256' | 'sha512' = 'sha256'
): boolean {
  if (!expectedSignature || !secret) return false;

  const calculated = generateWebhookSignature(payload, secret, algorithm);
  const cleanExpected = expectedSignature.replace(/^(sha256=|sha512=)/i, '').trim();

  if (calculated.length !== cleanExpected.length) {
    return false;
  }

  const bufA = Buffer.from(calculated, 'hex');
  const bufB = Buffer.from(cleanExpected, 'hex');

  if (bufA.length !== bufB.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Validate incoming request headers with replay-attack protection
 */
export function validateWebhookRequest(
  payload: string,
  headers: Record<string, string | string[] | undefined>,
  secret: string,
  options: WebhookValidationOptions = {}
): WebhookValidationResult {
  const headerName = (options.headerName || 'x-n8n-signature').toLowerCase();
  const timestampHeader = (options.timestampHeader || 'x-n8n-timestamp').toLowerCase();
  const tolerance = options.toleranceSeconds ?? 300; // default 5 minutes
  const algorithm = options.algorithm || 'sha256';

  let rawSignature: string | undefined;
  let rawTimestamp: string | undefined;

  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (lower === headerName) {
      rawSignature = Array.isArray(value) ? value[0] : value;
    }
    if (lower === timestampHeader) {
      rawTimestamp = Array.isArray(value) ? value[0] : value;
    }
  }

  if (!rawSignature) {
    return { isValid: false, error: `Missing signature header: ${headerName}` };
  }

  let timestampNum: number | undefined;
  if (rawTimestamp) {
    timestampNum = parseInt(rawTimestamp, 10);
    if (isNaN(timestampNum)) {
      return { isValid: false, error: 'Malformed timestamp header' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestampNum) > tolerance) {
      return { isValid: false, error: 'Webhook timestamp outside allowed tolerance (replay attack protection)' };
    }
  }

  const toVerify = timestampNum ? `${timestampNum}.${payload}` : payload;
  const valid = verifyWebhookSignature(toVerify, rawSignature, secret, algorithm);

  if (!valid) {
    return { isValid: false, error: 'Signature mismatch' };
  }

  return { isValid: true, timestamp: timestampNum };
}

/**
 * In-memory Circuit Breaker to prevent cascading downstream failures
 */
export class WebhookCircuitBreaker {
  private state: CircuitBreakerState = 'CLOSED';
  private failureCount = 0;
  private nextAttempt = 0;
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;

  constructor(options: CircuitBreakerOptions = {}) {
    this.failureThreshold = options.failureThreshold ?? 5;
    this.resetTimeoutMs = options.resetTimeoutMs ?? 30000;
  }

  public getState(): CircuitBreakerState {
    if (this.state === 'OPEN' && Date.now() >= this.nextAttempt) {
      this.state = 'HALF_OPEN';
    }
    return this.state;
  }

  public canExecute(): boolean {
    const current = this.getState();
    return current === 'CLOSED' || current === 'HALF_OPEN';
  }

  public recordSuccess(): void {
    this.failureCount = 0;
    this.state = 'CLOSED';
  }

  public recordFailure(): void {
    this.failureCount++;
    if (this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.resetTimeoutMs;
    }
  }
}
