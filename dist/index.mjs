"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.WebhookCircuitBreaker = void 0;
exports.generateWebhookSignature = generateWebhookSignature;
exports.verifyWebhookSignature = verifyWebhookSignature;
exports.validateWebhookRequest = validateWebhookRequest;
const crypto = __importStar(require("crypto"));
/**
 * Generate a hex HMAC signature for an n8n webhook payload
 */
function generateWebhookSignature(payload, secret, algorithm = 'sha256') {
    return crypto.createHmac(algorithm, secret).update(payload).digest('hex');
}
/**
 * Timing-safe HMAC verification preventing timing attacks
 */
function verifyWebhookSignature(payload, expectedSignature, secret, algorithm = 'sha256') {
    if (!expectedSignature || !secret)
        return false;
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
function validateWebhookRequest(payload, headers, secret, options = {}) {
    const headerName = (options.headerName || 'x-n8n-signature').toLowerCase();
    const timestampHeader = (options.timestampHeader || 'x-n8n-timestamp').toLowerCase();
    const tolerance = options.toleranceSeconds ?? 300; // default 5 minutes
    const algorithm = options.algorithm || 'sha256';
    let rawSignature;
    let rawTimestamp;
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
    let timestampNum;
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
class WebhookCircuitBreaker {
    state = 'CLOSED';
    failureCount = 0;
    nextAttempt = 0;
    failureThreshold;
    resetTimeoutMs;
    constructor(options = {}) {
        this.failureThreshold = options.failureThreshold ?? 5;
        this.resetTimeoutMs = options.resetTimeoutMs ?? 30000;
    }
    getState() {
        if (this.state === 'OPEN' && Date.now() >= this.nextAttempt) {
            this.state = 'HALF_OPEN';
        }
        return this.state;
    }
    canExecute() {
        const current = this.getState();
        return current === 'CLOSED' || current === 'HALF_OPEN';
    }
    recordSuccess() {
        this.failureCount = 0;
        this.state = 'CLOSED';
    }
    recordFailure() {
        this.failureCount++;
        if (this.failureCount >= this.failureThreshold) {
            this.state = 'OPEN';
            this.nextAttempt = Date.now() + this.resetTimeoutMs;
        }
    }
}
exports.WebhookCircuitBreaker = WebhookCircuitBreaker;
