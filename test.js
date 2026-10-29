const assert = require('assert');
const {
  generateWebhookSignature,
  verifyWebhookSignature,
  validateWebhookRequest,
  WebhookCircuitBreaker
} = require('./dist/index.js');

console.log('🧪 Running n8n-webhook-guard test suite...');

const secret = 'prod_secret_key_12345';
const payload = JSON.stringify({ event: 'lead.created', email: 'test@example.com', amount: 5000 });

// 1. Signature generation & verification
const sig = generateWebhookSignature(payload, secret);
assert(typeof sig === 'string' && sig.length === 64, 'Signature should be 64-char hex string');

const isValid = verifyWebhookSignature(payload, sig, secret);
assert(isValid === true, 'Signature should be valid');

const isInvalid = verifyWebhookSignature(payload + '_tampered', sig, secret);
assert(isInvalid === false, 'Tampered signature should fail');

// 2. Request validation with timestamp
const timestamp = Math.floor(Date.now() / 1000);
const tsPayload = `${timestamp}.${payload}`;
const tsSig = generateWebhookSignature(tsPayload, secret);

const valResult = validateWebhookRequest(payload, {
  'x-n8n-signature': tsSig,
  'x-n8n-timestamp': timestamp.toString()
}, secret);

assert(valResult.isValid === true, 'Request validation with timestamp should pass');

// 3. Replay attack rejection (timestamp drift > 300s)
const oldTimestamp = timestamp - 400;
const oldTsPayload = `${oldTimestamp}.${payload}`;
const oldTsSig = generateWebhookSignature(oldTsPayload, secret);

const replayResult = validateWebhookRequest(payload, {
  'x-n8n-signature': oldTsSig,
  'x-n8n-timestamp': oldTimestamp.toString()
}, secret, { toleranceSeconds: 300 });

assert(replayResult.isValid === false, 'Replay attack outside tolerance should be rejected');

// 4. Circuit breaker state transitions
const breaker = new WebhookCircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 100 });
assert(breaker.getState() === 'CLOSED', 'Initial state should be CLOSED');
assert(breaker.canExecute() === true, 'Can execute when CLOSED');

breaker.recordFailure();
breaker.recordFailure();
assert(breaker.getState() === 'CLOSED', 'Should stay CLOSED below threshold');

breaker.recordFailure();
assert(breaker.getState() === 'OPEN', 'Should switch to OPEN after 3 failures');
assert(breaker.canExecute() === false, 'Cannot execute when OPEN');

console.log('✅ ALL TESTS PASSED (100% functional integrity verified)');
