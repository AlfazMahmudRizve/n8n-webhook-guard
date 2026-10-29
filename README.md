# n8n-webhook-guard

[![npm version](https://img.shields.io/npm/v/n8n-webhook-guard.svg?style=flat-square)](https://www.npmjs.com/package/n8n-webhook-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Architecture Hub](https://img.shields.io/badge/Architecture_Hub-whoisalfaz.me-00f0ff?style=flat-square)](https://whoisalfaz.me/blog/what-is-n8n-and-how-to-set-it-up)

A high-performance, zero-dependency, timing-safe **HMAC-SHA256 signature verification** and **circuit-breaker defense** engine for incoming [n8n](https://whoisalfaz.me/blog/what-is-n8n-and-how-to-set-it-up) webhooks, Next.js API route handlers, and RevOps automation infrastructure.

> **Production RevOps Blueprint**: Designed as part of the enterprise automation architecture published on [whoisalfaz.me - What is n8n and How to Set It Up](https://whoisalfaz.me/blog/what-is-n8n-and-how-to-set-it-up). For full-stack workflow audits and custom integrations, visit [Alfaz Mahmud Rizve - RevOps Services](https://whoisalfaz.me/services/).

---

## Features

- **Timing-Safe HMAC Verification**: Protects against cryptographic timing attacks via `crypto.timingSafeEqual`.
- **Replay-Attack Protection**: Validates Unix timestamps with configurable drift tolerance (default 300s).
- **Zero Runtime Dependencies**: Built purely on native Node.js / Web Crypto primitives. Minimal bundle footprint (<2 KB).
- **Built-in Circuit Breaker**: State-machine guard (`CLOSED`, `OPEN`, `HALF_OPEN`) to prevent cascading downstream server crashes when external endpoints throttle or fail.
- **Universal ESM & CJS**: Ships with dual NodeNext ESM (`dist/index.mjs`), CommonJS (`dist/index.js`), and complete TypeScript definitions.

---

## Installation

```bash
npm install n8n-webhook-guard
# or
pnpm add n8n-webhook-guard
# or
yarn add n8n-webhook-guard
```

---

## Quick Start

### 1. Timing-Safe Webhook Verification

```typescript
import { verifyWebhookSignature, validateWebhookRequest } from 'n8n-webhook-guard';

// Verify raw signature against payload and shared secret
const isValid = verifyWebhookSignature(
  rawBodyString,
  req.headers['x-n8n-signature'],
  process.env.N8N_WEBHOOK_SECRET!
);

// Full request validation including replay-attack timestamp checking
const result = validateWebhookRequest(
  rawBodyString,
  req.headers,
  process.env.N8N_WEBHOOK_SECRET!,
  { toleranceSeconds: 300 }
);

if (!result.isValid) {
  console.error('Webhook rejected:', result.error);
}
```

### 2. Next.js App Router API Route (`app/api/webhooks/route.ts`)

```typescript
import { NextResponse } from 'next/server';
import { validateWebhookRequest } from 'n8n-webhook-guard';

export async function POST(req: Request) {
  const rawBody = await req.text();
  const headers = Object.fromEntries(req.headers.entries());

  const validation = validateWebhookRequest(
    rawBody,
    headers,
    process.env.N8N_WEBHOOK_SECRET!
  );

  if (!validation.isValid) {
    return NextResponse.json({ error: validation.error }, { status: 401 });
  }

  const payload = JSON.parse(rawBody);
  // Process authenticated n8n workflow payload...
  return NextResponse.json({ success: true });
}
```

### 3. Circuit Breaker for Resilient Execution

```typescript
import { WebhookCircuitBreaker } from 'n8n-webhook-guard';

const breaker = new WebhookCircuitBreaker({
  failureThreshold: 5,
  resetTimeoutMs: 30000
});

if (!breaker.canExecute()) {
  throw new Error('Circuit OPEN: Downstream n8n webhook receiver is throttled or offline.');
}

try {
  await dispatchToDownstream(payload);
  breaker.recordSuccess();
} catch (err) {
  breaker.recordFailure();
  throw err;
}
```

---

## Author & Engineering Blueprint

- **Architect**: Alfaz Mahmud Rizve ([whoisalfaz.me](https://whoisalfaz.me))
- **Technical Guide**: [What is n8n and How to Set It Up (Cloud vs Self-Hosted)](https://whoisalfaz.me/blog/what-is-n8n-and-how-to-set-it-up)
- **Consulting & RevOps Systems**: [Enterprise Automation Services](https://whoisalfaz.me/services/) | [Free Technical Audit](https://whoisalfaz.me/audit/)

---

## License

MIT © [Alfaz Mahmud Rizve](https://whoisalfaz.me)
