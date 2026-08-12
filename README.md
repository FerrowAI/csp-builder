# csp-builder

Typed Content-Security-Policy builder with fluent directives, nonce/hash helpers, and standards-compliant header generation.

## Quick Start

```typescript
import CSPBuilder, { KEYWORDS } from "csp-builder";

const csp = new CSPBuilder()
  .defaultSrc(KEYWORDS.self)
  .scriptSrc(KEYWORDS.self, "https://trusted.com")
  .styleSrc(KEYWORDS.self)
  .toString();

// Output: "default-src 'self'; script-src 'self' https://trusted.com; style-src 'self'"
```

## API

### Directives

All directives accept multiple values and are chainable:

- `defaultSrc(...values)`
- `scriptSrc(...values)`
- `styleSrc(...values)`
- `imgSrc(...values)`
- `fontSrc(...values)`
- `connectSrc(...values)`
- `mediaSrc(...values)`
- `objectSrc(...values)`
- `childSrc(...values)`
- `formAction(...values)`
- `frameAncestors(...values)`
- `reportUri(uri)` / `reportTo(group)`
- `upgradeInsecureRequests()`
- `blockAllMixedContent()`

### Keywords

```typescript
import { KEYWORDS } from "csp-builder";

KEYWORDS.self           // 'self'
KEYWORDS.none           // 'none'
KEYWORDS.unsafeInline   // 'unsafe-inline' (discouraged)
KEYWORDS.unsafeEval     // 'unsafe-eval'
KEYWORDS.strictDynamic  // 'strict-dynamic'
KEYWORDS.reportSample   // 'report-sample'
```

### Nonce & Hash

```typescript
const nonce = csp.generateNonce();
csp.scriptSrc(csp.nonce(nonce));

const hash = csp.hash("console.log('hi')", "sha256");
csp.scriptSrc(hash);
```

### Output

```typescript
csp.toString();       // Full CSP header string
csp.toMeta();         // Meta tag variant (drops frame-ancestors)
csp.getHeaderName();  // "Content-Security-Policy" or "...-Report-Only"
```

### Parsing

```typescript
const parsed = CSPBuilder.parse("default-src 'self'; script-src https:");
```

## Limits

- No directive validation (application responsibility)
- frame-ancestors unsupported in meta tags (per spec)
- Keyword constants listed; 'unsafe-inline' use is logged as conceptually discouraged

---

Part of the [ferrow-toolkit](https://github.com/Ruzylo-cloud/ferrow-toolkit) collection · Sponsored by [Ferrow](https://ferrow.ai)
