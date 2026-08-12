const CSPBuilder = require("../dist/index").default;
const { KEYWORDS } = require("../dist/index");

// Demo: build a real policy string
const builder = new CSPBuilder();
builder
  .defaultSrc(KEYWORDS.self)
  .scriptSrc(KEYWORDS.self, "https://trusted.com")
  .styleSrc(KEYWORDS.self, KEYWORDS.unsafeInline)
  .imgSrc(KEYWORDS.self, "https:", "data:")
  .connectSrc("https://api.example.com")
  .frameAncestors(KEYWORDS.self);

const policyString = builder.toString();
console.log("Generated Policy:\n" + policyString);

// Demo: nonce round-trip
const nonce = builder.generateNonce();
const nonceDirective = builder.nonce(nonce);
console.log("\nGenerated nonce directive:", nonceDirective);

// Demo: hash for inline script
const scriptContent = "console.log('hello');";
const scriptHash = builder.hash(scriptContent, "sha256");
console.log("Script hash:", scriptHash);

// Demo: parse existing header back into builder
const parsed = CSPBuilder.parse(policyString);
console.log("\nParsed policy:");
console.log(parsed.toString());

// Demo: toMeta() with frame-ancestors (should warn and drop)
console.log("\nMeta tag version (frame-ancestors dropped with warning):");
console.log(builder.toMeta());

// Demo: header name
console.log("\nHeader name (non-report-only):", builder.getHeaderName());
const ro = new CSPBuilder({ reportOnly: true });
console.log("Header name (report-only):", ro.getHeaderName());
