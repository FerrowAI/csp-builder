import { createHash } from "crypto";

export const KEYWORDS = {
  self: "'self'",
  none: "'none'",
  unsafeInline: "'unsafe-inline'", // Documented as discouraged
  unsafeEval: "'unsafe-eval'",
  strictDynamic: "'strict-dynamic'",
  reportSample: "'report-sample'",
} as const;

type KeywordType = (typeof KEYWORDS)[keyof typeof KEYWORDS];

type DirectiveValue = string | KeywordType;

export interface CSPBuilderOptions {
  reportOnly?: boolean;
}

export class CSPBuilder {
  private directives: Map<string, Set<DirectiveValue>> = new Map();
  private reportOnly: boolean = false;

  constructor(options?: CSPBuilderOptions) {
    this.reportOnly = options?.reportOnly || false;
  }

  private addDirective(name: string, value: DirectiveValue): this {
    if (!this.directives.has(name)) {
      this.directives.set(name, new Set());
    }
    this.directives.get(name)!.add(value);
    return this;
  }

  defaultSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("default-src", v));
    return this;
  }

  scriptSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("script-src", v));
    return this;
  }

  styleSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("style-src", v));
    return this;
  }

  imgSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("img-src", v));
    return this;
  }

  fontSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("font-src", v));
    return this;
  }

  connectSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("connect-src", v));
    return this;
  }

  mediaSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("media-src", v));
    return this;
  }

  objectSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("object-src", v));
    return this;
  }

  childSrc(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("child-src", v));
    return this;
  }

  formAction(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("form-action", v));
    return this;
  }

  frameAncestors(...values: DirectiveValue[]): this {
    values.forEach((v) => this.addDirective("frame-ancestors", v));
    return this;
  }

  reportUri(uri: string): this {
    this.directives.set("report-uri", new Set([uri]));
    return this;
  }

  reportTo(group: string): this {
    this.directives.set("report-to", new Set([group]));
    return this;
  }

  upgradeInsecureRequests(): this {
    this.directives.set("upgrade-insecure-requests", new Set([""]));
    return this;
  }

  blockAllMixedContent(): this {
    this.directives.set("block-all-mixed-content", new Set([""]));
    return this;
  }

  generateNonce(): string {
    const bytes = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes.toString("base64");
  }

  nonce(value: string): string {
    return `'nonce-${value}'`;
  }

  hash(content: string, algorithm: "sha256" | "sha384" | "sha512" = "sha256"): string {
    const digest = createHash(algorithm).update(content).digest("base64");
    return `'${algorithm}-${digest}'`;
  }

  toString(): string {
    const parts: string[] = [];

    // Sort directives for consistent output
    const sortedDirs = Array.from(this.directives.entries()).sort((a, b) =>
      a[0].localeCompare(b[0])
    );

    for (const [name, values] of sortedDirs) {
      const valueStr = Array.from(values).join(" ").trim();
      parts.push(`${name}${valueStr ? " " + valueStr : ""}`);
    }

    return parts.join("; ");
  }

  toMeta(): string {
    const parts: string[] = [];
    const sortedDirs = Array.from(this.directives.entries()).sort((a, b) =>
      a[0].localeCompare(b[0])
    );

    let hasFrameAncestors = false;

    for (const [name, values] of sortedDirs) {
      if (name === "frame-ancestors") {
        hasFrameAncestors = true;
        continue; // Skip frame-ancestors in meta tag
      }

      const valueStr = Array.from(values).join(" ").trim();
      parts.push(`${name}${valueStr ? " " + valueStr : ""}`);
    }

    if (hasFrameAncestors) {
      console.warn(
        "CSPBuilder: frame-ancestors directive ignored in meta tag (not supported)"
      );
    }

    return parts.join("; ");
  }

  setReportOnly(reportOnly: boolean): this {
    this.reportOnly = reportOnly;
    return this;
  }

  getHeaderName(): string {
    return this.reportOnly
      ? "Content-Security-Policy-Report-Only"
      : "Content-Security-Policy";
  }

  static parse(headerValue: string): CSPBuilder {
    const builder = new CSPBuilder();
    const directives = headerValue.split(";").map((d) => d.trim());

    for (const directive of directives) {
      if (!directive) continue;

      const parts = directive.split(/\s+/);
      const name = parts[0];
      const values = parts.slice(1);

      if (!builder.directives.has(name)) {
        builder.directives.set(name, new Set());
      }

      values.forEach((v) => {
        builder.directives.get(name)!.add(v as DirectiveValue);
      });
    }

    return builder;
  }
}

export default CSPBuilder;
