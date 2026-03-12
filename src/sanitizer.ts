/**
 * opencode-context-sanitizer — core sanitization engine.
 *
 * All functions are pure (no side-effects) and safe for large inputs.
 * Regex patterns are designed to avoid catastrophic backtracking.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SanitizerConfig {
  /** Quoted strings / base64 blobs longer than this are redacted. @default 300 */
  maxStringLength: number;
  /** Detect and redact JWT tokens (eyJ…). @default true */
  enableJwtDetection: boolean;
  /** Detect and redact bcrypt hashes ($2a$/$2b$/$2y$). @default true */
  enableBcryptDetection: boolean;
  /** Detect and redact base64 blobs longer than `maxStringLength`. @default true */
  enableBase64Detection: boolean;
}

export const DEFAULT_CONFIG: SanitizerConfig = {
  maxStringLength: 300,
  enableJwtDetection: true,
  enableBcryptDetection: true,
  enableBase64Detection: true,
};

export interface SanitizeResult {
  text: string;
  redactionCount: number;
}

export function resolveConfig(config?: Partial<SanitizerConfig>): SanitizerConfig {
  if (!config) return DEFAULT_CONFIG;
  return { ...DEFAULT_CONFIG, ...config };
}

// ---------------------------------------------------------------------------
// Pre-compiled patterns (module-level — compiled once, reused forever)
// ---------------------------------------------------------------------------

/**
 * JWT: three dot-separated base64url segments, first starting with `eyJ`.
 * `\b` word-boundaries prevent re-matching already-redacted placeholders.
 */
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

/**
 * bcrypt: fixed-length format — no variable quantifiers, no backtracking risk.
 * Total hash length is always 60 chars.
 */
const BCRYPT_PATTERN = /\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}/g;

/**
 * Base64 blob at the default threshold (300 chars).
 * Lookahead ensures at least one `+` or `/` — distinguishes real base64
 * from hex strings, UUIDs, and long alphanumeric identifiers.
 *
 * A second pattern is built lazily if the caller uses a non-default threshold.
 */
const BASE64_PATTERN_300 = /(?=[A-Za-z0-9+/]*[+/])[A-Za-z0-9+/]{300,}={0,2}/g;

// Cache for non-default thresholds (rare in practice).
const base64PatternCache = new Map<number, RegExp>();

function getBase64Pattern(minLength: number): RegExp {
  if (minLength === 300) return BASE64_PATTERN_300;
  let pattern = base64PatternCache.get(minLength);
  if (!pattern) {
    pattern = new RegExp(`(?=[A-Za-z0-9+/]*[+/])[A-Za-z0-9+/]{${minLength},}={0,2}`, 'g');
    base64PatternCache.set(minLength, pattern);
  }
  return pattern;
}

/** Fast check: is `<no-redact>` present at all? Avoids regex overhead on most inputs. */
const NO_REDACT_OPEN = '<no-redact>';

// ---------------------------------------------------------------------------
// Step 1 — no-redact block extraction
// ---------------------------------------------------------------------------

interface NoRedactBlock {
  placeholder: string;
  content: string;
}

const NO_REDACT_PATTERN = /<no-redact>([\s\S]*?)<\/no-redact>/g;

export function extractNoRedactBlocks(text: string): { text: string; blocks: NoRedactBlock[] } {
  const blocks: NoRedactBlock[] = [];
  const result = text.replace(NO_REDACT_PATTERN, (match) => {
    const placeholder = `__NR${blocks.length}__`;
    blocks.push({ placeholder, content: match });
    return placeholder;
  });
  return { text: result, blocks };
}

export function restoreNoRedactBlocks(text: string, blocks: NoRedactBlock[]): string {
  if (blocks.length === 0) return text;
  // Build a single-pass replacement map instead of N full-string scans.
  const map: Record<string, string> = {};
  for (const b of blocks) map[b.placeholder] = b.content;
  return text.replace(/__NR\d+__/g, (ph) => map[ph] ?? ph);
}

// ---------------------------------------------------------------------------
// Step 2 — JWT redaction
// ---------------------------------------------------------------------------

export function redactJwt(text: string): { text: string; count: number } {
  let count = 0;
  // Reset lastIndex before each use — patterns are module-level with /g flag.
  JWT_PATTERN.lastIndex = 0;
  const result = text.replace(JWT_PATTERN, () => {
    count++;
    return '[redacted:jwt]';
  });
  return { text: result, count };
}

// ---------------------------------------------------------------------------
// Step 3 — bcrypt redaction
// ---------------------------------------------------------------------------

export function redactBcrypt(text: string): { text: string; count: number } {
  let count = 0;
  BCRYPT_PATTERN.lastIndex = 0;
  const result = text.replace(BCRYPT_PATTERN, () => {
    count++;
    return '[redacted:bcrypt]';
  });
  return { text: result, count };
}

// ---------------------------------------------------------------------------
// Step 4 — base64 blob redaction
// ---------------------------------------------------------------------------

export function redactBase64(text: string, minLength: number): { text: string; count: number } {
  const pattern = getBase64Pattern(minLength);
  pattern.lastIndex = 0;
  let count = 0;
  const result = text.replace(pattern, (match) => {
    count++;
    return `[redacted:base64:${match.length}chars]`;
  });
  return { text: result, count };
}

// ---------------------------------------------------------------------------
// Step 5 — long quoted-string redaction  (linear scan, no regex)
// ---------------------------------------------------------------------------

/**
 * Scan through `text` identifying single/double-quoted string literals.
 * Strings whose content exceeds `maxLength` chars are replaced with `"redacted"`.
 *
 * Uses a linear scan with slice-range accumulation — O(n), no per-char push.
 * Handles: escaped quotes, multi-line strings, unterminated strings (kept as-is).
 */
export function redactLongStrings(
  text: string,
  maxLength: number
): { text: string; count: number } {
  const parts: string[] = [];
  let i = 0;
  let segStart = 0; // start of current unmodified run
  let count = 0;
  const len = text.length;

  while (i < len) {
    const ch = text[i];

    if (ch !== '"' && ch !== "'") {
      i++;
      continue;
    }

    const openQuote = ch;
    let j = i + 1;
    let contentLength = 0;
    let closed = false;

    while (j < len) {
      const c = text[j];
      if (c === '\\') {
        j += 2;
        contentLength += 2;
        continue;
      }
      if (c === openQuote) {
        closed = true;
        j++;
        break;
      }
      contentLength++;
      j++;
    }

    if (!closed) {
      i++;
      continue;
    }

    if (contentLength > maxLength) {
      // Flush the unmodified run up to this quote, then push the redaction.
      parts.push(text.slice(segStart, i));
      parts.push('"redacted"');
      count++;
      i = j;
      segStart = j;
    } else {
      i = j;
    }
  }

  // Flush any remaining unmodified tail.
  if (segStart < len) parts.push(text.slice(segStart));

  return { text: parts.join(''), count };
}

// ---------------------------------------------------------------------------
// Main pipeline
// ---------------------------------------------------------------------------

/**
 * Run the full sanitization pipeline on `text`:
 *
 * 1. Extract `<no-redact>` blocks        → placeholders
 * 2. Redact JWT tokens                   → `[redacted:jwt]`
 * 3. Redact bcrypt hashes                → `[redacted:bcrypt]`
 * 4. Redact long base64 blobs            → `[redacted:base64:Nchars]`
 * 5. Redact long quoted strings          → `"redacted"`
 * 6. Restore `<no-redact>` blocks
 *
 * Accepts a pre-resolved `SanitizerConfig` (pass `resolveConfig(partial)` once
 * at plugin init) or a raw partial config (resolved internally — slightly slower).
 */
export function sanitize(
  text: string,
  config?: Partial<SanitizerConfig> | SanitizerConfig
): SanitizeResult {
  if (!text) return { text, redactionCount: 0 };

  const cfg = resolveConfig(config);
  let totalRedactions = 0;

  // Fast-path: skip no-redact machinery when the marker is absent.
  const hasNoRedact = text.includes(NO_REDACT_OPEN);
  let current = text;
  let blocks: NoRedactBlock[] = [];

  if (hasNoRedact) {
    const extracted = extractNoRedactBlocks(text);
    current = extracted.text;
    blocks = extracted.blocks;
  }

  if (cfg.enableJwtDetection) {
    const { text: t, count } = redactJwt(current);
    current = t;
    totalRedactions += count;
  }

  if (cfg.enableBcryptDetection) {
    const { text: t, count } = redactBcrypt(current);
    current = t;
    totalRedactions += count;
  }

  if (cfg.enableBase64Detection) {
    const { text: t, count } = redactBase64(current, cfg.maxStringLength);
    current = t;
    totalRedactions += count;
  }

  const { text: t5, count: c5 } = redactLongStrings(current, cfg.maxStringLength);
  current = t5;
  totalRedactions += c5;

  if (hasNoRedact) {
    current = restoreNoRedactBlocks(current, blocks);
  }

  return { text: current, redactionCount: totalRedactions };
}
