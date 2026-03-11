/**
 * opencode-context-sanitizer — core sanitization engine.
 *
 * All functions here are pure (no side-effects) and safe for large inputs.
 * Regex patterns are designed to avoid catastrophic backtracking.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SanitizerConfig {
  /**
   * Quoted strings longer than this threshold are redacted.
   * @default 300
   */
  maxStringLength: number;

  /** Detect and redact JWT tokens (eyJ...). @default true */
  enableJwtDetection: boolean;

  /** Detect and redact bcrypt hashes ($2a$, $2b$, $2y$). @default true */
  enableBcryptDetection: boolean;

  /**
   * Detect and redact base64 blobs longer than `maxStringLength` chars.
   * @default true
   */
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Merge user config with defaults, applying only the provided keys.
 */
export function resolveConfig(config?: Partial<SanitizerConfig>): SanitizerConfig {
  return { ...DEFAULT_CONFIG, ...config };
}

// ---------------------------------------------------------------------------
// Step 1 — no-redact block extraction
// ---------------------------------------------------------------------------

interface NoRedactBlock {
  placeholder: string;
  content: string;
}

/**
 * Finds all `<no-redact>…</no-redact>` blocks in `text`, replaces each with
 * a unique placeholder string, and returns the modified text + a list of
 * (placeholder, original-content) pairs for later restoration.
 */
export function extractNoRedactBlocks(text: string): {
  text: string;
  blocks: NoRedactBlock[];
} {
  const blocks: NoRedactBlock[] = [];
  // Use a non-greedy match; `[\s\S]*?` is safe because it stops at the first
  // closing tag — no catastrophic backtracking risk here.
  const pattern = /<no-redact>([\s\S]*?)<\/no-redact>/g;

  const result = text.replace(pattern, (match) => {
    const placeholder = `__NOREDACT_${blocks.length}__`;
    blocks.push({ placeholder, content: match });
    return placeholder;
  });

  return { text: result, blocks };
}

/**
 * Restores all `<no-redact>` blocks by replacing placeholders with their
 * original content.
 */
export function restoreNoRedactBlocks(text: string, blocks: NoRedactBlock[]): string {
  let result = text;
  for (const block of blocks) {
    result = result.replaceAll(block.placeholder, block.content);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Step 2 — JWT redaction
// ---------------------------------------------------------------------------

/**
 * JWT tokens always start with `eyJ` (base64-encoded `{"`) and consist of
 * three dot-separated base64url segments. The pattern is safe: each segment
 * uses a character class with `+` quantifier, bounded in practice by the
 * surrounding non-base64url characters.
 *
 * We look for the token both bare (in logs) and inside quotes.
 */
const JWT_PATTERN =
  /(?:"|'|^|[\s,:[{(])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:"|'|$|[\s,:\]})"])/gm;

/**
 * Simpler bare-form pattern used when the JWT is not quote-delimited.
 * This covers tokens pasted directly into logs without surrounding quotes.
 */
const JWT_BARE_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}\b/g;

export function redactJwt(text: string): { text: string; count: number } {
  let count = 0;

  // First pass: quoted-or-boundary-delimited tokens
  let result = text.replace(JWT_PATTERN, (match) => {
    count++;
    // Preserve the surrounding delimiter characters (quote, space, etc.)
    const leadChar = /^["'\s,:[{(]/.test(match) ? match[0] : '';
    const trailChar = /["'\s,:\]})]$/.test(match) ? match[match.length - 1] : '';
    return `${leadChar}redacted${trailChar}`;
  });

  // Second pass: remaining bare tokens not caught by the first pattern
  result = result.replace(JWT_BARE_PATTERN, (_match) => {
    // Skip if already redacted by a previous step
    if (_match === 'redacted') return _match;
    count++;
    return 'redacted';
  });

  return { text: result, count };
}

// ---------------------------------------------------------------------------
// Step 3 — bcrypt redaction
// ---------------------------------------------------------------------------

/**
 * bcrypt hashes follow the format: $2[aby]$<cost>$<53 chars of base64>.
 * Pattern: `$2a$10$...` — 60 characters total normally.
 * Using a fixed-length pattern at the end avoids backtracking.
 */
const BCRYPT_PATTERN = /\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}/g;

export function redactBcrypt(text: string): { text: string; count: number } {
  let count = 0;
  const result = text.replace(BCRYPT_PATTERN, () => {
    count++;
    return 'redacted';
  });
  return { text: result, count };
}

// ---------------------------------------------------------------------------
// Step 4 — base64 blob redaction
// ---------------------------------------------------------------------------

/**
 * Detect base64-encoded blobs that are longer than `minLength` characters.
 * We use `{minLength,}` which is safe — the engine will match greedily and
 * stop at the first non-base64 character. No catastrophic risk.
 *
 * We generate the pattern dynamically based on the configured threshold.
 */
function buildBase64Pattern(minLength: number): RegExp {
  // Build pattern: [A-Za-z0-9+/] chars followed by optional `=` padding.
  // We ensure the minimum length is `minLength` to avoid false positives on
  // short words that happen to be only alphanumeric.
  return new RegExp(`[A-Za-z0-9+/]{${minLength},}={0,2}`, 'g');
}

export function redactBase64(text: string, minLength: number): { text: string; count: number } {
  const pattern = buildBase64Pattern(minLength);
  let count = 0;
  const result = text.replace(pattern, () => {
    count++;
    return 'redacted';
  });
  return { text: result, count };
}

// ---------------------------------------------------------------------------
// Step 5 — long quoted-string redaction
// ---------------------------------------------------------------------------

/**
 * Scan through `text` character-by-character, identifying quoted string
 * literals (single or double quoted). If the content between quotes exceeds
 * `maxLength` characters, replace the entire `"..."` / `'...'` with
 * `"redacted"`.
 *
 * This approach avoids regex quantifiers on arbitrary-length content, so it
 * is immune to catastrophic backtracking even on 10k+ character inputs.
 *
 * Handles:
 * - Escaped quotes inside strings (`\"`, `\'`, `\\`)
 * - Multi-line strings
 */
export function redactLongStrings(
  text: string,
  maxLength: number
): { text: string; count: number } {
  const result: string[] = [];
  let i = 0;
  let count = 0;
  const len = text.length;

  while (i < len) {
    const ch = text[i];

    if (ch !== '"' && ch !== "'") {
      result.push(ch);
      i++;
      continue;
    }

    // We're at an opening quote. Walk forward to find the matching close.
    const openQuote = ch;
    let j = i + 1;
    let contentLength = 0;
    let closed = false;

    while (j < len) {
      const c = text[j];

      if (c === '\\') {
        // Escaped character — skip two chars
        j += 2;
        contentLength += 2;
        continue;
      }

      if (c === openQuote) {
        closed = true;
        j++; // move past the closing quote
        break;
      }

      contentLength++;
      j++;
    }

    if (!closed) {
      // Unterminated string — emit as-is and move on
      result.push(ch);
      i++;
      continue;
    }

    if (contentLength > maxLength) {
      // Redact: replace the whole quoted string with `"redacted"`
      result.push('"redacted"');
      count++;
    } else {
      // Keep as-is
      result.push(text.slice(i, j));
    }

    i = j;
  }

  return { text: result.join(''), count };
}

// ---------------------------------------------------------------------------
// Main pipeline
// ---------------------------------------------------------------------------

/**
 * Run the full sanitization pipeline on `text`:
 *
 * 1. Extract `<no-redact>` blocks → placeholders
 * 2. Redact JWTs
 * 3. Redact bcrypt hashes
 * 4. Redact long base64 blobs
 * 5. Redact long quoted strings
 * 6. Restore `<no-redact>` blocks
 */
export function sanitize(text: string, config?: Partial<SanitizerConfig>): SanitizeResult {
  if (!text || text.length === 0) return { text, redactionCount: 0 };

  const cfg = resolveConfig(config);
  let totalRedactions = 0;

  // Step 1: Extract bypass blocks
  const { text: extracted, blocks } = extractNoRedactBlocks(text);
  let current = extracted;

  // Step 2: JWT
  if (cfg.enableJwtDetection) {
    const { text: t, count } = redactJwt(current);
    current = t;
    totalRedactions += count;
  }

  // Step 3: bcrypt
  if (cfg.enableBcryptDetection) {
    const { text: t, count } = redactBcrypt(current);
    current = t;
    totalRedactions += count;
  }

  // Step 4: base64 blobs
  if (cfg.enableBase64Detection) {
    const { text: t, count } = redactBase64(current, cfg.maxStringLength);
    current = t;
    totalRedactions += count;
  }

  // Step 5: long quoted strings
  const { text: t, count } = redactLongStrings(current, cfg.maxStringLength);
  current = t;
  totalRedactions += count;

  // Step 6: Restore bypass blocks
  current = restoreNoRedactBlocks(current, blocks);

  return { text: current, redactionCount: totalRedactions };
}
