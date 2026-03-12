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
 *
 * Pattern uses a non-greedy `[\s\S]*?` which stops at the first closing tag —
 * no catastrophic backtracking risk.
 */
export function extractNoRedactBlocks(text: string): {
  text: string;
  blocks: NoRedactBlock[];
} {
  const blocks: NoRedactBlock[] = [];
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
 * JWT tokens always begin with `eyJ` (base64url-encoded `{"`).
 * They consist of exactly three dot-separated base64url segments.
 *
 * The pattern uses `\b` word boundaries to avoid matching already-redacted
 * placeholder text (e.g. "redacted" written by a previous pass).
 *
 * Each segment allows `[A-Za-z0-9_-]+` — the standard base64url alphabet —
 * with a minimum length of 10 on each part to avoid false positives on short
 * identifiers that happen to start with `eyJ`.
 */
const JWT_BARE_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

export function redactJwt(text: string): { text: string; count: number } {
  let count = 0;

  const result = text.replace(JWT_BARE_PATTERN, (match) => {
    // Skip tokens that are already inside a redaction placeholder produced
    // by an earlier pattern (shouldn't happen in normal flow, but be safe).
    if (match === 'redacted') return match;
    count++;
    return '[redacted:jwt]';
  });

  return { text: result, count };
}

// ---------------------------------------------------------------------------
// Step 3 — bcrypt redaction
// ---------------------------------------------------------------------------

/**
 * bcrypt hashes follow the format: $2[aby]$<cost>$<53 chars of base64>.
 * Total length is always exactly 60 characters.
 * Using a fixed-length terminal segment `{53}` eliminates any backtracking risk.
 */
const BCRYPT_PATTERN = /\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}/g;

export function redactBcrypt(text: string): { text: string; count: number } {
  let count = 0;
  const result = text.replace(BCRYPT_PATTERN, () => {
    count++;
    return '[redacted:bcrypt]';
  });
  return { text: result, count };
}

// ---------------------------------------------------------------------------
// Step 4 — base64 blob redaction
// ---------------------------------------------------------------------------

/**
 * Detect base64-encoded blobs that are longer than `minLength` characters.
 *
 * Criteria for a "real" base64 blob (vs. a long alphanumeric identifier):
 *   - Uses the standard base64 alphabet: A-Z, a-z, 0-9, +, /
 *   - Optionally ends with `=` or `==` padding
 *   - Must contain at least one `/` or `+` character, or the string must be
 *     entirely uppercase/lowercase (not a mix of camelCase words)
 *
 * This is intentionally conservative to avoid false-positives on things like
 * long hex strings or normal prose. The long-quoted-string pass (step 5)
 * handles the "everything else" case for quoted values.
 *
 * Pattern breakdown:
 *   - At least `minLength` characters of the base64 alphabet
 *   - Must contain at least one `+` or `/` to distinguish from hex/alphanumeric
 *   - Optionally followed by `=` padding
 */
function buildBase64Pattern(minLength: number): RegExp {
  // We match sequences that:
  //   1. Contain at least one `+` or `/` (i.e. real base64, not just hex or alphanum)
  //   2. Are at least minLength chars long
  //   3. End with optional `==?` padding
  //
  // The look-ahead/look-behind approach:
  //   (?=[A-Za-z0-9+/]*[+/])   — lookahead: the match contains at least one +/
  //   [A-Za-z0-9+/]{minLen,}   — the body
  //   ={0,2}                   — optional padding
  return new RegExp(`(?=[A-Za-z0-9+/]*[+/])[A-Za-z0-9+/]{${minLength},}={0,2}`, 'g');
}

export function redactBase64(text: string, minLength: number): { text: string; count: number } {
  const pattern = buildBase64Pattern(minLength);
  let count = 0;
  const result = text.replace(pattern, (match) => {
    count++;
    return `[redacted:base64:${match.length}chars]`;
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
 * This linear scan avoids regex quantifiers on arbitrary-length content,
 * making it immune to catastrophic backtracking on 10k+ character inputs.
 *
 * Handles:
 * - Escaped quotes inside strings (`\"`, `\'`, `\\`)
 * - Multi-line strings
 * - Unterminated strings (emitted unchanged, no crash)
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
        // Escaped character — skip both the backslash and the next char
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
      // Unterminated string — emit the opening quote as-is and advance
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
 * 1. Extract `<no-redact>` blocks → replace with placeholders
 * 2. Redact JWT tokens          → `[redacted:jwt]`
 * 3. Redact bcrypt hashes       → `[redacted:bcrypt]`
 * 4. Redact long base64 blobs   → `[redacted:base64:Nchars]`
 * 5. Redact long quoted strings → `"redacted"`
 * 6. Restore `<no-redact>` blocks
 *
 * The pipeline never throws on malformed input; every step is defensive.
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

  // Step 4: base64 blobs (only real base64 — must contain + or /)
  if (cfg.enableBase64Detection) {
    const { text: t, count } = redactBase64(current, cfg.maxStringLength);
    current = t;
    totalRedactions += count;
  }

  // Step 5: long quoted strings
  const { text: t5, count: c5 } = redactLongStrings(current, cfg.maxStringLength);
  current = t5;
  totalRedactions += c5;

  // Step 6: Restore bypass blocks
  current = restoreNoRedactBlocks(current, blocks);

  return { text: current, redactionCount: totalRedactions };
}
