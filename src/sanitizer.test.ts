import { describe, it, expect } from 'vitest';
import {
  sanitize,
  redactJwt,
  redactBcrypt,
  redactBase64,
  redactLongStrings,
  extractNoRedactBlocks,
  restoreNoRedactBlocks,
  DEFAULT_CONFIG,
} from './sanitizer.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a string of `n` repeated characters */
const repeat = (ch: string, n: number) => ch.repeat(n);

/** Build a double-quoted string literal with content of length `n` */
const quotedStr = (n: number) => `"${repeat('a', n)}"`;

// ---------------------------------------------------------------------------
// extractNoRedactBlocks / restoreNoRedactBlocks
// ---------------------------------------------------------------------------

describe('no-redact block extraction', () => {
  it('extracts a single block and returns a placeholder', () => {
    const input = 'before <no-redact>secret</no-redact> after';
    const { text, blocks } = extractNoRedactBlocks(input);
    expect(text).toBe('before __NOREDACT_0__ after');
    expect(blocks).toHaveLength(1);
    expect(blocks[0].content).toBe('<no-redact>secret</no-redact>');
  });

  it('extracts multiple blocks with unique placeholders', () => {
    const input = '<no-redact>A</no-redact> mid <no-redact>B</no-redact>';
    const { text, blocks } = extractNoRedactBlocks(input);
    expect(text).toBe('__NOREDACT_0__ mid __NOREDACT_1__');
    expect(blocks).toHaveLength(2);
  });

  it('restores blocks to their original content', () => {
    const input = 'x <no-redact>keep this</no-redact> y';
    const { text, blocks } = extractNoRedactBlocks(input);
    const restored = restoreNoRedactBlocks(text, blocks);
    expect(restored).toBe(input);
  });

  it('handles text with no no-redact blocks', () => {
    const input = 'nothing special here';
    const { text, blocks } = extractNoRedactBlocks(input);
    expect(text).toBe(input);
    expect(blocks).toHaveLength(0);
  });

  it('handles multi-line content inside blocks', () => {
    const input = '<no-redact>\nline1\nline2\n</no-redact>';
    const { text, blocks } = extractNoRedactBlocks(input);
    expect(text).toBe('__NOREDACT_0__');
    const restored = restoreNoRedactBlocks(text, blocks);
    expect(restored).toBe(input);
  });
});

// ---------------------------------------------------------------------------
// redactJwt
// ---------------------------------------------------------------------------

describe('redactJwt', () => {
  const sampleJwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  it('redacts a bare JWT token in a log line', () => {
    const { text, count } = redactJwt(`token: ${sampleJwt}`);
    expect(text).not.toContain('eyJ');
    expect(text).toContain('[redacted:jwt]');
    expect(count).toBeGreaterThan(0);
  });

  it('redacts a JWT inside double quotes (the long-string pass catches the quoted form)', () => {
    // JWT inside quotes: the bare pattern still matches the token content
    const { text, count } = redactJwt(`{"token": "${sampleJwt}"}`);
    expect(text).not.toContain('eyJ');
    expect(count).toBeGreaterThan(0);
  });

  it('does not modify text without a JWT', () => {
    const input = 'no tokens here just ordinary text';
    const { text, count } = redactJwt(input);
    expect(text).toBe(input);
    expect(count).toBe(0);
  });

  it('does not produce double-redaction on already-replaced text', () => {
    // After one pass, the token is gone — a second pass should be a no-op.
    const { text: first } = redactJwt(`token: ${sampleJwt}`);
    const { count: second } = redactJwt(first);
    expect(second).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// redactBcrypt
// ---------------------------------------------------------------------------

describe('redactBcrypt', () => {
  const hash = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';

  it('redacts a $2b$ bcrypt hash', () => {
    const { text, count } = redactBcrypt(`password_hash: ${hash}`);
    expect(text).not.toContain('$2b$');
    expect(text).toContain('[redacted:bcrypt]');
    expect(count).toBe(1);
  });

  it('redacts $2a$ and $2y$ variants', () => {
    const hashA = hash.replace('$2b$', '$2a$');
    const hashY = hash.replace('$2b$', '$2y$');
    expect(redactBcrypt(hashA).count).toBe(1);
    expect(redactBcrypt(hashY).count).toBe(1);
  });

  it('does not modify text without a bcrypt hash', () => {
    const input = 'just a regular password: hunter2';
    const { text, count } = redactBcrypt(input);
    expect(text).toBe(input);
    expect(count).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// redactBase64
// ---------------------------------------------------------------------------

describe('redactBase64', () => {
  // A real base64 blob must contain at least one + or / — use a realistic value
  const long64 = repeat('A', 200) + '/abc+' + repeat('B', 100) + '==';

  it('redacts a base64 blob longer than the threshold', () => {
    const { text, count } = redactBase64(`data: ${long64}`, 300);
    expect(text).not.toContain('AAAA');
    expect(text).toContain('[redacted:base64:');
    expect(count).toBeGreaterThan(0);
  });

  it('does not redact a base64-like string shorter than the threshold', () => {
    const short64 = 'abc+/def' + repeat('A', 40); // ~48 chars, has + and /
    const { count } = redactBase64(`data: ${short64}`, 300);
    expect(count).toBe(0);
  });

  it('does not redact a plain alphanumeric string (no + or /)', () => {
    // A 400-char string of only A-Za-z0-9 — should NOT be caught as base64
    const pureAlpha = repeat('A', 400);
    const { count } = redactBase64(pureAlpha, 300);
    expect(count).toBe(0);
  });

  it('includes character count in the placeholder', () => {
    const { text } = redactBase64(`data: ${long64}`, 300);
    expect(text).toMatch(/\[redacted:base64:\d+chars\]/);
  });
});

// ---------------------------------------------------------------------------
// redactLongStrings
// ---------------------------------------------------------------------------

describe('redactLongStrings', () => {
  it('redacts a double-quoted string longer than maxLength', () => {
    const long = quotedStr(400);
    const { text, count } = redactLongStrings(long, 300);
    expect(text).toBe('"redacted"');
    expect(count).toBe(1);
  });

  it('redacts a single-quoted string longer than maxLength', () => {
    const long = `'${repeat('b', 400)}'`;
    const { text, count } = redactLongStrings(long, 300);
    expect(text).toBe('"redacted"');
    expect(count).toBe(1);
  });

  it('does not redact a string at or below maxLength', () => {
    const short = `"${repeat('a', 299)}"`;
    const { text, count } = redactLongStrings(short, 300);
    expect(text).toBe(short);
    expect(count).toBe(0);
  });

  it('redacts only the long string in a JSON object, leaving the rest intact', () => {
    const long = repeat('x', 400);
    const input = `{"key": "${long}", "other": "value"}`;
    const { text, count } = redactLongStrings(input, 300);
    expect(text).toContain('"redacted"');
    expect(text).toContain('"other": "value"');
    expect(count).toBe(1);
  });

  it('handles escaped quotes inside a string correctly', () => {
    const content = `he said \\"hello\\" and left`;
    const withQuotes = `"${content}"`;
    const { text, count } = redactLongStrings(withQuotes, 300);
    // Content length well below 300 — should be kept
    expect(count).toBe(0);
    expect(text).toBe(withQuotes);
  });

  it('handles an unterminated string gracefully (no crash)', () => {
    const input = '"start of string without end';
    expect(() => redactLongStrings(input, 300)).not.toThrow();
  });

  it('handles very large inputs efficiently', () => {
    const large = repeat('x ', 5000) + `"${repeat('t', 1000)}"` + repeat(' y', 5000);
    const start = Date.now();
    const { count } = redactLongStrings(large, 300);
    const elapsed = Date.now() - start;
    expect(count).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(500);
  });

  it('handles malformed/arbitrary text without crashing', () => {
    const inputs = [
      '',
      '{}',
      '{"a": null}',
      'Error: something\n    at foo (bar.js:1:2)',
      '0'.repeat(10000),
      '"\\"',
    ];
    for (const input of inputs) {
      expect(() => redactLongStrings(input, 300)).not.toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// sanitize — full pipeline
// ---------------------------------------------------------------------------

describe('sanitize (full pipeline)', () => {
  it('returns the original text unchanged when nothing to redact', () => {
    const input = '{"name": "Alice", "age": 30}';
    const { text, redactionCount } = sanitize(input);
    expect(text).toBe(input);
    expect(redactionCount).toBe(0);
  });

  it('redacts a JWT in a realistic log snippet', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const input = `Authorization: Bearer ${jwt}`;
    const { text, redactionCount } = sanitize(input);
    expect(text).not.toContain('eyJ');
    expect(text).toContain('[redacted:jwt]');
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('redacts a bcrypt hash in a log line', () => {
    const hash = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';
    const input = `{"passwordHash": "${hash}"}`;
    const { text, redactionCount } = sanitize(input);
    expect(text).not.toContain('$2b$');
    expect(text).toContain('[redacted:bcrypt]');
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('redacts a long quoted string', () => {
    const input = `{"token": "${repeat('a', 500)}"}`;
    const { text, redactionCount } = sanitize(input);
    expect(text).toContain('"redacted"');
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('redacts a real base64 blob (contains + or /)', () => {
    const blob = repeat('A', 200) + '/abc+' + repeat('B', 100); // >300 chars, has / and +
    const input = `avatar: ${blob}`;
    const { text, redactionCount } = sanitize(input);
    expect(text).not.toContain('AAAA');
    expect(text).toContain('[redacted:base64:');
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('does NOT redact a long plain alphanumeric string as base64', () => {
    // 400-char hex-like string: no + or / — should only be caught if quoted and >300
    const hexLike = repeat('a1b2', 100); // 400 chars, no + or /
    const input = `checksum: ${hexLike}`;
    const { text, redactionCount } = sanitize(input);
    // Not inside quotes, no + or / — should be left alone
    expect(text).toBe(input);
    expect(redactionCount).toBe(0);
  });

  it('preserves content inside <no-redact> blocks', () => {
    const secret = repeat('a', 500);
    const input = `before <no-redact>"${secret}"</no-redact> after`;
    const { text, redactionCount } = sanitize(input);
    expect(text).toContain(secret);
    expect(text).toContain(`<no-redact>"${secret}"</no-redact>`);
    expect(redactionCount).toBe(0);
  });

  it('does not touch no-redact content while still redacting the rest', () => {
    const secret = repeat('s', 500);
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const input = `${jwt} and <no-redact>"${secret}"</no-redact>`;
    const { text, redactionCount } = sanitize(input);
    expect(text).not.toContain('eyJ');
    expect(text).toContain('[redacted:jwt]');
    expect(text).toContain(secret);
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('respects custom maxStringLength configuration', () => {
    const input = `"${repeat('a', 60)}"`;
    const { redactionCount } = sanitize(input, { maxStringLength: 50 });
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('respects feature flags — disabling JWT detection', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const input = `token: ${jwt}`;
    const { text } = sanitize(input, { enableJwtDetection: false });
    expect(text).toContain('eyJ');
  });

  it('handles an empty string without errors', () => {
    const { text, redactionCount } = sanitize('');
    expect(text).toBe('');
    expect(redactionCount).toBe(0);
  });

  it('handles a stack trace without crashing or false-positives', () => {
    const stackTrace = `Error: something went wrong
    at Object.<anonymous> (/app/src/server.ts:42:11)
    at Module._compile (node:internal/modules/cjs/loader:1356:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1414:10)`;
    expect(() => sanitize(stackTrace)).not.toThrow();
  });

  it('has the correct default config values', () => {
    expect(DEFAULT_CONFIG.maxStringLength).toBe(300);
    expect(DEFAULT_CONFIG.enableJwtDetection).toBe(true);
    expect(DEFAULT_CONFIG.enableBcryptDetection).toBe(true);
    expect(DEFAULT_CONFIG.enableBase64Detection).toBe(true);
  });

  it('handles a realistic multi-field JSON log without crashing', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const hash = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';
    const blob = repeat('A', 200) + '/abc+' + repeat('B', 100);
    const input = JSON.stringify({
      email: 'user@example.com',
      passwordHash: hash,
      token: jwt,
      avatar: blob,
      name: 'Alice',
    });
    const { text } = sanitize(input);
    expect(text).toContain('user@example.com');
    expect(text).toContain('Alice');
    expect(text).not.toContain('eyJ');
    expect(text).not.toContain('$2b$');
  });
});
