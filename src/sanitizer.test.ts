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

const repeat = (ch: string, n: number) => ch.repeat(n);
const quotedStr = (n: number) => `"${repeat('a', n)}"`;

describe('no-redact block extraction', () => {
  it('extracts a single block and returns a placeholder', () => {
    const input = 'before <no-redact>secret</no-redact> after';
    const { text, blocks } = extractNoRedactBlocks(input);
    expect(text).toBe('before __NR0__ after');
    expect(blocks).toHaveLength(1);
    expect(blocks[0].content).toBe('<no-redact>secret</no-redact>');
  });

  it('extracts multiple blocks with unique placeholders', () => {
    const input = '<no-redact>A</no-redact> mid <no-redact>B</no-redact>';
    const { text, blocks } = extractNoRedactBlocks(input);
    expect(text).toBe('__NR0__ mid __NR1__');
    expect(blocks).toHaveLength(2);
  });

  it('restores blocks to their original content', () => {
    const input = 'x <no-redact>keep this</no-redact> y';
    const { text, blocks } = extractNoRedactBlocks(input);
    expect(restoreNoRedactBlocks(text, blocks)).toBe(input);
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
    expect(text).toBe('__NR0__');
    expect(restoreNoRedactBlocks(text, blocks)).toBe(input);
  });
});

describe('redactJwt', () => {
  const sampleJwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  it('redacts a bare JWT token', () => {
    const { text, count } = redactJwt(`token: ${sampleJwt}`);
    expect(text).not.toContain('eyJ');
    expect(text).toContain('[redacted:jwt]');
    expect(count).toBeGreaterThan(0);
  });

  it('redacts a JWT inside double quotes', () => {
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

  it('does not double-redact already-replaced text', () => {
    const { text: first } = redactJwt(`token: ${sampleJwt}`);
    const { count: second } = redactJwt(first);
    expect(second).toBe(0);
  });
});

describe('redactBcrypt', () => {
  const hash = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';

  it('redacts a $2b$ bcrypt hash', () => {
    const { text, count } = redactBcrypt(`password_hash: ${hash}`);
    expect(text).not.toContain('$2b$');
    expect(text).toContain('[redacted:bcrypt]');
    expect(count).toBe(1);
  });

  it('redacts $2a$ and $2y$ variants', () => {
    expect(redactBcrypt(hash.replace('$2b$', '$2a$')).count).toBe(1);
    expect(redactBcrypt(hash.replace('$2b$', '$2y$')).count).toBe(1);
  });

  it('does not modify text without a bcrypt hash', () => {
    const input = 'just a regular password: hunter2';
    const { text, count } = redactBcrypt(input);
    expect(text).toBe(input);
    expect(count).toBe(0);
  });
});

describe('redactBase64', () => {
  const long64 = repeat('A', 200) + '/abc+' + repeat('B', 100) + '==';

  it('redacts a base64 blob longer than the threshold', () => {
    const { text, count } = redactBase64(`data: ${long64}`, 300);
    expect(text).not.toContain('AAAA');
    expect(text).toContain('[redacted:base64:');
    expect(count).toBeGreaterThan(0);
  });

  it('does not redact a base64-like string shorter than the threshold', () => {
    const short64 = 'abc+/def' + repeat('A', 40);
    expect(redactBase64(`data: ${short64}`, 300).count).toBe(0);
  });

  it('does not redact a plain alphanumeric string (no + or /)', () => {
    expect(redactBase64(repeat('A', 400), 300).count).toBe(0);
  });

  it('includes character count in the placeholder', () => {
    const { text } = redactBase64(`data: ${long64}`, 300);
    expect(text).toMatch(/\[redacted:base64:\d+chars\]/);
  });
});

describe('redactLongStrings', () => {
  it('redacts a double-quoted string longer than maxLength', () => {
    const { text, count } = redactLongStrings(quotedStr(400), 300);
    expect(text).toBe('"redacted"');
    expect(count).toBe(1);
  });

  it('redacts a single-quoted string longer than maxLength', () => {
    const { text, count } = redactLongStrings(`'${repeat('b', 400)}'`, 300);
    expect(text).toBe('"redacted"');
    expect(count).toBe(1);
  });

  it('does not redact a string at or below maxLength', () => {
    const short = `"${repeat('a', 299)}"`;
    const { text, count } = redactLongStrings(short, 300);
    expect(text).toBe(short);
    expect(count).toBe(0);
  });

  it('redacts only the long string in a JSON object', () => {
    const input = `{"key": "${repeat('x', 400)}", "other": "value"}`;
    const { text, count } = redactLongStrings(input, 300);
    expect(text).toContain('"redacted"');
    expect(text).toContain('"other": "value"');
    expect(count).toBe(1);
  });

  it('does not redact a long HTML class attribute value', () => {
    const classList = repeat('btn-primary ', 40).trim();
    const input = `<div class="${classList}">content</div>`;
    const { text, count } = redactLongStrings(input, 300);
    expect(text).toBe(input);
    expect(count).toBe(0);
  });

  it('does not redact a long JSX className attribute value', () => {
    const classList = repeat('md:grid-cols-12 ', 30).trim();
    const input = `<div className="${classList}">content</div>`;
    const { text, count } = redactLongStrings(input, 300);
    expect(text).toBe(input);
    expect(count).toBe(0);
  });

  it('still redacts long non-class HTML attribute values', () => {
    const input = `<div data-token="${repeat('x', 400)}">content</div>`;
    const { text, count } = redactLongStrings(input, 300);
    expect(text).toContain('"redacted"');
    expect(count).toBe(1);
  });

  it('handles escaped quotes inside a string correctly', () => {
    const withQuotes = `"he said \\"hello\\" and left"`;
    const { text, count } = redactLongStrings(withQuotes, 300);
    expect(count).toBe(0);
    expect(text).toBe(withQuotes);
  });

  it('counts each escape sequence as 1 logical char, not 2', () => {
    const plain299 = repeat('a', 299);
    // 299 plain chars + one \n escape = 300 logical → at limit, NOT redacted
    const atLimit = '"' + plain299 + '\\n"';
    expect(redactLongStrings(atLimit, 300).count).toBe(0);
    // 300 plain chars + one \n escape = 301 logical → over limit, must redact
    const overLimit = '"' + plain299 + 'x\\n"';
    expect(redactLongStrings(overLimit, 300).count).toBe(1);
  });

  it('handles an unterminated string gracefully', () => {
    expect(() => redactLongStrings('"start of string without end', 300)).not.toThrow();
  });

  it('handles very large inputs efficiently', () => {
    const large = repeat('x ', 5000) + `"${repeat('t', 1000)}"` + repeat(' y', 5000);
    const start = Date.now();
    const { count } = redactLongStrings(large, 300);
    expect(count).toBeGreaterThan(0);
    expect(Date.now() - start).toBeLessThan(500);
  });

  it('handles malformed/arbitrary text without crashing', () => {
    for (const input of [
      '',
      '{}',
      '{"a": null}',
      'Error: x\n  at foo.js:1:2',
      '0'.repeat(10000),
      '"\\"',
    ]) {
      expect(() => redactLongStrings(input, 300)).not.toThrow();
    }
  });
});

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
    const { text, redactionCount } = sanitize(`Authorization: Bearer ${jwt}`);
    expect(text).not.toContain('eyJ');
    expect(text).toContain('[redacted:jwt]');
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('redacts a bcrypt hash in a log line', () => {
    const hash = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';
    const { text, redactionCount } = sanitize(`{"passwordHash": "${hash}"}`);
    expect(text).not.toContain('$2b$');
    expect(text).toContain('[redacted:bcrypt]');
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('redacts a long quoted string', () => {
    const { text, redactionCount } = sanitize(`{"token": "${repeat('a', 500)}"}`);
    expect(text).toContain('"redacted"');
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('preserves long HTML class attributes in the full pipeline', () => {
    const classList = repeat('inline-flex items-center justify-center ', 12).trim();
    const input = `<button class="${classList}">Click me</button>`;
    const { text, redactionCount } = sanitize(input);
    expect(text).toBe(input);
    expect(redactionCount).toBe(0);
  });

  it('redacts a real base64 blob (contains + or /)', () => {
    const blob = repeat('A', 200) + '/abc+' + repeat('B', 100);
    const { text, redactionCount } = sanitize(`avatar: ${blob}`);
    expect(text).not.toContain('AAAA');
    expect(text).toContain('[redacted:base64:');
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('does not redact a long plain alphanumeric string as base64', () => {
    const input = `checksum: ${repeat('a1b2', 100)}`;
    const { text, redactionCount } = sanitize(input);
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

  it('redacts outside no-redact blocks while preserving their content', () => {
    const secret = repeat('s', 500);
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const { text, redactionCount } = sanitize(`${jwt} and <no-redact>"${secret}"</no-redact>`);
    expect(text).not.toContain('eyJ');
    expect(text).toContain('[redacted:jwt]');
    expect(text).toContain(secret);
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('respects custom maxStringLength', () => {
    const { redactionCount } = sanitize(`"${repeat('a', 60)}"`, { maxStringLength: 50 });
    expect(redactionCount).toBeGreaterThan(0);
  });

  it('respects feature flags — disabling JWT detection', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const { text } = sanitize(`token: ${jwt}`, { enableJwtDetection: false });
    expect(text).toContain('eyJ');
  });

  it('handles an empty string', () => {
    const { text, redactionCount } = sanitize('');
    expect(text).toBe('');
    expect(redactionCount).toBe(0);
  });

  it('handles a stack trace without false-positives', () => {
    const stackTrace = `Error: something went wrong
    at Object.<anonymous> (/app/src/server.ts:42:11)
    at Module._compile (node:internal/modules/cjs/loader:1356:14)`;
    expect(() => sanitize(stackTrace)).not.toThrow();
  });

  it('has correct default config values', () => {
    expect(DEFAULT_CONFIG.maxStringLength).toBe(300);
    expect(DEFAULT_CONFIG.enableJwtDetection).toBe(true);
    expect(DEFAULT_CONFIG.enableBcryptDetection).toBe(true);
    expect(DEFAULT_CONFIG.enableBase64Detection).toBe(true);
  });

  it('handles a realistic multi-field JSON log', () => {
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
