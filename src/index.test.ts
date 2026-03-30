import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PluginInput } from '@opencode-ai/plugin';
import type { Part } from '@opencode-ai/sdk';
import { ContextSanitizer } from './index.ts';
import { _sanitize, resolveConfig } from './sanitizer.ts';

const TEST_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' +
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

function createPluginInput(logSpy = vi.fn()): PluginInput {
  return {
    client: {
      app: { log: logSpy },
    },
    project: {} as PluginInput['project'],
    directory: '/tmp',
    worktree: '/tmp',
    serverUrl: new URL('http://localhost:4096'),
    $: {} as PluginInput['$'],
  } as unknown as PluginInput;
}

describe('ContextSanitizer plugin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uses plugin config passed by OpenCode loader', async () => {
    const plugin = await ContextSanitizer(createPluginInput(), {
      enableJwtDetection: false,
    });

    const output = {
      message: {} as never,
      parts: [{ type: 'text', text: `Bearer ${TEST_JWT}` }] as Part[],
    };

    await plugin['chat.message']!({ sessionID: 'session-1' }, output);

    expect((output.parts[0] as { text: string }).text).toContain(TEST_JWT);
  });

  it('writes debug logs to the configured file and OpenCode logger', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'opencode-log-sanitizer-'));
    const debugLogFile = join(dir, 'opencode-log-sanitizer.debug.log');
    const logSpy = vi.fn().mockResolvedValue(undefined);

    try {
      const plugin = await ContextSanitizer(createPluginInput(logSpy), {
        debug: true,
        debugLogFile,
      });

      const output = {
        message: {} as never,
        parts: [{ type: 'text', text: `Bearer ${TEST_JWT}` }] as Part[],
      };

      await plugin['chat.message']!({ sessionID: 'session-2' }, output);

      const logText = await readFile(debugLogFile, 'utf8');

      expect(logText).toContain('plugin initialized');
      expect(logText).toContain('message sanitized');
      expect(logText).toContain('"jwt":1');
      expect(logSpy).toHaveBeenCalled();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('returns per-detector redaction counts', () => {
    const bcrypt = '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';
    const base64 = 'a'.repeat(299) + '+A==';
    const longString = '"' + 'x'.repeat(301) + '"';
    const input = `Bearer ${TEST_JWT}\n${bcrypt}\n${base64}\n${longString}`;

    const result = _sanitize(input, resolveConfig());

    expect(result.redactionCount).toBe(4);
    expect(result.redactions).toEqual({
      jwt: 1,
      bcrypt: 1,
      base64: 1,
      longString: 1,
    });
  });
});
