/**
 * End-to-end test: verifies that the opencode-log-sanitizer plugin actually
 * intercepts and redacts prompt content before it is stored / forwarded to the
 * LLM.
 *
 * Strategy
 * --------
 * 1. Start a real OpenCode server via `createOpencode` with the plugin enabled.
 * 2. Create a session (no real LLM model needed — we set `noReply: true`).
 * 3. POST a user message containing a JWT, a bcrypt hash, and a base64 blob.
 * 4. Read back the stored TextPart for that message.
 * 5. Assert the stored text contains the redaction placeholders instead of the
 *    original values.
 *
 * `noReply: true` means OpenCode stores the user message and fires all hooks
 * (including `chat.message`) but does NOT call the LLM provider, so no real
 * API key is required.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createOpencode, type Part } from '@opencode-ai/sdk';
import path from 'node:path';

// ---------------------------------------------------------------------------
// Fixtures — values that must be redacted
// ---------------------------------------------------------------------------

const TEST_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' +
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

const TEST_BCRYPT = '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

// Single 416-char base64 blob (contains + and /) — long enough to trigger the 300-char threshold.
const TEST_BASE64 =
  'iMMKXum4SfgFkTd3ryFWB2qn5iIB9g3m9X4sROOO+rn3G0+if0PHTko0gjK6VkTVDO+IuLTr3mNrp1SI7XEcBm/traKoslmcL1ycmF6hFDnui9WgiBH1' +
  'jKhjEduz14V7+cBzP6PmYIzq7uV8I549ufWmpe/O7YjVWwRuKXkm7XQsmGOaEu43LBrLAgmtXtbnWWqtffR/k+ZBNdO2oRMJyjxU/671itgO+nNkOGLX' +
  'uXryNZM+Eu4+9IEo0+KiXLygGxH4z/IZrrs5nMiivp2m7UzIPGQc4aBrNrGtkNB+1Gfv00TjATKp/Iyyraf/j8xv3khN2vz2CpwtD35RXDQdNKOEezD' +
  'QPrsopod2NoOQb9PcnJmx8+HwkdDRFuFfJqz5lwVrOgI88fIjArqy78K4azajuN6m0Q==';

// Prompt text that embeds all three
const DIRTY_PROMPT = [
  'Here is some debug output.',
  `Authorization: Bearer ${TEST_JWT}`,
  `Password hash: ${TEST_BCRYPT}`,
  `Image data: ${TEST_BASE64}`,
  'End of debug.',
].join('\n');

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

let server: Awaited<ReturnType<typeof createOpencode>>['server'] | null = null;
let client: Awaited<ReturnType<typeof createOpencode>>['client'] | null = null;

const PLUGIN_PATH = path.resolve(
  process.env.HOME ?? '/root',
  '.config/opencode/plugins/opencode-log-sanitizer.js'
);

beforeAll(async () => {
  const result = await createOpencode({
    timeout: 30_000,
    config: {
      // Point at the deployed self-contained plugin file.
      plugin: [PLUGIN_PATH],
      // Disable all real providers so noReply sessions work without credentials.
      disabled_providers: ['anthropic', 'openai', 'google', 'bedrock', 'azure'],
    },
  });

  server = result.server;
  client = result.client;
}, 35_000);

afterAll(() => {
  server?.close();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('opencode-context-sanitizer plugin (e2e)', () => {
  it('redacts JWT, bcrypt hash, and base64 blob from a stored user message', async () => {
    // Create a throwaway session
    const sessionResp = await client!.session.create({
      query: { directory: '/tmp' },
    });
    expect(sessionResp.data?.id, 'session should be created').toBeTruthy();
    const sessionID = sessionResp.data!.id;

    // Send the dirty prompt — noReply so no LLM call is made
    await client!.session.prompt({
      path: { id: sessionID },
      query: { directory: '/tmp' },
      body: {
        noReply: true,
        parts: [{ type: 'text', text: DIRTY_PROMPT }],
      },
    });

    // Read back the stored messages for this session
    const messagesResp = await client!.session.messages({
      path: { id: sessionID },
      query: { directory: '/tmp' },
    });

    const messages = messagesResp.data ?? [];

    // Find user message entries — each entry is { info: Message, parts: Part[] }
    const userEntries = messages.filter(
      (entry: { info: { role: string }; parts: Part[] }) => entry.info.role === 'user'
    );
    expect(userEntries.length, 'should have at least one user message').toBeGreaterThan(0);

    // Collect all text parts from user messages
    const allText = userEntries
      .flatMap((entry: { info: { role: string }; parts: Part[] }) => entry.parts)
      .filter((part: Part) => part.type === 'text')
      .map((part: Part) => (part as { type: 'text'; text: string }).text)
      .join('');

    // The stored text must NOT contain the original sensitive values
    expect(allText, 'JWT should be redacted').not.toContain(TEST_JWT);
    expect(allText, 'bcrypt hash should be redacted').not.toContain(TEST_BCRYPT);
    // base64 — check a unique substring of it
    expect(allText, 'base64 blob should be redacted').not.toContain('iVBORw0KGgo');

    // And SHOULD contain the placeholder tokens
    expect(allText, 'should have jwt placeholder').toContain('[redacted:jwt]');
    expect(allText, 'should have bcrypt placeholder').toContain('[redacted:bcrypt]');
    expect(allText, 'should have base64 placeholder').toContain('[redacted:base64:');
  });
});
