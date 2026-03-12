import type { Plugin } from '@opencode-ai/plugin';
import type { Part } from '@opencode-ai/sdk';
import { sanitize, resolveConfig, type SanitizerConfig } from './sanitizer.js';

/**
 * ContextSanitizer — OpenCode plugin that redacts long/machine-generated values
 * (JWTs, bcrypt hashes, base64 blobs, long quoted strings) from user messages
 * before they are forwarded to the LLM.
 *
 * Configuration (all optional, shown with defaults):
 *   { "plugin": [["opencode-log-sanitizer", { "maxStringLength": 300 }]] }
 */
export const ContextSanitizer = (config?: Partial<SanitizerConfig>): Plugin => {
  // Resolve config once at plugin-init time, not on every message.
  const cfg = resolveConfig(config);

  return async () => ({
    'chat.message': async (_input, output) => {
      for (const part of output.parts as Part[]) {
        if (part.type !== 'text') continue;
        const original = part.text;
        if (!original) continue;
        const { text: sanitized, redactionCount } = sanitize(original, cfg);
        if (redactionCount > 0) {
          (part as { text: string }).text = sanitized;
        }
      }
    },
  });
};

/**
 * Default export: a ready-to-use Plugin instance with default config.
 * Opencode calls the default export directly as `plugin(input) => Promise<Hooks>`,
 * so we export the already-instantiated Plugin, not the factory function.
 * For custom config use the named export: ContextSanitizer({ maxStringLength: 200 })
 */
export default ContextSanitizer();
