import type { Plugin } from '@opencode-ai/plugin';
import type { Part } from '@opencode-ai/sdk';
import { _sanitize, resolveConfig, type SanitizerConfig } from './sanitizer.js';

/**
 * ContextSanitizer — OpenCode plugin that redacts long/machine-generated values
 * (JWTs, bcrypt hashes, base64 blobs, long quoted strings) from user messages
 * before they are forwarded to the LLM.
 *
 * Configuration (all optional, shown with defaults):
 *   { "plugin": [["opencode-log-sanitizer", { "maxStringLength": 300 }]] }
 */
export const ContextSanitizer = (config?: Partial<SanitizerConfig>): Plugin => {
  const cfg = resolveConfig(config);

  return async () => ({
    'chat.message': async (_input, output) => {
      for (const part of output.parts as Part[]) {
        if (part.type !== 'text') continue;
        const original = part.text;
        if (!original) continue;
        const { text: sanitized, redactionCount } = _sanitize(original, cfg);
        if (redactionCount > 0) {
          (part as { text: string }).text = sanitized;
        }
      }
    },
  });
};

export default ContextSanitizer();
