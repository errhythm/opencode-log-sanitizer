/**
 * opencode-context-sanitizer
 *
 * An OpenCode plugin that sanitizes prompts before they are sent to the AI
 * model. It redacts sensitive or noisy values — JWT tokens, bcrypt hashes,
 * base64 blobs, and arbitrarily long quoted strings — to reduce token usage
 * and remove irrelevant noise.
 *
 * Usage in opencode.json:
 *
 *   {
 *     "plugin": ["opencode-log-sanitizer"]
 *   }
 */

import type { Plugin } from '@opencode-ai/plugin';
import { sanitize } from './sanitizer.ts';

// ---------------------------------------------------------------------------
// Plugin export
// ---------------------------------------------------------------------------

/**
 * ContextSanitizer — OpenCode plugin.
 *
 * Hooks into `chat.message` to sanitize all TextPart content in the user
 * message before it is sent to the AI model.
 *
 * @example
 * // opencode.json
 * {
 *   "plugin": ["opencode-log-sanitizer"]
 * }
 */
export const ContextSanitizer: Plugin = async ({ client }) => {
  return {
    /**
     * `chat.message` fires when a new user message is received, before it is
     * sent to the LLM. We sanitize every TextPart in output.parts to redact
     * sensitive or noisy values.
     */
    'chat.message': async (_input, output) => {
      let totalRedactions = 0;
      let savedChars = 0;

      for (const part of output.parts) {
        if (part.type !== 'text') continue;

        const original = part.text;

        if (!original || original.trim().length === 0) continue;

        const { text: sanitized, redactionCount } = sanitize(original);

        if (redactionCount > 0) {
          part.text = sanitized;
          totalRedactions += redactionCount;
          savedChars += original.length - sanitized.length;
        }
      }

      if (totalRedactions > 0) {
        await client.app.log({
          body: {
            service: 'opencode-log-sanitizer',
            level: 'info',
            message: `Sanitized prompt: ${totalRedactions} value(s) redacted, ${savedChars} chars saved`,
          },
        });
      }
    },
  };
};

export default ContextSanitizer;
