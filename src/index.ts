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
 *     "plugins": {
 *       "opencode-log-sanitizer": {
 *         "maxStringLength": 300,
 *         "enableJwtDetection": true,
 *         "enableBcryptDetection": true,
 *         "enableBase64Detection": true
 *       }
 *     }
 *   }
 */

import { sanitize, type SanitizerConfig } from './sanitizer.ts';

// ---------------------------------------------------------------------------
// Plugin export
// ---------------------------------------------------------------------------

/**
 * ContextSanitizer — OpenCode plugin factory.
 *
 * @param config Optional configuration overrides (see SanitizerConfig).
 *
 * @example
 * // opencode.json
 * {
 *   "plugins": {
 *     "opencode-log-sanitizer": {}
 *   }
 * }
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const ContextSanitizer = (config?: Partial<SanitizerConfig>) => async (ctx: any) => {
  return {
    /**
     * `tui.prompt.append` fires just before the user's typed prompt is
     * committed to the session and sent to the AI. We mutate `output.text`
     * in-place to sanitize it.
     *
     * input  — read-only snapshot of the original prompt text
     * output — mutable object; set output.text to change what the AI sees
     */
    'tui.prompt.append': async (input: { text: string }, output: { text: string }) => {
      const original = output.text;
      if (!original || original.trim().length === 0) return;

      const { text: sanitized, redactionCount } = sanitize(original, config);

      if (redactionCount > 0) {
        output.text = sanitized;

        await ctx.client.app.log({
          body: {
            service: 'opencode-log-sanitizer',
            level: 'info',
            message: `Sanitized prompt: ${redactionCount} value(s) redacted`,
            extra: {
              originalLength: original.length,
              sanitizedLength: sanitized.length,
              redactionCount,
              savedChars: original.length - sanitized.length,
            },
          },
        });
      }
    },
  };
};
