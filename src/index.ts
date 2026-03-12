/**
 * opencode-context-sanitizer
 *
 * Intercepts outgoing prompts via the `chat.message` hook and redacts
 * long / machine-generated values (JWTs, bcrypt hashes, base64 blobs,
 * long quoted strings) before they reach the AI model.
 *
 * Hook anatomy (from @opencode-ai/plugin Hooks interface):
 *
 *   "chat.message": async (input, output) => { ... }
 *
 *   output.parts  — mutable Part[] that will be sent to the LLM.
 *                   Each TextPart has a `text` property we can rewrite.
 *
 * This is the only hook that lets a plugin modify prompt content before
 * it is transmitted. `tui.prompt.append` is a *notification* that text was
 * appended to the TUI input box; mutating its output has no effect on the
 * model payload.
 */

import type { Plugin } from '@opencode-ai/plugin';
import type { Part } from '@opencode-ai/sdk';
import { sanitize, type SanitizerConfig } from './sanitizer.ts';

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

/**
 * ContextSanitizer plugin factory.
 *
 * Accepts an optional partial config that overrides the defaults:
 *
 *   opencode.json
 *   { "plugin": [["opencode-context-sanitizer", { "maxStringLength": 200 }]] }
 */
export const ContextSanitizer = (config?: Partial<SanitizerConfig>): Plugin => {
  return async (ctx) => {
    return {
      /**
       * `chat.message` fires just before a user message is sent to the LLM.
       *
       * `output.parts` is the mutable array of Part objects that will be
       * forwarded to the model. We iterate over every TextPart and run the
       * sanitization pipeline on its `.text` field.
       */
      'chat.message': async (_input, output) => {
        let totalRedacted = 0;

        for (const part of output.parts as Part[]) {
          // Only TextParts carry free-form user text worth sanitizing.
          if (part.type !== 'text') continue;

          const original = part.text;
          if (!original || original.trim().length === 0) continue;

          const { text: sanitized, redactionCount } = sanitize(original, config);

          if (redactionCount > 0) {
            // Mutate in place — this is the object opencode will forward to the model.
            (part as { text: string }).text = sanitized;
            totalRedacted += redactionCount;
          }
        }

        if (totalRedacted > 0 && ctx.client?.app?.log) {
          await ctx.client.app.log({
            body: {
              service: 'opencode-context-sanitizer',
              level: 'info',
              message: `Sanitized prompt: ${totalRedacted} value(s) redacted`,
            },
          });
        }
      },
    };
  };
};

export default ContextSanitizer;
