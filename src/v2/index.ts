import { _sanitize, resolveConfig, type SanitizerConfig } from '../sanitizer.js';
import { createDebugLogger } from '../logger.js';

const plugin = {
  id: 'opencode-log-sanitizer',

  async setup(ctx: any) {
    const cfg = resolveConfig(ctx?.options as Partial<SanitizerConfig> | undefined);
    const logger = createDebugLogger({
      client: ctx?.client,
      enabled: cfg.debug,
      filePath: cfg.debugLogFile,
    });

    await logger.info('plugin initialized', {
      maxStringLength: cfg.maxStringLength,
      enableJwtDetection: cfg.enableJwtDetection,
      enableBcryptDetection: cfg.enableBcryptDetection,
      enableBase64Detection: cfg.enableBase64Detection,
      enableSecretDetection: cfg.enableSecretDetection,
    });

    // Sanitize user prompts before they reach the model.
    try {
      await ctx.session?.hook?.('prompt', async (event: any) => {
        try {
          const prompt = event?.prompt;
          if (!prompt || typeof prompt.text !== 'string') return;
          const original = prompt.text;
          if (!original) return;

          const { text: sanitized, redactionCount, redactions } = _sanitize(original, cfg);
          if (redactionCount === 0) {
            await logger.debug('prompt left unchanged', { sessionID: event?.sessionID });
            return;
          }

          prompt.text = sanitized;

          await logger.info('prompt sanitized', {
            sessionID: event?.sessionID,
            originalLength: original.length,
            sanitizedLength: sanitized.length,
            redactionCount,
            redactions,
          });
        } catch {
          // best-effort: never break a request
        }
      });
    } catch {
      // No prompt hook surface: plugin still loads, just no sanitization
    }

    // Also sanitize tool output (shell/bash) before it reaches the model.
    try {
      await ctx.tool?.hook?.('execute.after', async (event: any) => {
        try {
          if (event?.tool !== 'shell' && event?.tool !== 'bash') return;
          const result = event?.result;
          if (!result) return;

          let redactionCount = 0;
          const redact = (text: string): string => {
            const res = _sanitize(text, cfg);
            redactionCount += res.redactionCount;
            return res.text;
          };
          if (typeof result.output === 'string') {
            result.output = redact(result.output);
          }
          if (typeof result.content === 'string') {
            result.content = redact(result.content);
          } else if (Array.isArray(result.content)) {
            for (const part of result.content) {
              if (part && typeof part === 'object' && typeof part.text === 'string') {
                part.text = redact(part.text);
              }
            }
          }
          if (redactionCount === 0) return;

          await logger.info('tool output sanitized', {
            sessionID: event?.sessionID,
            tool: event?.tool,
            redactionCount,
          });
        } catch {
          // best-effort
        }
      });
    } catch {
      // No tool hook surface
    }
  },
};

// Re-export the v1-style factory to avoid duplicating its implementation.
export { ContextSanitizer } from '../index.ts';

export default plugin;
