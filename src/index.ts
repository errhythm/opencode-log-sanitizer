import type { Plugin, PluginInput } from '@opencode-ai/plugin';
import type { Part } from '@opencode-ai/sdk';
import { _sanitize, resolveConfig, type SanitizerConfig } from './sanitizer.js';
import { createDebugLogger } from './logger.js';

/**
 * ContextSanitizer — OpenCode plugin that redacts long/machine-generated values
 * (JWTs, bcrypt hashes, base64 blobs, long quoted strings) from user messages
 * before they are forwarded to the LLM.
 *
 * Configuration (all optional, shown with defaults):
 *   { "plugin": [["opencode-log-sanitizer", { "maxStringLength": 300 }]] }
 */
export interface ContextSanitizerPlugin extends Plugin {
  (input: PluginInput, config?: Partial<SanitizerConfig>): ReturnType<Plugin>;
}

export const ContextSanitizer: ContextSanitizerPlugin = async (
  { client },
  config?: Partial<SanitizerConfig>
) => {
  const cfg = resolveConfig(config);
  const logger = createDebugLogger({
    client,
    enabled: cfg.debug,
    filePath: cfg.debugLogFile,
  });

  await logger.info('plugin initialized', {
    debugLogFile: logger.filePath,
    maxStringLength: cfg.maxStringLength,
    enableJwtDetection: cfg.enableJwtDetection,
    enableBcryptDetection: cfg.enableBcryptDetection,
    enableBase64Detection: cfg.enableBase64Detection,
  });

  return {
    'chat.message': async (input, output) => {
      let totalRedactions = 0;
      let changedParts = 0;

      await logger.debug('chat.message received', {
        sessionID: input.sessionID,
        partCount: output.parts.length,
      });

      for (const part of output.parts as Part[]) {
        if (part.type !== 'text') continue;

        const original = part.text;
        if (!original) continue;

        const { text: sanitized, redactionCount, redactions } = _sanitize(original, cfg);
        if (redactionCount === 0) continue;

        (part as { text: string }).text = sanitized;
        totalRedactions += redactionCount;
        changedParts++;

        await logger.debug('message part sanitized', {
          originalLength: original.length,
          sanitizedLength: sanitized.length,
          redactionCount,
          redactions,
        });
      }

      if (totalRedactions === 0) {
        await logger.debug('message left unchanged', { sessionID: input.sessionID });
        return;
      }

      await logger.info('message sanitized', {
        sessionID: input.sessionID,
        changedParts,
        totalRedactions,
      });
    },
  };
};

export default ContextSanitizer;
