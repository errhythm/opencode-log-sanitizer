import { appendFile, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface AppLogger {
  app?: {
    log?: (input: {
      body: {
        service: string;
        level: LogLevel;
        message: string;
        extra?: Record<string, unknown>;
      };
    }) => Promise<unknown>;
  };
}

interface DebugLoggerOptions {
  client: AppLogger;
  enabled: boolean;
  filePath?: string;
}

const DEFAULT_LOG_PATH = join(
  homedir(),
  '.local',
  'share',
  'opencode',
  'opencode-log-sanitizer.debug.log'
);

function resolveLogPath(filePath?: string): string {
  if (!filePath) return DEFAULT_LOG_PATH;
  if (filePath.startsWith('~/')) return join(homedir(), filePath.slice(2));
  return filePath;
}

async function appendDebugLog(filePath: string, entry: Record<string, unknown>): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });
  await appendFile(filePath, `${JSON.stringify(entry)}\n`, 'utf8');
}

export function createDebugLogger(options: DebugLoggerOptions) {
  const filePath = resolveLogPath(options.filePath);

  async function log(
    level: LogLevel,
    message: string,
    extra?: Record<string, unknown>
  ): Promise<void> {
    if (!options.enabled) return;

    const entry = {
      ts: new Date().toISOString(),
      service: 'opencode-log-sanitizer',
      level,
      message,
      ...(extra ? { extra } : {}),
    };

    await Promise.allSettled([
      options.client.app?.log?.({
        body: {
          service: 'opencode-log-sanitizer',
          level,
          message,
          ...(extra ? { extra } : {}),
        },
      }),
      appendDebugLog(filePath, entry),
    ]);
  }

  return {
    debug: (message: string, extra?: Record<string, unknown>) => log('debug', message, extra),
    info: (message: string, extra?: Record<string, unknown>) => log('info', message, extra),
    warn: (message: string, extra?: Record<string, unknown>) => log('warn', message, extra),
    error: (message: string, extra?: Record<string, unknown>) => log('error', message, extra),
    filePath,
  };
}
