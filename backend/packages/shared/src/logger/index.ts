/**
 * Structured logger built on top of Pino.
 *
 * Provides a consistent JSON log shape across all AICC services, with
 * service-name and version correlation.
 */
import pino, { type Logger, type LoggerOptions } from 'pino';

export interface CreateLoggerOptions {
  service: string;
  version: string;
  level?: string;
  environment?: string;
  pretty?: boolean;
}

export function createLogger(opts: CreateLoggerOptions): Logger {
  const level = opts.level ?? process.env.LOG_LEVEL ?? 'info';
  const baseOptions: LoggerOptions = {
    level,
    base: {
      service: opts.service,
      version: opts.version,
      env: opts.environment ?? process.env.NODE_ENV ?? 'development',
      pid: process.pid,
    },
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level: (label) => ({ level: label }),
    },
  };

  if (opts.pretty ?? process.env.NODE_ENV !== 'production') {
    return pino({
      ...baseOptions,
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:HH:MM:ss.l',
          ignore: 'pid,hostname,service,version',
          messageFormat: '[{service}] {msg}',
        },
      },
    });
  }

  return pino(baseOptions);
}

export type { Logger };
