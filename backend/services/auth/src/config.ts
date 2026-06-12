/**
 * Auth Service — environment configuration.
 *
 * Centralized env loading & validation with sensible defaults and
 * type safety via Zod.
 */
import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'staging', 'production']).default('development'),
  SERVICE_NAME: z.string().default('auth-service'),
  SERVICE_VERSION: z.string().default('0.1.0'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(4001),
  LOG_LEVEL: z.string().default('info'),
  JWT_SECRET: z.string().min(16, 'JWT_SECRET must be at least 16 chars'),
  JWT_ISSUER: z.string().default('aicc'),
  JWT_AUDIENCE: z.string().default('aicc-api'),
  JWT_ACCESS_TTL: z.string().default('15m'),
  JWT_REFRESH_TTL: z.string().default('7d'),
  DATABASE_URL: z.string().url().optional(),
  EVENT_BUS_DRIVER: z.enum(['memory', 'nats', 'redis-streams']).default('memory'),
  EVENT_BUS_NATS_URL: z.string().optional(),
});

export type AuthEnv = z.infer<typeof EnvSchema>;

let cached: AuthEnv | undefined;

export function loadEnv(): AuthEnv {
  if (cached) return cached;
  const parsed = EnvSchema.safeParse(process.env);
  if (!parsed.success) {
    // eslint-disable-next-line no-console
    console.error('[auth-service] invalid environment', parsed.error.flatten());
    throw new Error('Invalid environment configuration for auth-service');
  }
  cached = parsed.data;
  return cached;
}
