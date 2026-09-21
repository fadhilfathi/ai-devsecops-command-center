import { test, expect, beforeEach, afterEach } from 'vitest';
import { loadServiceConfig } from './index.js';

const ENV_KEYS = ['PORT', 'HOST', 'NODE_ENV', 'LOG_LEVEL'] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of ENV_KEYS) savedEnv[key] = process.env[key];
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

test('loadServiceConfig applies defaults when no env is set', () => {
  for (const key of ENV_KEYS) delete process.env[key];
  const cfg = loadServiceConfig('agent-service', '0.1.0');
  expect(cfg).toEqual({
    name: 'agent-service',
    version: '0.1.0',
    port: 4002,
    host: '0.0.0.0',
    environment: 'development',
    logLevel: 'info',
  });
});

test('loadServiceConfig unknown service defaults to port 4000', () => {
  delete process.env.PORT;
  const cfg = loadServiceConfig('unknown-service', '0.1.0');
  expect(cfg.port).toBe(4000);
});

test('loadServiceConfig honors env var overrides', () => {
  process.env.PORT = '5099';
  process.env.HOST = '127.0.0.1';
  process.env.NODE_ENV = 'production';
  process.env.LOG_LEVEL = 'debug';
  const cfg = loadServiceConfig('agent-service', '0.1.0');
  expect(cfg.port).toBe(5099);
  expect(cfg.host).toBe('127.0.0.1');
  expect(cfg.environment).toBe('production');
  expect(cfg.logLevel).toBe('debug');
});
