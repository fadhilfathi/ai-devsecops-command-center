#!/usr/bin/env node
/**
 * Cross-service smoke test.
 *
 * Boots every service in-process and hits /healthz, /readyz, /version
 * on each. Intended for CI and developer sanity checks; not a
 * substitute for per-service unit tests.
 */
import { buildServer as buildAuth } from '../services/auth/src/index.js';
import { buildServer as buildAgent } from '../services/agent/src/index.js';
import { buildServer as buildSecurity } from '../services/security/src/index.js';
import { buildServer as buildIncident } from '../services/incident/src/index.js';
import { buildServer as buildCompliance } from '../services/compliance/src/index.js';
import { buildServer as buildIntegration } from '../services/integration/src/index.js';

const services = [
  { name: 'auth',         port: 4001, build: buildAuth },
  { name: 'agent',        port: 4002, build: buildAgent },
  { name: 'security',     port: 4003, build: buildSecurity },
  { name: 'incident',     port: 4004, build: buildIncident },
  { name: 'compliance',   port: 4005, build: buildCompliance },
  { name: 'integration',  port: 4006, build: buildIntegration },
];

async function main() {
  let failed = 0;
  for (const svc of services) {
    process.env.PORT = String(svc.port);
    const server = await svc.build();
    await server.listen({ port: svc.port, host: '127.0.0.1' });
    const base = `http://127.0.0.1:${svc.port}`;
    for (const path of ['/healthz', '/readyz', '/version']) {
      try {
        const res = await fetch(base + path);
        if (!res.ok) {
          console.error(`✖ ${svc.name}${path} -> ${res.status}`);
          failed++;
        } else {
          console.log(`✓ ${svc.name}${path}`);
        }
      } catch (err) {
        console.error(`✖ ${svc.name}${path} -> ${(err as Error).message}`);
        failed++;
      }
    }
    await server.close();
  }
  if (failed > 0) {
    console.error(`\n${failed} check(s) failed`);
    process.exit(1);
  }
  console.log('\nAll services healthy');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
