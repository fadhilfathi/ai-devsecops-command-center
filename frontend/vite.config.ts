import { defineConfig, type ProxyOptions } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';
import { PROXY_TABLE } from './proxy-table.mjs';

// There is no API gateway. Each browser-facing resource is proxied
// straight to the backend service that owns it — see `proxy-table.mjs`
// (the single source of truth, also used to generate `nginx.conf` for the
// production image via `pnpm --filter ./frontend gen:nginx`).
const SERVICE_PROXIES: Record<string, ProxyOptions> = Object.fromEntries(
  PROXY_TABLE.map(({ browserPath, port, upstreamPath }) => [
    browserPath,
    {
      target: `http://localhost:${port}`,
      changeOrigin: true,
      secure: false,
      rewrite: (p: string) => p.replace(browserPath, upstreamPath),
    },
  ]),
);

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    host: true,
    proxy: SERVICE_PROXIES,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    target: 'es2022',
  },
});
