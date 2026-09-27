import { describe, expect, it } from 'vitest';
import { isChunkLoadError, routeErrorMessage } from './App';

// No jsdom/testing-library in this project (see App.routes.test.ts), so the
// `RouteErrorBoundary` class itself isn't mounted here — its
// `getDerivedStateFromError`/message-selection logic is pulled out into
// these two pure functions instead, which this exercises directly.
describe('RouteErrorBoundary message selection (S9-3)', () => {
  it('flags a webpack/Vite ChunkLoadError by name', () => {
    const err = new Error('Loading chunk 4 failed');
    err.name = 'ChunkLoadError';
    expect(isChunkLoadError(err)).toBe(true);
    expect(routeErrorMessage(err)).toMatch(/reload/i);
  });

  it('flags a browser dynamic-import failure by message', () => {
    const err = new Error('Failed to fetch dynamically imported module: /routes/SBOM.js');
    expect(isChunkLoadError(err)).toBe(true);
    expect(routeErrorMessage(err)).toMatch(/reload/i);
  });

  it('treats an ordinary render error as a generic failure', () => {
    const err = new Error('Cannot read properties of undefined');
    expect(isChunkLoadError(err)).toBe(false);
    expect(routeErrorMessage(err)).toBe('Something went wrong loading this page.');
  });
});
