import { test, expect } from 'vitest';
import { InMemoryEventBus } from './index.js';

test('publish delivers the event to a subscribed handler', async () => {
  const bus = new InMemoryEventBus();
  const received: unknown[] = [];
  await bus.subscribe('test.event', (event) => {
    received.push(event.data);
  });

  await bus.publish({
    type: 'test.event',
    version: 1,
    source: 'test',
    tenantId: 't-1',
    data: { hello: 'world' },
  });

  expect(received).toEqual([{ hello: 'world' }]);
});

test('publish fans out to every handler subscribed to the same type', async () => {
  const bus = new InMemoryEventBus();
  let a = 0;
  let b = 0;
  await bus.subscribe('test.event', () => { a += 1; });
  await bus.subscribe('test.event', () => { b += 1; });

  await bus.publish({ type: 'test.event', version: 1, source: 'test', tenantId: 't-1', data: {} });

  expect(a).toBe(1);
  expect(b).toBe(1);
});

test('publish is a no-op when there are no subscribers for the type', async () => {
  const bus = new InMemoryEventBus();
  await expect(
    bus.publish({ type: 'no.subscribers', version: 1, source: 'test', tenantId: 't-1', data: {} }),
  ).resolves.toBeUndefined();
});

test('publish after close rejects', async () => {
  const bus = new InMemoryEventBus();
  await bus.close();
  await expect(
    bus.publish({ type: 'test.event', version: 1, source: 'test', tenantId: 't-1', data: {} }),
  ).rejects.toThrow(/closed/i);
});
