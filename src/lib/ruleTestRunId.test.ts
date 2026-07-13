import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRunId } from './ruleTestRunId';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('rule-test run IDs', () => {
  it('uses randomUUID when the browser exposes it', () => {
    vi.spyOn(Date, 'now').mockReturnValue(1234);
    vi.stubGlobal('crypto', {
      randomUUID: () => '12345678-1234-4123-8123-123456789abc',
    });

    expect(createRunId()).toBe('ruleatlas-ui-1234-12345678');
  });

  it('uses getRandomValues when randomUUID is unavailable', () => {
    vi.spyOn(Date, 'now').mockReturnValue(5678);
    vi.stubGlobal('crypto', {
      getRandomValues: (values: Uint8Array) => {
        values.set([0xde, 0xad, 0xbe, 0xef]);
        return values;
      },
    });

    expect(createRunId()).toBe('ruleatlas-ui-5678-deadbeef');
  });

  it('keeps working when the Web Crypto API is unavailable', () => {
    vi.spyOn(Date, 'now').mockReturnValue(9012);
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    vi.stubGlobal('crypto', undefined);

    expect(createRunId()).toBe('ruleatlas-ui-9012-80000000');
  });
});
