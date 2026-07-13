import type { IncomingMessage } from 'node:http';
import { describe, expect, it } from 'vitest';
import { ApiError, assertLocalApiRequest, isLoopbackAddress } from './http';

describe('local API guard', () => {
  it.each(['127.0.0.1', '127.0.0.42', '::1', '::ffff:127.0.0.1'])(
    'allows loopback address %s',
    (address) => expect(isLoopbackAddress(address)).toBe(true),
  );

  it('rejects non-loopback clients', () => {
    expect(() => assertLocalApiRequest(requestFrom('192.168.1.50'))).toThrowError(ApiError);
  });

  it('rejects cross-origin browser requests on loopback', () => {
    const request = requestFrom('127.0.0.1', {
      host: '127.0.0.1:5173',
      origin: 'http://attacker.example',
    });
    expect(() => assertLocalApiRequest(request)).toThrowError('Cross-origin API requests are not allowed.');
  });

  it('allows same-origin browser requests on loopback', () => {
    const request = requestFrom('127.0.0.1', {
      host: '127.0.0.1:5173',
      origin: 'http://127.0.0.1:5173',
    });
    expect(() => assertLocalApiRequest(request)).not.toThrow();
  });
});

function requestFrom(remoteAddress: string, headers: Record<string, string> = {}): IncomingMessage {
  return {
    headers,
    socket: { remoteAddress },
  } as unknown as IncomingMessage;
}
