import { Buffer } from 'node:buffer';
import type { IncomingMessage, ServerResponse } from 'node:http';

const defaultBodyLimit = 1024 * 1024;

export class ApiError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(
    statusCode: number,
    code: string,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export async function readJsonBody(
  request: IncomingMessage,
  maxBytes = defaultBodyLimit,
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let receivedBytes = 0;

  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    receivedBytes += buffer.length;
    if (receivedBytes > maxBytes) {
      throw new ApiError(413, 'request_too_large', `Request body exceeds ${maxBytes} bytes.`);
    }
    chunks.push(buffer);
  }

  const raw = Buffer.concat(chunks).toString('utf-8');
  if (!raw.trim()) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new ApiError(400, 'invalid_json', 'Request body must contain valid JSON.');
  }
}

export function sendJson(response: ServerResponse, statusCode: number, payload: unknown) {
  response.statusCode = statusCode;
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json');
  response.end(JSON.stringify(payload));
}

export function sendApiError(response: ServerResponse, error: unknown) {
  const apiError = error instanceof ApiError
    ? error
    : new ApiError(500, 'internal_error', error instanceof Error ? error.message : 'Unexpected server error.');

  sendJson(response, apiError.statusCode, {
    error: {
      code: apiError.code,
      message: apiError.message,
      ...(apiError.details ? { details: apiError.details } : {}),
    },
  });
}

export function requestPath(request: IncomingMessage): string {
  return new URL(request.url ?? '/', 'http://ruleatlas.local').pathname;
}

export function assertLocalApiRequest(request: IncomingMessage): void {
  const remoteAddress = request.socket.remoteAddress ?? '';
  if (!isLoopbackAddress(remoteAddress)) {
    throw new ApiError(403, 'local_api_only', 'RuleAtlas operational APIs accept loopback connections only.');
  }

  const origin = request.headers.origin;
  const host = request.headers.host;
  if (origin && (!host || !sameOriginHost(origin, host))) {
    throw new ApiError(403, 'cross_origin_denied', 'Cross-origin API requests are not allowed.');
  }
}

export function isLoopbackAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  return normalized === '::1' || normalized === 'localhost' || normalized.startsWith('127.') || normalized.startsWith('::ffff:127.');
}

export function assertObject(value: unknown, code = 'invalid_request'): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ApiError(422, code, 'Request body must be a JSON object.');
  }
  return value as Record<string, unknown>;
}

export function requiredString(
  value: unknown,
  field: string,
  options: { maxLength?: number } = {},
): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new ApiError(422, 'validation_failed', `${field} is required.`, { field });
  }

  const normalized = value.trim();
  const maxLength = options.maxLength ?? 500;
  if (normalized.length > maxLength) {
    throw new ApiError(422, 'validation_failed', `${field} must be at most ${maxLength} characters.`, {
      field,
      maxLength,
    });
  }
  return normalized;
}

function sameOriginHost(origin: string, host: string): boolean {
  try {
    return new URL(origin).host.toLowerCase() === host.toLowerCase();
  } catch {
    return false;
  }
}
