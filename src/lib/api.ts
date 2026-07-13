export async function requestJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const response = await fetch(input, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  });
  const payload = await response.json().catch(() => null) as unknown;
  if (!response.ok) {
    throw new Error(apiErrorMessage(payload) || `Request failed with HTTP ${response.status}.`);
  }
  return payload as T;
}

function apiErrorMessage(payload: unknown): string {
  if (!isObject(payload)) {
    return '';
  }
  if (typeof payload.error === 'string') {
    return payload.error;
  }
  if (isObject(payload.error) && typeof payload.error.message === 'string') {
    return payload.error.message;
  }
  return '';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
