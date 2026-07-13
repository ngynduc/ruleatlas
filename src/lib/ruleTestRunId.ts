export function createRunId(): string {
  return `ruleatlas-ui-${Date.now()}-${randomSuffix()}`;
}

function randomSuffix(): string {
  const cryptoApi = globalThis.crypto;

  if (typeof cryptoApi?.randomUUID === 'function') {
    return cryptoApi.randomUUID().slice(0, 8);
  }

  if (typeof cryptoApi?.getRandomValues === 'function') {
    return Array.from(cryptoApi.getRandomValues(new Uint8Array(4)), (byte) => (
      byte.toString(16).padStart(2, '0')
    )).join('');
  }

  return Math.floor(Math.random() * 0x1_0000_0000)
    .toString(16)
    .padStart(8, '0');
}
