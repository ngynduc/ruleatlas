import { emptyStore, importStorePayload, normalizeStore } from './records';
import type { TemplateStore } from '../types';

const storageKey = 'ruleatlas.templates.v1';
const repoStoreApi = '/api/rule-repo/store';
const repoConfigApi = '/api/rule-repo/config';

export interface RuleRepoConfigPayload {
  path: string;
  contentRoot: string;
  githubRemote: string;
  githubBaseBranch: string;
  attackDataPath: string;
  attackDataMaxDatasets: number;
  splunkHecUrl: string;
  splunkApiUrl: string;
  splunkIndex: string;
  splunkVerifyTls: boolean;
}

export interface RuleRepoConfigResult extends RuleRepoConfigPayload {
  targetRepo: string;
  contentRootPath: string;
  configPath: string;
  resolvedAttackDataPath: string;
  githubAuthAvailable: boolean;
  splunkHecTokenAvailable: boolean;
  splunkApiTokenAvailable: boolean;
}

export interface RepoStoreLoadResult {
  store: TemplateStore | null;
  storePath: string;
  targetRepo: string;
  contentRoot: string;
  contentRootPath: string;
}

export interface RepoStoreSaveResult {
  savedFiles: string[];
  store: TemplateStore;
  storePath: string;
  targetRepo: string;
  contentRoot: string;
  contentRootPath: string;
}

export function loadStore(): TemplateStore {
  const raw = window.localStorage.getItem(storageKey);
  if (!raw) {
    return emptyStore();
  }

  try {
    return normalizeStore(JSON.parse(raw));
  } catch {
    return emptyStore();
  }
}

export function saveStore(store: TemplateStore): void {
  window.localStorage.setItem(storageKey, JSON.stringify(normalizeStore(store), null, 2));
}

export async function loadRepoConfig(): Promise<RuleRepoConfigResult> {
  const response = await fetch(repoConfigApi, {
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Rule repo config load failed with HTTP ${response.status}`);
  }

  return (await response.json()) as RuleRepoConfigResult;
}

export async function saveRepoConfig(config: RuleRepoConfigPayload): Promise<RuleRepoConfigResult> {
  const response = await fetch(repoConfigApi, {
    body: JSON.stringify(config),
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    method: 'PUT',
  });

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(payload?.error ?? `Rule repo config save failed with HTTP ${response.status}`);
  }

  return (await response.json()) as RuleRepoConfigResult;
}

export async function loadRepoStore(): Promise<RepoStoreLoadResult | null> {
  const response = await fetch(repoStoreApi, {
    headers: { Accept: 'application/json' },
  });

  if (response.status === 404) {
    const payload = (await response.json()) as Omit<RepoStoreLoadResult, 'store'> & {
      store: null;
    };
    return {
      ...payload,
      store: null,
    };
  }

  if (!response.ok) {
    throw new Error(`Repo store load failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as RepoStoreLoadResult;
  return {
    ...payload,
    store: payload.store ? importStorePayload(payload.store) : null,
  };
}

export async function saveRepoStore(store: TemplateStore): Promise<RepoStoreSaveResult> {
  const response = await fetch(repoStoreApi, {
    body: JSON.stringify(normalizeStore(store)),
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    method: 'PUT',
  });

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(payload?.error ?? `Repo store save failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as Omit<RepoStoreSaveResult, 'store'> & { store: unknown };
  return { ...payload, store: importStorePayload(payload.store) };
}

export async function reserveRuleId(category: string): Promise<string> {
  const response = await fetch('/api/rule-repo/rule-ids', {
    body: JSON.stringify({ category }),
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    method: 'POST',
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(payload?.error ?? `Rule ID reservation failed with HTTP ${response.status}`);
  }
  const payload = (await response.json()) as { id?: unknown };
  if (typeof payload.id !== 'string' || !payload.id) {
    throw new Error('Rule ID reservation returned an invalid ID.');
  }
  return payload.id;
}
