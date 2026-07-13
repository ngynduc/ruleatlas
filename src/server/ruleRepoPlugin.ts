import { Buffer } from 'node:buffer';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, readFile, readdir, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Plugin } from 'vite';
import { handleGitRepositoryApi, validateGitBranchName, validateGitRemoteName } from './gitRepo';
import { handleRuleTestApi } from './ruleTestApi';
import { assertLocalApiRequest, sendApiError } from './http';

interface StoredRecord {
  id?: unknown;
  archived?: unknown;
  createdAt?: unknown;
  updatedAt?: unknown;
  data?: Record<string, unknown>;
}

type StorePayload = Record<string, StoredRecord[]>;

interface StoreFile {
  exportedAt: string;
  version: number;
  templates: StorePayload;
}

interface RuleAtlasConfigFile {
  ruleRepo?: {
    path?: unknown;
    repoPath?: unknown;
    contentRoot?: unknown;
  };
  github?: {
    remote?: unknown;
    baseBranch?: unknown;
  };
  attackData?: {
    path?: unknown;
    maxDatasets?: unknown;
  };
  splunk?: {
    hecUrl?: unknown;
    apiUrl?: unknown;
    index?: unknown;
    verifyTls?: unknown;
  };
}

export interface RuleRepoPluginOptions {
  repoPath?: string;
  contentRoot?: string;
  configPath?: string;
}

export interface RuleRepoConfig {
  configPath: string;
  repoPathInput: string;
  repoPath: string;
  contentRoot: string;
  contentRootPath: string;
  githubRemote: string;
  githubBaseBranch: string;
  attackDataPathInput: string;
  attackDataPath: string;
  attackDataMaxDatasets: number;
  splunkHecUrl: string;
  splunkApiUrl: string;
  splunkIndex: string;
  splunkVerifyTls: boolean;
}

const defaultRuleRepo = '../detection-rules';
const defaultContentRoot = 'contents';
const defaultAttackDataRepo = '../../DetectionEngineering/attack_data';
const defaultMaxDatasets = 5;
const defaultGitHubRemote = 'origin';
const defaultGitHubBaseBranch = 'main';
const defaultSplunkIndex = 'attack_data';
const localConfigFileName = 'ruleatlas.config.json';
const storeFileName = 'ruleatlas-store.json';
const templateFolders: Record<string, string> = {
  dataSources: 'data-sources',
  detectionObjectives: 'detection-objectives',
  inventory: 'inventory',
  mitreMappings: 'mitre-mappings',
  owners: 'owners',
  rules: 'rules',
};
const legacyRuleFolders: Record<string, string> = {
  'existing-rules': 'rules',
  'new-rules': 'rules',
};

export function ruleRepoPlugin(options: RuleRepoPluginOptions = {}): Plugin {
  return {
    name: 'ruleatlas-rule-repo',
    configureServer(server) {
      let repoConfig = resolveRuleRepoConfig(server.config.root, options);

      server.middlewares.use('/api', (request, response, next) => {
        try {
          assertLocalApiRequest(request);
          next();
        } catch (error) {
          sendApiError(response, error);
        }
      });

      server.middlewares.use('/api/rule-repo/config', async (request, response) => {
        try {
          if (request.method === 'GET') {
            sendJson(response, 200, repoResponseFields(repoConfig));
            return;
          }

          if (request.method === 'PUT') {
            repoConfig = await handleConfigPut(request, server.config.root, options);
            sendJson(response, 200, repoResponseFields(repoConfig));
            return;
          }

          sendJson(response, 405, { error: 'Method not allowed' });
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Unknown repo config error';
          sendJson(response, 500, { error: message });
        }
      });

      server.middlewares.use('/api/rule-repo/store', async (request, response) => {
        try {
          if (request.method === 'GET') {
            await handleGet(response, repoConfig);
            return;
          }

          if (request.method === 'PUT') {
            await handlePut(request, response, repoConfig);
            return;
          }

          sendJson(response, 405, { error: 'Method not allowed' });
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Unknown repo storage error';
          sendJson(response, 500, { error: message });
        }
      });

      server.middlewares.use('/api/rule-repo/git', (request, response) =>
        void handleGitRepositoryApi(request, response, repoConfig),
      );

      server.middlewares.use('/api/rule-tests', (request, response) =>
        void handleRuleTestApi(request, response, repoConfig),
      );
    },
  };
}

async function handleConfigPut(
  request: IncomingMessage,
  projectRoot: string,
  options: RuleRepoPluginOptions,
): Promise<RuleRepoConfig> {
  const payload = await readJson(request);
  if (!isObject(payload)) {
    throw new Error('Rule repo config must be an object.');
  }

  const repoPathInput = firstString(payload.path, payload.repoPath);
  if (!repoPathInput) {
    throw new Error('Rule repo path is required.');
  }

  const contentRoot = normalizeContentRoot(firstString(payload.contentRoot, defaultContentRoot));
  const configPath = resolveRuleAtlasConfigPath(projectRoot, options.configPath);
  const currentConfig = readRuleAtlasConfig(projectRoot, options.configPath);
  const attackDataPath = firstString(payload.attackDataPath, currentConfig.attackData?.path, defaultAttackDataRepo);
  const attackDataMaxDatasets = boundedInteger(
    payload.attackDataMaxDatasets,
    boundedInteger(currentConfig.attackData?.maxDatasets, defaultMaxDatasets, 1, 20),
    1,
    20,
  );
  const githubRemote = validateGitRemoteName(
    firstString(payload.githubRemote, currentConfig.github?.remote, defaultGitHubRemote),
  );
  const githubBaseBranch = validateGitBranchName(
    firstString(payload.githubBaseBranch, currentConfig.github?.baseBranch, defaultGitHubBaseBranch),
  );
  const splunkHecUrl = optionalString(payload.splunkHecUrl, currentConfig.splunk?.hecUrl);
  const splunkApiUrl = optionalString(payload.splunkApiUrl, currentConfig.splunk?.apiUrl);
  const splunkIndex = firstString(payload.splunkIndex, currentConfig.splunk?.index, defaultSplunkIndex);
  const splunkVerifyTls = booleanValue(payload.splunkVerifyTls, booleanValue(currentConfig.splunk?.verifyTls, true));
  const nextConfig: RuleAtlasConfigFile = {
    ...currentConfig,
    ruleRepo: {
      ...currentConfig.ruleRepo,
      path: repoPathInput,
      contentRoot: contentRoot || '.',
    },
    github: {
      ...currentConfig.github,
      remote: githubRemote,
      baseBranch: githubBaseBranch,
    },
    attackData: {
      ...currentConfig.attackData,
      path: attackDataPath,
      maxDatasets: attackDataMaxDatasets,
    },
    splunk: {
      ...currentConfig.splunk,
      hecUrl: splunkHecUrl,
      apiUrl: splunkApiUrl,
      index: splunkIndex,
      verifyTls: splunkVerifyTls,
    },
  };

  await writeJson(configPath, nextConfig);
  return resolveRuleRepoConfig(projectRoot, options);
}

async function handleGet(response: ServerResponse, repoConfig: RuleRepoConfig) {
  const storePath = path.join(repoConfig.repoPath, storeFileName);
  const fileStore = await readRuleFiles(repoConfig);

  try {
    const raw = await readFile(storePath, 'utf-8');
    const store = mergeStores(normalizeStore(JSON.parse(raw)), fileStore);
    sendJson(response, 200, {
      store: {
        exportedAt: new Date().toISOString(),
        version: 1,
        templates: store,
      },
      storePath,
      ...repoResponseFields(repoConfig),
    });
  } catch {
    if (storeHasRecords(fileStore)) {
      sendJson(response, 200, {
        store: {
          exportedAt: new Date().toISOString(),
          version: 1,
          templates: fileStore,
        },
        storePath,
        ...repoResponseFields(repoConfig),
      });
      return;
    }

    sendJson(response, 404, {
      store: null,
      storePath,
      ...repoResponseFields(repoConfig),
    });
  }
}

async function handlePut(request: IncomingMessage, response: ServerResponse, repoConfig: RuleRepoConfig) {
  const store = await readJson(request);
  const savedFiles = await writeStore(repoConfig, store);

  sendJson(response, 200, {
    savedFiles,
    storePath: path.join(repoConfig.repoPath, storeFileName),
    ...repoResponseFields(repoConfig),
  });
}

async function readRuleFiles(repoConfig: RuleRepoConfig): Promise<StorePayload> {
  const contentRootPath = repoConfig.contentRootPath;
  const folderToStoreKey = Object.fromEntries(
    Object.entries(templateFolders).map(([storeKey, folder]) => [folder, storeKey]),
  );
  const output: StorePayload = {};

  try {
    const folders = await readdir(contentRootPath, { withFileTypes: true });
    for (const folderEntry of folders) {
      if (!folderEntry.isDirectory()) {
        continue;
      }

      const storeKey =
        legacyRuleFolders[folderEntry.name] ?? folderToStoreKey[folderEntry.name] ?? folderEntry.name;
      const folderPath = path.join(contentRootPath, folderEntry.name);
      const files = await readdir(folderPath, { withFileTypes: true });
      output[storeKey] = output[storeKey] ?? [];

      for (const fileEntry of files) {
        if (!fileEntry.isFile() || !fileEntry.name.endsWith('.json')) {
          continue;
        }

        const filePath = path.join(folderPath, fileEntry.name);
        const raw = await readFile(filePath, 'utf-8');
        const parsed = JSON.parse(raw);
        if (isObject(parsed)) {
          output[storeKey].push(recordFromRuleFile(parsed));
        }
      }
    }
  } catch {
    return output;
  }

  return output;
}

function recordFromRuleFile(input: Record<string, unknown>): StoredRecord {
  const data = isObject(input.rule)
    ? input.rule
    : isObject(input.data)
      ? input.data
      : input;

  return {
    id: stringValue(input.id) || stringValue(data.rule_id) || stringValue(data.name),
    archived: input.archived === true,
    createdAt: stringValue(input.createdAt) || new Date().toISOString(),
    updatedAt: stringValue(input.updatedAt) || new Date().toISOString(),
    data,
  };
}

function mergeStores(primary: StorePayload, fallback: StorePayload): StorePayload {
  const output: StorePayload = { ...fallback, ...primary };

  for (const [storeKey, fallbackRecords] of Object.entries(fallback)) {
    const primaryRecords = primary[storeKey] ?? [];
    const recordsById = new Map<string, StoredRecord>();

    for (const record of fallbackRecords) {
      recordsById.set(recordKey(record), record);
    }
    for (const record of primaryRecords) {
      recordsById.set(recordKey(record), record);
    }

    output[storeKey] = [...recordsById.values()];
  }

  return output;
}

function storeHasRecords(store: StorePayload): boolean {
  return Object.values(store).some((records) => records.length > 0);
}

async function writeStore(repoConfig: RuleRepoConfig, store: unknown): Promise<string[]> {
  const storeFile: StoreFile = {
    exportedAt: new Date().toISOString(),
    version: 1,
    templates: normalizeStore(store),
  };

  await mkdir(repoConfig.repoPath, { recursive: true });

  const savedFiles: string[] = [];
  const storePath = path.join(repoConfig.repoPath, storeFileName);
  await writeJson(storePath, storeFile);
  savedFiles.push(storePath);

  for (const [storeKey, records] of Object.entries(storeFile.templates)) {
    const folder = templateFolders[storeKey] ?? slugify(storeKey);
    const targetFolder = path.join(repoConfig.contentRootPath, folder);
    await mkdir(targetFolder, { recursive: true });
    await removeJsonFiles(targetFolder);

    for (const record of records) {
      if (record.archived === true) {
        continue;
      }

      const fileName = `${recordSlug(record)}.json`;
      const filePath = path.join(targetFolder, fileName);
      await writeJson(filePath, {
        id: stringValue(record.id),
        archived: record.archived === true,
        createdAt: stringValue(record.createdAt),
        updatedAt: stringValue(record.updatedAt),
        rule: record.data ?? {},
      });
      savedFiles.push(filePath);
    }
  }

  return savedFiles;
}

async function removeJsonFiles(targetFolder: string) {
  const files = await readdir(targetFolder, { withFileTypes: true });
  await Promise.all(
    files
      .filter((file) => file.isFile() && file.name.endsWith('.json'))
      .map((file) => unlink(path.join(targetFolder, file.name))),
  );
}

function normalizeStore(store: unknown): StorePayload {
  if (!isObject(store)) {
    return {};
  }

  const source = isObject(store.templates) ? store.templates : store;
  const output = Object.entries(source).reduce<StorePayload>((normalized, [key, value]) => {
    const normalizedKey = key === 'newRules' || key === 'existingRules' ? 'rules' : key;
    normalized[normalizedKey] = [
      ...(normalized[normalizedKey] ?? []),
      ...(Array.isArray(value) ? value.filter(isObject) : []),
    ];
    return normalized;
  }, {});

  if (output.rules) {
    output.rules = dedupeRecords(output.rules);
  }

  return output;
}

function dedupeRecords(records: StoredRecord[]): StoredRecord[] {
  const recordsByKey = new Map<string, StoredRecord>();
  for (const record of records) {
    recordsByKey.set(recordKey(record), record);
  }
  return [...recordsByKey.values()];
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const raw = Buffer.concat(chunks).toString('utf-8');
  return raw.trim() ? JSON.parse(raw) : {};
}

async function writeJson(filePath: string, value: unknown) {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf-8');
}

function resolveRuleRepoConfig(projectRoot: string, options: RuleRepoPluginOptions): RuleRepoConfig {
  const config = readRuleAtlasConfig(projectRoot, options.configPath);
  const repoPathInput = firstString(
    process.env.RULEATLAS_RULE_REPO,
    options.repoPath,
    config.ruleRepo?.path,
    config.ruleRepo?.repoPath,
    defaultRuleRepo,
  );
  const contentRoot = normalizeContentRoot(
    firstString(
      process.env.RULEATLAS_RULE_REPO_CONTENT_ROOT,
      process.env.RULEATLAS_RULE_REPO_ROOT,
      options.contentRoot,
      config.ruleRepo?.contentRoot,
      defaultContentRoot,
    ),
  );
  const attackDataPathInput = firstString(
    process.env.RULEATLAS_ATTACK_DATA_REPO,
    config.attackData?.path,
    defaultAttackDataRepo,
  );
  const splunkHost = firstString(process.env.SPLUNK_HOST);
  const splunkHecUrl = firstString(
    process.env.SPLUNK_HEC_URL,
    config.splunk?.hecUrl,
    splunkHost ? `https://${splunkHost}:8088` : '',
  );
  const splunkApiUrl = firstString(
    process.env.SPLUNK_API_URL,
    config.splunk?.apiUrl,
    splunkHost ? `https://${splunkHost}:8089` : '',
  );
  return ruleRepoConfigFromValues(
    projectRoot,
    repoPathInput,
    contentRoot,
    resolveRuleAtlasConfigPath(projectRoot, options.configPath),
    {
      attackDataPathInput,
      attackDataMaxDatasets: boundedInteger(
        process.env.RULEATLAS_ATTACK_DATA_MAX_DATASETS,
        boundedInteger(config.attackData?.maxDatasets, defaultMaxDatasets, 1, 20),
        1,
        20,
      ),
      githubRemote: validateGitRemoteName(
        firstString(process.env.RULEATLAS_GITHUB_REMOTE, config.github?.remote, defaultGitHubRemote),
      ),
      githubBaseBranch: validateGitBranchName(
        firstString(
          process.env.RULEATLAS_GITHUB_BASE_BRANCH,
          config.github?.baseBranch,
          defaultGitHubBaseBranch,
        ),
      ),
      splunkHecUrl,
      splunkApiUrl,
      splunkIndex: firstString(process.env.SPLUNK_INDEX, config.splunk?.index, defaultSplunkIndex),
      splunkVerifyTls: booleanValue(process.env.SPLUNK_VERIFY_TLS, booleanValue(config.splunk?.verifyTls, true)),
    },
  );
}

function ruleRepoConfigFromValues(
  projectRoot: string,
  repoPathInput: string,
  contentRoot: string,
  configPath: string,
  services: Pick<
    RuleRepoConfig,
    | 'attackDataPathInput'
    | 'attackDataMaxDatasets'
    | 'githubRemote'
    | 'githubBaseBranch'
    | 'splunkHecUrl'
    | 'splunkApiUrl'
    | 'splunkIndex'
    | 'splunkVerifyTls'
  >,
): RuleRepoConfig {
  const resolvedRepoPath = path.resolve(projectRoot, repoPathInput);
  const attackDataPath = path.resolve(projectRoot, services.attackDataPathInput);
  return {
    configPath,
    repoPathInput,
    repoPath: resolvedRepoPath,
    contentRoot,
    contentRootPath: contentRoot ? path.join(resolvedRepoPath, contentRoot) : resolvedRepoPath,
    ...services,
    attackDataPath,
  };
}

function readRuleAtlasConfig(projectRoot: string, configPath?: string): RuleAtlasConfigFile {
  const resolvedPath = resolveRuleAtlasConfigPath(projectRoot, configPath);
  if (!existsSync(resolvedPath)) {
    return {};
  }

  try {
    const parsed = JSON.parse(readFileSync(resolvedPath, 'utf-8'));
    return isObject(parsed) ? (parsed as RuleAtlasConfigFile) : {};
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid JSON';
    throw new Error(`Unable to read ${resolvedPath}: ${message}`);
  }
}

function resolveRuleAtlasConfigPath(projectRoot: string, configPath?: string): string {
  return path.resolve(projectRoot, configPath || localConfigFileName);
}

function repoResponseFields(repoConfig: RuleRepoConfig) {
  return {
    path: repoConfig.repoPathInput,
    targetRepo: repoConfig.repoPath,
    contentRoot: repoConfig.contentRoot || '.',
    contentRootPath: repoConfig.contentRootPath,
    configPath: repoConfig.configPath,
    githubRemote: repoConfig.githubRemote,
    githubBaseBranch: repoConfig.githubBaseBranch,
    githubAuthAvailable: Boolean(process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_PAT),
    attackDataPath: repoConfig.attackDataPathInput,
    resolvedAttackDataPath: repoConfig.attackDataPath,
    attackDataMaxDatasets: repoConfig.attackDataMaxDatasets,
    splunkHecUrl: repoConfig.splunkHecUrl,
    splunkApiUrl: repoConfig.splunkApiUrl,
    splunkIndex: repoConfig.splunkIndex,
    splunkVerifyTls: repoConfig.splunkVerifyTls,
    splunkHecTokenAvailable: Boolean(process.env.SPLUNK_HEC_TOKEN),
    splunkApiTokenAvailable: Boolean(process.env.SPLUNK_API_TOKEN || process.env.SPLUNK_TOKEN),
  };
}

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return '';
}

function optionalString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string') {
      return value.trim();
    }
  }
  return '';
}

function boundedInteger(value: unknown, fallback: number, minimum: number, maximum: number): number {
  const parsed = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : Number.NaN;
  if (!Number.isInteger(parsed)) {
    return fallback;
  }
  return Math.min(maximum, Math.max(minimum, parsed));
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
  }
  return fallback;
}

function normalizeContentRoot(value: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed === '.') {
    return '';
  }
  if (path.isAbsolute(trimmed)) {
    throw new Error('Rule repo content root must be relative to the configured rule repo.');
  }

  const normalized = path.normalize(trimmed);
  if (normalized === '..' || normalized.startsWith(`..${path.sep}`)) {
    throw new Error('Rule repo content root must stay inside the configured rule repo.');
  }

  return normalized;
}

function recordSlug(record: StoredRecord): string {
  const data = record.data ?? {};
  const name =
    stringValue(data.rule_id) ||
    stringValue(data.name) ||
    stringValue(data.title) ||
    stringValue(record.id) ||
    'rule';

  return slugify(name);
}

function recordKey(record: StoredRecord): string {
  return (
    stringValue(record.id) ||
    stringValue(record.data?.rule_id) ||
    stringValue(record.data?.name) ||
    JSON.stringify(record)
  );
}

function slugify(value: string): string {
  const slug = value
    .toLowerCase()
    .replace(/https?:\/\//g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 96);

  return slug || 'rule';
}

function stringValue(value: unknown): string {
  if (typeof value === 'string') {
    return value.trim();
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return '';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sendJson(response: ServerResponse, statusCode: number, payload: unknown) {
  response.statusCode = statusCode;
  response.setHeader('Content-Type', 'application/json');
  response.end(JSON.stringify(payload));
}
