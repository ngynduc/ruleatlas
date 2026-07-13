import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import type { RuleRepoConfig } from './ruleRepoPlugin';
import type { AttackDataDiscovery, AttackDatasetFile, RuleTestInput } from './attackData';
import { ApiError } from './http';

const defaultRequestTimeoutMs = 120_000;
const searchRetryDelayMs = 1_500;
const searchRetries = 5;
const attackDataEarliestTime = '-5m';
const defaultHistoricalEarliestTime = '-24h';
const defaultLatestTime = 'now';

export type RuleTestMode = 'attack_data' | 'historical';

export interface RuleTestRunResult {
  runId: string;
  ruleId: string;
  ruleName: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  passed: boolean;
  mode: RuleTestMode;
  originalQuery: string;
  query: string;
  queryScoped: boolean;
  indexOverridden: boolean;
  testIndex?: string;
  earliestTime: string;
  latestTime: string;
  resultCount: number;
  searchAttempts: number;
  pulledAttackData: boolean;
  selectionMode?: AttackDataDiscovery['selectionMode'];
  selectedManifests: AttackDataDiscovery['matches'];
  ingestedFiles: Array<{
    name: string;
    path: string;
    source: string;
    sourcetype: string;
    bytes: number;
  }>;
  warnings: string[];
}

export type SplunkTestProgress =
  | {
    type: 'ingest_started';
    currentFile: number;
    totalFiles: number;
    file: AttackDatasetFile;
    bytes: number;
    index: string;
  }
  | {
    type: 'ingest_accepted';
    currentFile: number;
    totalFiles: number;
    file: AttackDatasetFile;
    statusCode: number;
    hecCode?: number;
    hecText?: string;
  }
  | { type: 'search_started'; queryScoped: boolean; totalAttempts: number }
  | { type: 'search_attempt'; attempt: number; totalAttempts: number; resultCount: number };

interface RunOptions {
  mode?: RuleTestMode;
  discovery?: AttackDataDiscovery;
  files?: AttackDatasetFile[];
  pulledAttackData?: boolean;
  earliestTime?: string;
  latestTime?: string;
  runId?: string;
  onProgress?: (progress: SplunkTestProgress) => void;
}

export async function executeSplunkRuleTest(
  config: RuleRepoConfig,
  rule: RuleTestInput,
  options: RunOptions,
): Promise<RuleTestRunResult> {
  const mode = options.mode ?? 'attack_data';
  const credentials = splunkCredentials(config, mode);
  const data = rule.data ?? {};
  const ruleId = stringValue(data.rule_id) || stringValue(rule.id) || 'rule';
  const ruleName = stringValue(data.name) || ruleId;
  const rawQuery = stringValue(data.query);
  if (!rawQuery) {
    throw new ApiError(422, 'rule_query_missing', 'Rule query is required before a Splunk test can run.');
  }
  const platform = stringValue(data.platform);
  if (platform && platform.toLowerCase() !== 'splunk') {
    throw new ApiError(422, 'unsupported_rule_platform', `Splunk tests cannot run for platform ${platform}.`);
  }

  const startedAt = new Date();
  const runId = options.runId ?? `ruleatlas-${slug(ruleId)}-${startedAt.getTime()}`;
  const files = mode === 'attack_data' ? options.files ?? [] : [];
  const ingestedFiles: RuleTestRunResult['ingestedFiles'] = [];

  for (const [index, file] of files.entries()) {
    const fileStat = await stat(file.localPath);
    options.onProgress?.({
      type: 'ingest_started',
      currentFile: index + 1,
      totalFiles: files.length,
      file,
      bytes: fileStat.size,
      index: config.splunkIndex,
    });
    const acknowledgement = await sendFileToHec(config, credentials.hecToken, file, runId, fileStat.size);
    ingestedFiles.push({
      name: file.name,
      path: file.path,
      source: file.source,
      sourcetype: file.sourcetype,
      bytes: fileStat.size,
    });
    options.onProgress?.({
      type: 'ingest_accepted',
      currentFile: index + 1,
      totalFiles: files.length,
      file,
      ...acknowledgement,
    });
  }

  const preparedQuery = mode === 'attack_data'
    ? scopeSplunkQuery(rawQuery, runId, config.splunkIndex)
    : { query: normalizeSplunkQuery(rawQuery), scoped: false, indexOverridden: false };
  const earliestTime = mode === 'attack_data'
    ? attackDataEarliestTime
    : options.earliestTime?.trim() || defaultHistoricalEarliestTime;
  const latestTime = mode === 'attack_data'
    ? defaultLatestTime
    : options.latestTime?.trim() || defaultLatestTime;
  const totalAttempts = mode === 'attack_data' ? searchRetries : 1;
  options.onProgress?.({
    type: 'search_started',
    queryScoped: preparedQuery.scoped,
    totalAttempts,
  });
  const search = await searchUntilSettled(config, credentials.apiToken, preparedQuery.query, {
    earliestTime,
    latestTime,
    totalAttempts,
    onProgress: options.onProgress,
  });
  const completedAt = new Date();
  const warnings = mode === 'attack_data' ? [...(options.discovery?.warnings ?? [])] : [];
  if (mode === 'attack_data' && !preparedQuery.scoped) {
    warnings.push('Query starts with a generating command, so RuleAtlas could not override the test index or add the per-run host filter. The search is limited to the recent test window.');
  }

  return {
    runId,
    ruleId,
    ruleName,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    passed: search.resultCount > 0,
    mode,
    originalQuery: rawQuery,
    query: preparedQuery.query,
    queryScoped: preparedQuery.scoped,
    indexOverridden: preparedQuery.indexOverridden,
    ...(mode === 'attack_data' ? { testIndex: config.splunkIndex } : {}),
    earliestTime,
    latestTime,
    resultCount: search.resultCount,
    searchAttempts: search.attempts,
    pulledAttackData: mode === 'attack_data' && Boolean(options.pulledAttackData),
    ...(mode === 'attack_data' && options.discovery
      ? { selectionMode: options.discovery.selectionMode }
      : {}),
    selectedManifests: mode === 'attack_data' ? options.discovery?.matches ?? [] : [],
    ingestedFiles,
    warnings,
  };
}

export function assertSplunkTestConfigured(
  config: RuleRepoConfig,
  mode: RuleTestMode = 'attack_data',
): void {
  splunkCredentials(config, mode);
}

export function scopeSplunkQuery(
  query: string,
  runHost: string,
  testIndex?: string,
): { query: string; scoped: boolean; indexOverridden: boolean } {
  const searchQuery = normalizeSplunkQuery(query);
  if (searchQuery.startsWith('|')) {
    return { query: searchQuery, scoped: false, indexOverridden: false };
  }

  const pipeIndex = searchQuery.indexOf('|');
  const originalHead = pipeIndex >= 0 ? searchQuery.slice(0, pipeIndex).trimEnd() : searchQuery;
  const tail = pipeIndex >= 0 ? ` ${searchQuery.slice(pipeIndex).trimStart()}` : '';
  const head = testIndex ? overrideBaseSearchIndex(originalHead, testIndex) : originalHead;
  return {
    query: `${head} host="${escapeSplunkString(runHost)}"${tail}`,
    scoped: true,
    indexOverridden: Boolean(testIndex),
  };
}

function normalizeSplunkQuery(query: string): string {
  const trimmed = query.trim();
  return /^search\s+/i.test(trimmed) || trimmed.startsWith('|') ? trimmed : `search ${trimmed}`;
}

function overrideBaseSearchIndex(searchHead: string, testIndex: string): string {
  const replacement = `index="${escapeSplunkString(testIndex)}"`;
  let replacements = 0;
  const replaceIndex = () => {
    replacements += 1;
    return replacement;
  };
  const withoutIndexLists = searchHead.replace(/\bindex\s+IN\s*\([^)]*\)/gi, replaceIndex);
  const overridden = withoutIndexLists.replace(
    /\bindex\s*=\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s|()]+)/gi,
    replaceIndex,
  );
  return replacements > 0 ? overridden : `${overridden} ${replacement}`;
}

export function parseSplunkExportResults(body: string): number {
  let resultCount = 0;
  for (const line of body.split('\n').map((item) => item.trim()).filter(Boolean)) {
    try {
      const payload = JSON.parse(line) as Record<string, unknown>;
      if (payload.result && typeof payload.result === 'object') {
        resultCount += 1;
      }
    } catch {
      // Splunk can include informational lines; only JSON result objects count.
    }
  }
  return resultCount;
}

async function sendFileToHec(
  config: RuleRepoConfig,
  hecToken: string,
  file: AttackDatasetFile,
  runId: string,
  size: number,
) {
  const url = serviceUrl(config.splunkHecUrl, '/services/collector/raw');
  url.searchParams.set('host', runId);
  url.searchParams.set('index', config.splunkIndex);
  url.searchParams.set('source', file.source);
  url.searchParams.set('sourcetype', file.sourcetype);
  url.searchParams.set('time', String(Date.now() / 1000));

  const response = await requestText(url, {
    filePath: file.localPath,
    headers: {
      Authorization: `Splunk ${hecToken}`,
      'Content-Length': String(size),
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Splunk-Request-Channel': crypto.randomUUID(),
    },
    method: 'POST',
    rejectUnauthorized: config.splunkVerifyTls,
  });
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new ApiError(502, 'splunk_ingest_failed', `Splunk HEC rejected ${file.name} with HTTP ${response.statusCode}.`, {
      file: file.path,
      splunkStatus: response.statusCode,
      response: safeResponseSummary(response.body),
    });
  }
  const payload = parseJsonObject(response.body);
  if (typeof payload.code === 'number' && payload.code !== 0) {
    throw new ApiError(502, 'splunk_ingest_failed', `Splunk HEC rejected ${file.name}: ${stringValue(payload.text) || `code ${payload.code}`}.`, {
      file: file.path,
      hecCode: payload.code,
    });
  }
  return {
    statusCode: response.statusCode,
    ...(typeof payload.code === 'number' ? { hecCode: payload.code } : {}),
    ...(stringValue(payload.text) ? { hecText: stringValue(payload.text) } : {}),
  };
}

async function searchUntilSettled(
  config: RuleRepoConfig,
  apiToken: string,
  query: string,
  options: {
    earliestTime: string;
    latestTime: string;
    totalAttempts: number;
    onProgress?: (progress: SplunkTestProgress) => void;
  },
) {
  let resultCount = 0;
  let attempts = 0;
  for (let attempt = 1; attempt <= options.totalAttempts; attempt += 1) {
    attempts = attempt;
    if (attempt > 1) {
      await delay(searchRetryDelayMs);
    }
    resultCount = await runSplunkSearch(
      config,
      apiToken,
      query,
      options.earliestTime,
      options.latestTime,
    );
    options.onProgress?.({
      type: 'search_attempt',
      attempt,
      totalAttempts: options.totalAttempts,
      resultCount,
    });
    if (resultCount > 0) {
      break;
    }
  }
  return { attempts, resultCount };
}

async function runSplunkSearch(
  config: RuleRepoConfig,
  apiToken: string,
  query: string,
  earliestTime: string,
  latestTime: string,
): Promise<number> {
  const url = serviceUrl(config.splunkApiUrl, '/services/search/jobs/export');
  const body = new URLSearchParams({
    earliest_time: earliestTime,
    latest_time: latestTime,
    output_mode: 'json',
    search: query,
  }).toString();
  const response = await requestText(url, {
    body,
    headers: {
      Authorization: `Splunk ${apiToken}`,
      'Content-Length': String(Buffer.byteLength(body)),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    method: 'POST',
    rejectUnauthorized: config.splunkVerifyTls,
  });
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new ApiError(502, 'splunk_search_failed', `Splunk search returned HTTP ${response.statusCode}.`, {
      splunkStatus: response.statusCode,
      response: safeResponseSummary(response.body),
    });
  }
  return parseSplunkExportResults(response.body);
}

function splunkCredentials(config: RuleRepoConfig, mode: RuleTestMode = 'attack_data') {
  const hecToken = process.env.SPLUNK_HEC_TOKEN?.trim();
  const apiToken = (process.env.SPLUNK_API_TOKEN || process.env.SPLUNK_TOKEN)?.trim();
  const missing: string[] = [];
  if (!config.splunkApiUrl) missing.push('Splunk API URL');
  if (!apiToken) missing.push('SPLUNK_API_TOKEN');
  if (mode === 'attack_data') {
    if (!config.splunkHecUrl) missing.push('Splunk HEC URL');
    if (!hecToken) missing.push('SPLUNK_HEC_TOKEN');
  }
  if (missing.length > 0) {
    throw new ApiError(412, 'splunk_not_configured', `Splunk test engine is missing: ${missing.join(', ')}.`, { missing });
  }
  return { apiToken: apiToken as string, hecToken: hecToken ?? '' };
}

interface RequestTextOptions {
  method: string;
  headers?: Record<string, string>;
  body?: string;
  filePath?: string;
  rejectUnauthorized: boolean;
}

async function requestText(url: URL, options: RequestTextOptions): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(url, {
      method: options.method,
      headers: options.headers,
      ...(url.protocol === 'https:' ? { rejectUnauthorized: options.rejectUnauthorized } : {}),
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on('end', () => resolve({
        statusCode: response.statusCode ?? 0,
        body: Buffer.concat(chunks).toString('utf-8'),
      }));
    });

    request.setTimeout(defaultRequestTimeoutMs, () => {
      request.destroy(new Error(`Request to ${url.host} timed out.`));
    });
    request.on('error', (error) => reject(new ApiError(502, 'splunk_unreachable', `Unable to reach Splunk at ${url.host}: ${error.message}`)));

    if (options.filePath) {
      const stream = createReadStream(options.filePath);
      stream.on('error', (error) => request.destroy(error));
      stream.pipe(request);
      return;
    }
    request.end(options.body);
  });
}

function serviceUrl(baseUrl: string, servicePath: string): URL {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new ApiError(422, 'invalid_splunk_url', `Invalid Splunk URL: ${baseUrl}`);
  }
  if (!url.pathname.includes('/services/')) {
    url.pathname = servicePath;
  }
  return url;
}

function safeResponseSummary(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').slice(0, 500);
}

function parseJsonObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function escapeSplunkString(value: string): string {
  return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'rule';
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : '';
}

function delay(milliseconds: number) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
