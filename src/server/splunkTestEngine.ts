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

export interface RuleTestRunResult {
  runId: string;
  ruleId: string;
  ruleName: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  passed: boolean;
  query: string;
  queryScoped: boolean;
  resultCount: number;
  searchAttempts: number;
  pulledAttackData: boolean;
  selectionMode: AttackDataDiscovery['selectionMode'];
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
  discovery: AttackDataDiscovery;
  files: AttackDatasetFile[];
  pulledAttackData: boolean;
  runId?: string;
  onProgress?: (progress: SplunkTestProgress) => void;
}

export async function executeSplunkRuleTest(
  config: RuleRepoConfig,
  rule: RuleTestInput,
  options: RunOptions,
): Promise<RuleTestRunResult> {
  const credentials = splunkCredentials(config);
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
  const ingestedFiles: RuleTestRunResult['ingestedFiles'] = [];

  for (const [index, file] of options.files.entries()) {
    const fileStat = await stat(file.localPath);
    options.onProgress?.({
      type: 'ingest_started',
      currentFile: index + 1,
      totalFiles: options.files.length,
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
      totalFiles: options.files.length,
      file,
      ...acknowledgement,
    });
  }

  const scoped = scopeSplunkQuery(rawQuery, runId);
  options.onProgress?.({ type: 'search_started', queryScoped: scoped.scoped, totalAttempts: searchRetries });
  const search = await searchUntilSettled(config, credentials.apiToken, scoped.query, options.onProgress);
  const completedAt = new Date();
  const warnings = [...options.discovery.warnings];
  if (!scoped.scoped) {
    warnings.push('Query starts with a generating command, so RuleAtlas could not add the per-run host filter. The search is limited to the recent test window.');
  }

  return {
    runId,
    ruleId,
    ruleName,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    passed: search.resultCount > 0,
    query: scoped.query,
    queryScoped: scoped.scoped,
    resultCount: search.resultCount,
    searchAttempts: search.attempts,
    pulledAttackData: options.pulledAttackData,
    selectionMode: options.discovery.selectionMode,
    selectedManifests: options.discovery.matches,
    ingestedFiles,
    warnings,
  };
}

export function assertSplunkTestConfigured(config: RuleRepoConfig): void {
  splunkCredentials(config);
}

export function scopeSplunkQuery(query: string, runHost: string): { query: string; scoped: boolean } {
  const trimmed = query.trim();
  const searchQuery = /^search\s+/i.test(trimmed) ? trimmed : trimmed.startsWith('|') ? trimmed : `search ${trimmed}`;
  if (searchQuery.startsWith('|')) {
    return { query: searchQuery, scoped: false };
  }

  const pipeIndex = searchQuery.indexOf('|');
  const head = pipeIndex >= 0 ? searchQuery.slice(0, pipeIndex).trimEnd() : searchQuery;
  const tail = pipeIndex >= 0 ? ` ${searchQuery.slice(pipeIndex).trimStart()}` : '';
  return { query: `${head} host="${escapeSplunkString(runHost)}"${tail}`, scoped: true };
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
  onProgress?: (progress: SplunkTestProgress) => void,
) {
  let resultCount = 0;
  let attempts = 0;
  for (let attempt = 1; attempt <= searchRetries; attempt += 1) {
    attempts = attempt;
    if (attempt > 1) {
      await delay(searchRetryDelayMs);
    }
    resultCount = await runSplunkSearch(config, apiToken, query);
    onProgress?.({
      type: 'search_attempt',
      attempt,
      totalAttempts: searchRetries,
      resultCount,
    });
    if (resultCount > 0) {
      break;
    }
  }
  return { attempts, resultCount };
}

async function runSplunkSearch(config: RuleRepoConfig, apiToken: string, query: string): Promise<number> {
  const url = serviceUrl(config.splunkApiUrl, '/services/search/jobs/export');
  const body = new URLSearchParams({
    earliest_time: '-5m',
    latest_time: 'now',
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

function splunkCredentials(config: RuleRepoConfig) {
  const hecToken = process.env.SPLUNK_HEC_TOKEN?.trim();
  const apiToken = (process.env.SPLUNK_API_TOKEN || process.env.SPLUNK_TOKEN)?.trim();
  const missing: string[] = [];
  if (!config.splunkHecUrl) missing.push('Splunk HEC URL');
  if (!config.splunkApiUrl) missing.push('Splunk API URL');
  if (!hecToken) missing.push('SPLUNK_HEC_TOKEN');
  if (!apiToken) missing.push('SPLUNK_API_TOKEN');
  if (missing.length > 0) {
    throw new ApiError(412, 'splunk_not_configured', `Splunk test engine is missing: ${missing.join(', ')}.`, { missing });
  }
  return { apiToken: apiToken as string, hecToken: hecToken as string };
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
