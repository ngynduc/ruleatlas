import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { handleRuleTestApi } from './ruleTestApi';
import type { RuleRepoConfig } from './ruleRepoPlugin';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })));
  delete process.env.SPLUNK_HEC_TOKEN;
  delete process.env.SPLUNK_API_TOKEN;
});

describe('rule-test API status', () => {
  it('exposes materialization, HEC acceptance, and search checkpoints for a run', async () => {
    const repository = await createAttackDataFixture();
    const splunkServer = mockSplunkServer();
    await listen(splunkServer);
    const splunkAddress = splunkServer.address();
    if (!splunkAddress || typeof splunkAddress === 'string') throw new Error('Mock Splunk server did not start.');

    const apiServer = http.createServer((request, response) => {
      void handleRuleTestApi(request, response, configFor(repository, splunkAddress.port));
    });
    await listen(apiServer);
    const apiAddress = apiServer.address();
    if (!apiAddress || typeof apiAddress === 'string') throw new Error('Mock rule-test API did not start.');

    process.env.SPLUNK_HEC_TOKEN = 'hec-test-token';
    process.env.SPLUNK_API_TOKEN = 'api-test-token';
    const runId = `ruleatlas-api-status-${Date.now()}`;

    try {
      const runResponse = await fetch(`http://127.0.0.1:${apiAddress.port}/runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          runId,
          selectedDatasetPaths: ['/datasets/attack_techniques/T1059.003/test/events.log'],
          rule: {
            id: 'RA-STATUS',
            data: {
              rule_id: 'RA-STATUS',
              name: 'Status test',
              platform: 'Splunk',
              query: 'index=production EventCode=1',
            },
          },
        }),
      });
      expect(runResponse.status).toBe(201);
      const result = await runResponse.json() as {
        mode: string;
        query: string;
        testIndex?: string;
      };
      expect(result).toMatchObject({
        mode: 'attack_data',
        query: expect.stringContaining('index="attack_data"'),
        testIndex: 'attack_data',
      });

      const statusResponse = await fetch(`http://127.0.0.1:${apiAddress.port}/runs/${runId}`);
      expect(statusResponse.status).toBe(200);
      const status = await statusResponse.json() as {
        mode: string;
        state: string;
        ingestedFiles: number;
        resultCount: number;
        events: Array<{ message: string }>;
      };

      expect(status).toMatchObject({
        mode: 'attack_data',
        state: 'completed',
        ingestedFiles: 1,
        resultCount: 1,
      });
      expect(status.events.map((event) => event.message)).toEqual(expect.arrayContaining([
        'Selected 1 dataset file(s) from 1 manifest(s).',
        'Selected attack-data files were already materialized; no Git LFS fetch was needed.',
        'Splunk HEC accepted events.',
        'Search attempt 1/5 found 1 result(s).',
      ]));
    } finally {
      await close(apiServer);
      await close(splunkServer);
    }
  });

  it('runs the original query against historical data without attack-data discovery or HEC', async () => {
    const repository = await mkdtemp(path.join(tmpdir(), 'ruleatlas-api-historical-'));
    temporaryDirectories.push(repository);
    const splunkRequests: Array<{ url: string; body: string }> = [];
    const splunkServer = http.createServer((request, response) => {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk: string) => {
        body += chunk;
      });
      request.on('end', () => {
        splunkRequests.push({ url: request.url ?? '', body });
        response.statusCode = 200;
        response.setHeader('Content-Type', 'application/json');
        response.end('{"result":{"source":"historical"}}\n');
      });
    });
    await listen(splunkServer);
    const splunkAddress = splunkServer.address();
    if (!splunkAddress || typeof splunkAddress === 'string') throw new Error('Mock Splunk server did not start.');

    const apiServer = http.createServer((request, response) => {
      void handleRuleTestApi(request, response, configFor(repository, splunkAddress.port));
    });
    await listen(apiServer);
    const apiAddress = apiServer.address();
    if (!apiAddress || typeof apiAddress === 'string') throw new Error('Mock rule-test API did not start.');

    process.env.SPLUNK_API_TOKEN = 'api-test-token';
    const runId = `ruleatlas-api-historical-${Date.now()}`;

    try {
      const runResponse = await fetch(`http://127.0.0.1:${apiAddress.port}/runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          runId,
          mode: 'historical',
          earliestTime: '-30d',
          latestTime: '-1d',
          selectedDatasetPaths: ['/datasets/does-not-exist.log'],
          rule: {
            id: 'RA-HISTORICAL',
            data: {
              rule_id: 'RA-HISTORICAL',
              name: 'Historical API test',
              platform: 'Splunk',
              query: 'index=security EventCode=4688',
            },
          },
        }),
      });

      expect(runResponse.status).toBe(201);
      const result = await runResponse.json() as {
        mode: string;
        query: string;
        earliestTime: string;
        latestTime: string;
        ingestedFiles: unknown[];
      };
      expect(result).toMatchObject({
        mode: 'historical',
        query: 'search index=security EventCode=4688',
        earliestTime: '-30d',
        latestTime: '-1d',
        ingestedFiles: [],
      });
      expect(splunkRequests).toHaveLength(1);
      expect(splunkRequests[0].url).toContain('/services/search/jobs/export');
      const search = new URLSearchParams(splunkRequests[0].body);
      expect(search.get('search')).toBe('search index=security EventCode=4688');
      expect(search.get('earliest_time')).toBe('-30d');
      expect(search.get('latest_time')).toBe('-1d');

      const statusResponse = await fetch(`http://127.0.0.1:${apiAddress.port}/runs/${runId}`);
      expect(statusResponse.status).toBe(200);
      const status = await statusResponse.json() as {
        mode: string;
        state: string;
        totalFiles: number;
        ingestedFiles: number;
        events: Array<{ message: string }>;
      };
      expect(status).toMatchObject({
        mode: 'historical',
        state: 'completed',
        totalFiles: 0,
        ingestedFiles: 0,
      });
      expect(status.events.map((event) => event.message)).toEqual(expect.arrayContaining([
        'Preparing a historical search against existing Splunk data.',
        'Searching existing Splunk data with the original rule query.',
        'Historical test completed with 1 matching result(s).',
      ]));
    } finally {
      await close(apiServer);
      await close(splunkServer);
    }
  });

  it('rejects unknown test modes before contacting Splunk', async () => {
    const repository = await mkdtemp(path.join(tmpdir(), 'ruleatlas-api-invalid-mode-'));
    temporaryDirectories.push(repository);
    const apiServer = http.createServer((request, response) => {
      void handleRuleTestApi(request, response, configFor(repository, 1));
    });
    await listen(apiServer);
    const apiAddress = apiServer.address();
    if (!apiAddress || typeof apiAddress === 'string') throw new Error('Mock rule-test API did not start.');

    try {
      const response = await fetch(`http://127.0.0.1:${apiAddress.port}/runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'production',
          rule: { id: 'RA-INVALID', data: { platform: 'Splunk', query: 'index=main' } },
        }),
      });

      expect(response.status).toBe(422);
      await expect(response.json()).resolves.toMatchObject({
        error: { code: 'invalid_test_mode' },
      });
    } finally {
      await close(apiServer);
    }
  });
});

async function createAttackDataFixture(): Promise<string> {
  const repository = await mkdtemp(path.join(tmpdir(), 'ruleatlas-api-status-'));
  temporaryDirectories.push(repository);
  const directory = path.join(repository, 'datasets', 'attack_techniques', 'T1059.003', 'test');
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, 'events.log'), 'event payload\n');
  await writeFile(path.join(directory, 'test.yml'), `
id: status-fixture
mitre_technique: [T1059.003]
datasets:
  - name: events
    path: /datasets/attack_techniques/T1059.003/test/events.log
    source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
    sourcetype: XmlWinEventLog
`);
  return repository;
}

function mockSplunkServer(): http.Server {
  return http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      response.statusCode = 200;
      response.setHeader('Content-Type', 'application/json');
      response.end(request.url?.includes('/services/collector/raw')
        ? '{"text":"Success","code":0}'
        : '{"result":{"host":"ruleatlas-api-status"}}\n');
    });
  });
}

function configFor(repository: string, splunkPort: number): RuleRepoConfig {
  const splunkUrl = `http://127.0.0.1:${splunkPort}`;
  return {
    configPath: path.join(repository, 'ruleatlas.config.json'),
    repoPathInput: repository,
    repoPath: repository,
    contentRoot: 'contents',
    contentRootPath: path.join(repository, 'contents'),
    githubRemote: 'origin',
    githubBaseBranch: 'main',
    attackDataPathInput: repository,
    attackDataPath: repository,
    attackDataMaxDatasets: 5,
    splunkHecUrl: splunkUrl,
    splunkApiUrl: splunkUrl,
    splunkIndex: 'attack_data',
    splunkVerifyTls: true,
  };
}

function listen(server: http.Server): Promise<void> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
}

function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
