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
              query: 'index=attack_data EventCode=1',
            },
          },
        }),
      });
      expect(runResponse.status).toBe(201);

      const statusResponse = await fetch(`http://127.0.0.1:${apiAddress.port}/runs/${runId}`);
      expect(statusResponse.status).toBe(200);
      const status = await statusResponse.json() as {
        state: string;
        ingestedFiles: number;
        resultCount: number;
        events: Array<{ message: string }>;
      };

      expect(status).toMatchObject({
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
