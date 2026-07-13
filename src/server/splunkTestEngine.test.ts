import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { executeSplunkRuleTest, parseSplunkExportResults, scopeSplunkQuery } from './splunkTestEngine';
import type { SplunkTestProgress } from './splunkTestEngine';
import type { RuleRepoConfig } from './ruleRepoPlugin';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })));
  delete process.env.SPLUNK_HEC_TOKEN;
  delete process.env.SPLUNK_API_TOKEN;
});

describe('Splunk rule test engine', () => {
  it('ingests selected data and passes when the rule search returns results', async () => {
    const requests: Array<{ url: string; authorization: string }> = [];
    const progress: SplunkTestProgress[] = [];
    const server = http.createServer((request, response) => {
      requests.push({
        url: request.url ?? '',
        authorization: String(request.headers.authorization ?? ''),
      });
      request.resume();
      request.on('end', () => {
        response.statusCode = 200;
        response.setHeader('Content-Type', 'application/json');
        response.end(request.url?.includes('/services/collector/raw')
          ? '{"text":"Success","code":0}'
          : '{"result":{"host":"ruleatlas-test"}}\n{"preview":false}\n');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('Mock Splunk server did not start.');
      const directory = await mkdtemp(path.join(tmpdir(), 'ruleatlas-splunk-'));
      temporaryDirectories.push(directory);
      const dataFile = path.join(directory, 'events.log');
      await writeFile(dataFile, 'event payload\n');
      process.env.SPLUNK_HEC_TOKEN = 'hec-test-token';
      process.env.SPLUNK_API_TOKEN = 'api-test-token';

      const result = await executeSplunkRuleTest(configFor(directory, address.port), {
        id: 'RA-TEST',
        data: {
          rule_id: 'RA-TEST',
          name: 'Scheduled task test',
          platform: 'Splunk',
          query: 'index=attack_data EventCode=1 | stats count',
        },
      }, {
        discovery: {
          scannedManifests: 1,
          selectionMode: 'mapping',
          warnings: [],
          matches: [{
            id: 'manifest-1',
            manifestPath: 'attack_techniques/T1053.005/test.yml',
            description: 'test',
            environment: 'lab',
            techniques: ['T1053.005'],
            matchedTechniques: ['T1053.005'],
            matchedTags: [],
            score: 100,
            datasets: [{
              name: 'events',
              path: '/datasets/events.log',
              source: 'Security',
              sourcetype: 'XmlWinEventLog',
              localPath: dataFile,
            }],
          }],
        },
        files: [{
          name: 'events',
          path: '/datasets/events.log',
          source: 'Security',
          sourcetype: 'XmlWinEventLog',
          localPath: dataFile,
        }],
        pulledAttackData: false,
        runId: 'ruleatlas-test-run',
        onProgress: (event) => progress.push(event),
      });

      expect(result.passed).toBe(true);
      expect(result.selectionMode).toBe('mapping');
      expect(result.resultCount).toBe(1);
      expect(result.query).toContain('host="ruleatlas-test-run"');
      expect(requests).toHaveLength(2);
      expect(requests[0].authorization).toBe('Splunk hec-test-token');
      expect(requests[1].authorization).toBe('Splunk api-test-token');
      expect(progress.map((event) => event.type)).toEqual([
        'ingest_started',
        'ingest_accepted',
        'search_started',
        'search_attempt',
      ]);
      expect(progress[1]).toMatchObject({
        type: 'ingest_accepted',
        statusCode: 200,
        hecCode: 0,
        hecText: 'Success',
      });
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it('scopes standard searches and counts only result objects', () => {
    expect(scopeSplunkQuery('index=main | stats count', 'run-1')).toEqual({
      query: 'search index=main host="run-1" | stats count',
      scoped: true,
    });
    expect(parseSplunkExportResults('{"result":{"x":1}}\n{"preview":false}\nnot-json')).toBe(1);
  });

  it('reports a HEC rejection before search and never marks the file accepted', async () => {
    let requests = 0;
    const progress: SplunkTestProgress[] = [];
    const server = http.createServer((request, response) => {
      requests += 1;
      request.resume();
      request.on('end', () => {
        response.statusCode = 200;
        response.setHeader('Content-Type', 'application/json');
        response.end('{"text":"Invalid token","code":4}');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('Mock Splunk server did not start.');
      const directory = await mkdtemp(path.join(tmpdir(), 'ruleatlas-splunk-failure-'));
      temporaryDirectories.push(directory);
      const dataFile = path.join(directory, 'events.log');
      await writeFile(dataFile, 'event payload\n');
      process.env.SPLUNK_HEC_TOKEN = 'bad-token';
      process.env.SPLUNK_API_TOKEN = 'api-test-token';

      await expect(executeSplunkRuleTest(configFor(directory, address.port), {
        id: 'RA-FAIL',
        data: {
          rule_id: 'RA-FAIL',
          platform: 'Splunk',
          query: 'index=attack_data EventCode=1',
        },
      }, {
        discovery: {
          scannedManifests: 1,
          selectionMode: 'explicit',
          warnings: [],
          matches: [],
        },
        files: [{
          name: 'events',
          path: '/datasets/events.log',
          source: 'Security',
          sourcetype: 'XmlWinEventLog',
          localPath: dataFile,
        }],
        pulledAttackData: false,
        runId: 'ruleatlas-failed-run',
        onProgress: (event) => progress.push(event),
      })).rejects.toMatchObject({ code: 'splunk_ingest_failed' });

      expect(requests).toBe(1);
      expect(progress.map((event) => event.type)).toEqual(['ingest_started']);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});

function configFor(repository: string, port: number): RuleRepoConfig {
  const baseUrl = `http://127.0.0.1:${port}`;
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
    splunkHecUrl: baseUrl,
    splunkApiUrl: baseUrl,
    splunkIndex: 'attack_data',
    splunkVerifyTls: true,
  };
}
