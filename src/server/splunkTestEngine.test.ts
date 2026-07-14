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
    const requests: Array<{ url: string; authorization: string; body: string }> = [];
    const progress: SplunkTestProgress[] = [];
    const server = http.createServer((request, response) => {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk: string) => {
        body += chunk;
      });
      request.on('end', () => {
        requests.push({
          url: request.url ?? '',
          authorization: String(request.headers.authorization ?? ''),
          body,
        });
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
          query: 'index=production EventCode=1 | stats count',
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
        mode: 'attack_data',
        runId: 'ruleatlas-test-run',
        onProgress: (event) => progress.push(event),
      });

      expect(result.passed).toBe(true);
      expect(result.mode).toBe('attack_data');
      expect(result.selectionMode).toBe('mapping');
      expect(result.resultCount).toBe(1);
      expect(result.query).toBe('search index="attack_data" EventCode=1 host="ruleatlas-test-run" | stats count');
      expect(result.originalQuery).toBe('index=production EventCode=1 | stats count');
      expect(result.testIndex).toBe('attack_data');
      expect(result.earliestTime).toBe('-5m');
      expect(result.latestTime).toBe('now');
      expect(requests).toHaveLength(3);
      expect(requests[0].authorization).toBe('Splunk hec-test-token');
      expect(requests[1].authorization).toBe('Splunk api-test-token');
      expect(new URLSearchParams(requests[1].body).get('earliest_time')).toBe('-5m');
      expect(new URLSearchParams(requests[1].body).get('latest_time')).toBe('now');
      expect(new URLSearchParams(requests[2].body).get('search')).toBe(
        'search index="attack_data" host="ruleatlas-test-run" | delete',
      );
      expect(result.cleanupSucceeded).toBe(true);
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

  it('overrides the base index, scopes standard searches, and counts only result objects', () => {
    expect(scopeSplunkQuery('index=main | stats count', 'run-1', 'attack_data')).toEqual({
      query: 'search index="attack_data" host="run-1" | stats count',
      scoped: true,
      indexOverridden: true,
    });
    expect(scopeSplunkQuery('sourcetype=sysmon | stats count', 'run-2', 'attack_data')).toEqual({
      query: 'search sourcetype=sysmon index="attack_data" host="run-2" | stats count',
      scoped: true,
      indexOverridden: true,
    });
    expect(scopeSplunkQuery('index IN (main, security) EventCode=1', 'run-3', 'attack_data')).toEqual({
      query: 'search index="attack_data" EventCode=1 host="run-3"',
      scoped: true,
      indexOverridden: true,
    });
    expect(scopeSplunkQuery('| tstats count where index=main', 'run-4', 'attack_data')).toEqual({
      query: '| tstats count where index=main',
      scoped: false,
      indexOverridden: false,
    });
    expect(parseSplunkExportResults('{"result":{"x":1}}\n{"preview":false}\nnot-json')).toBe(1);
  });

  it('searches historical data with the original index and without HEC credentials', async () => {
    const requests: Array<{ url: string; body: string }> = [];
    const progress: SplunkTestProgress[] = [];
    const server = http.createServer((request, response) => {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk: string) => {
        body += chunk;
      });
      request.on('end', () => {
        requests.push({ url: request.url ?? '', body });
        response.statusCode = 200;
        response.setHeader('Content-Type', 'application/json');
        response.end('{"result":{"source":"historical"}}\n');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('Mock Splunk server did not start.');
      process.env.SPLUNK_API_TOKEN = 'api-test-token';

      const result = await executeSplunkRuleTest(configFor(tmpdir(), address.port), {
        id: 'RA-HISTORICAL',
        data: {
          rule_id: 'RA-HISTORICAL',
          name: 'Historical process test',
          platform: 'Splunk',
          query: 'index=security EventCode=4688 | stats count',
        },
      }, {
        mode: 'historical',
        earliestTime: '-7d',
        latestTime: 'now',
        runId: 'ruleatlas-historical-run',
        onProgress: (event) => progress.push(event),
      });

      expect(result).toMatchObject({
        mode: 'historical',
        passed: true,
        query: 'search index=security EventCode=4688 | stats count',
        originalQuery: 'index=security EventCode=4688 | stats count',
        queryScoped: false,
        earliestTime: '-7d',
        latestTime: 'now',
        searchAttempts: 1,
        pulledAttackData: false,
        selectedManifests: [],
        ingestedFiles: [],
      });
      expect(requests).toHaveLength(1);
      expect(requests[0].url).toContain('/services/search/jobs/export');
      const search = new URLSearchParams(requests[0].body);
      expect(search.get('search')).toBe('search index=security EventCode=4688 | stats count');
      expect(search.get('earliest_time')).toBe('-7d');
      expect(search.get('latest_time')).toBe('now');
      expect(progress.map((event) => event.type)).toEqual(['search_started', 'search_attempt']);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
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
