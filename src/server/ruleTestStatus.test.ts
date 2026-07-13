import { describe, expect, it } from 'vitest';
import { ApiError } from './http';
import {
  completeRuleTestRunStatus,
  createRuleTestRunStatus,
  failRuleTestRunStatus,
  getRuleTestRunStatus,
  updateRuleTestRunStatus,
} from './ruleTestStatus';

describe('rule-test run status', () => {
  it('keeps ordered fetch, ingest, and search checkpoints through completion', () => {
    const runId = `status-complete-${Date.now()}`;
    createRuleTestRunStatus(runId, 'RA-1', 'Replay test');
    updateRuleTestRunStatus(runId, {
      phase: 'fetching',
      totalFiles: 2,
      filesRequiringFetch: 1,
    }, {
      phase: 'fetching',
      level: 'info',
      message: 'Fetching one file with Git LFS.',
    });
    updateRuleTestRunStatus(runId, {
      phase: 'ingesting',
      fetchedFiles: 1,
      ingestedFiles: 2,
    }, {
      phase: 'ingesting',
      level: 'success',
      message: 'Splunk HEC accepted both files.',
    });

    const completed = completeRuleTestRunStatus(runId, {
      runId,
      ruleId: 'RA-1',
      ruleName: 'Replay test',
      startedAt: '2026-07-13T00:00:00.000Z',
      completedAt: '2026-07-13T00:00:02.000Z',
      durationMs: 2_000,
      passed: true,
      mode: 'attack_data',
      originalQuery: 'index=main',
      query: 'search index=attack_data host="status-complete"',
      queryScoped: true,
      indexOverridden: true,
      testIndex: 'attack_data',
      earliestTime: '-5m',
      latestTime: 'now',
      resultCount: 3,
      searchAttempts: 2,
      pulledAttackData: true,
      selectionMode: 'explicit',
      selectedManifests: [],
      ingestedFiles: [
        { name: 'one', path: '/one.log', source: 'test', sourcetype: '_json', bytes: 10 },
        { name: 'two', path: '/two.log', source: 'test', sourcetype: '_json', bytes: 20 },
      ],
      warnings: [],
    });

    expect(completed).toMatchObject({
      state: 'completed',
      phase: 'complete',
      fetchedFiles: 1,
      ingestedFiles: 2,
      searchAttempt: 2,
      resultCount: 3,
      passed: true,
    });
    expect(completed.events.map((event) => event.phase)).toEqual([
      'preparing',
      'fetching',
      'ingesting',
      'complete',
    ]);
    expect(new Set(completed.events.map((event) => event.id)).size).toBe(completed.events.length);
  });

  it('persists an operational error as a terminal status event', () => {
    const runId = `status-failed-${Date.now()}`;
    createRuleTestRunStatus(runId, 'RA-2', 'Failed replay');

    const failed = failRuleTestRunStatus(
      runId,
      new ApiError(502, 'attack_data_pull_failed', 'Unable to pull selected Git LFS data.'),
    );

    expect(failed.state).toBe('failed');
    expect(failed.error).toEqual({
      code: 'attack_data_pull_failed',
      message: 'Unable to pull selected Git LFS data.',
    });
    expect(failed.events.at(-1)).toMatchObject({
      phase: 'failed',
      level: 'error',
      detail: 'attack_data_pull_failed',
    });
    expect(getRuleTestRunStatus(runId)).toEqual(failed);
  });
});
