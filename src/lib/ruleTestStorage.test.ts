import { describe, expect, it } from 'vitest';
import {
  emptyRuleTestWorkspace,
  loadRuleTestWorkspace,
  normalizeRuleTestWorkspace,
  saveRuleTestWorkspace,
} from './ruleTestStorage';

describe('rule-test workspace storage', () => {
  it('normalizes persisted test information and removes duplicate dataset paths', () => {
    const state = normalizeRuleTestWorkspace({
      version: 99,
      testName: 'Credential test',
      notes: 'Expected one result',
      selectedDatasetPaths: ['/datasets/a.log', ' /datasets/a.log ', 42],
      updatedAt: '2026-07-13T00:00:00.000Z',
    });

    expect(state.version).toBe(1);
    expect(state.testName).toBe('Credential test');
    expect(state.notes).toBe('Expected one result');
    expect(state.selectedDatasetPaths).toEqual(['/datasets/a.log']);
  });

  it('returns an empty workspace for invalid stored data', () => {
    expect(normalizeRuleTestWorkspace('invalid')).toEqual(emptyRuleTestWorkspace());
  });

  it('drops incomplete preview, result, and run status objects that would break the page', () => {
    const state = normalizeRuleTestWorkspace({ preview: {}, result: {}, runStatus: {} });

    expect(state.preview).toBeNull();
    expect(state.result).toBeNull();
    expect(state.runStatus).toBeNull();
  });

  it('keeps a completed replay status so ingest failures and acknowledgements survive reloads', () => {
    const runStatus = {
      runId: 'ruleatlas-ui-1',
      ruleId: 'RA-1',
      ruleName: 'Replay test',
      state: 'completed',
      phase: 'complete',
      startedAt: '2026-07-13T00:00:00.000Z',
      updatedAt: '2026-07-13T00:00:02.000Z',
      totalFiles: 1,
      filesRequiringFetch: 1,
      fetchedFiles: 1,
      ingestedFiles: 1,
      searchAttempt: 1,
      searchAttempts: 1,
      resultCount: 1,
      passed: true,
      events: [{
        id: 1,
        timestamp: '2026-07-13T00:00:01.000Z',
        phase: 'ingesting',
        level: 'success',
        message: 'Splunk HEC accepted events.log.',
      }],
    };

    expect(normalizeRuleTestWorkspace({ runStatus }).runStatus).toEqual(runStatus);
  });

  it('round-trips the current test setup through browser-style storage', () => {
    let stored = '';
    const storage = {
      getItem: () => stored || null,
      setItem: (_key: string, value: string) => {
        stored = value;
      },
    };
    const state = {
      ...emptyRuleTestWorkspace(),
      testName: 'Stored test',
      notes: 'Keep this context',
      selectedDatasetPaths: ['/datasets/selected.log'],
    };

    saveRuleTestWorkspace(state, storage);

    expect(loadRuleTestWorkspace(storage)).toEqual(state);
  });
});
