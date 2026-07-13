import { ApiError } from './http';
import type { RuleTestRunResult } from './splunkTestEngine';

export type RuleTestRunPhase = 'preparing' | 'fetching' | 'ingesting' | 'searching' | 'complete' | 'failed';
export type RuleTestRunState = 'running' | 'completed' | 'failed';
export type RuleTestRunEventLevel = 'info' | 'success' | 'warning' | 'error';

export interface RuleTestRunEvent {
  id: number;
  timestamp: string;
  phase: RuleTestRunPhase;
  level: RuleTestRunEventLevel;
  message: string;
  detail?: string;
}

export interface RuleTestRunStatus {
  runId: string;
  ruleId: string;
  ruleName: string;
  state: RuleTestRunState;
  phase: RuleTestRunPhase;
  startedAt: string;
  updatedAt: string;
  completedAt?: string;
  selectionMode?: 'explicit' | 'mapping';
  totalFiles: number;
  filesRequiringFetch: number;
  fetchedFiles: number;
  ingestedFiles: number;
  searchAttempt: number;
  searchAttempts: number;
  resultCount: number;
  passed?: boolean;
  error?: {
    code: string;
    message: string;
  };
  events: RuleTestRunEvent[];
}

interface StatusPatch {
  phase?: RuleTestRunPhase;
  selectionMode?: RuleTestRunStatus['selectionMode'];
  totalFiles?: number;
  filesRequiringFetch?: number;
  fetchedFiles?: number;
  ingestedFiles?: number;
  searchAttempt?: number;
  searchAttempts?: number;
  resultCount?: number;
}

interface StatusEventInput {
  phase: RuleTestRunPhase;
  level: RuleTestRunEventLevel;
  message: string;
  detail?: string;
}

const maximumStoredRuns = 25;
const maximumEventsPerRun = 100;
const statuses = new Map<string, RuleTestRunStatus>();
let nextEventId = 1;

export function createRuleTestRunStatus(
  runId: string,
  ruleId: string,
  ruleName: string,
): RuleTestRunStatus {
  const now = new Date().toISOString();
  const status: RuleTestRunStatus = {
    runId,
    ruleId,
    ruleName,
    state: 'running',
    phase: 'preparing',
    startedAt: now,
    updatedAt: now,
    totalFiles: 0,
    filesRequiringFetch: 0,
    fetchedFiles: 0,
    ingestedFiles: 0,
    searchAttempt: 0,
    searchAttempts: 0,
    resultCount: 0,
    events: [eventFor({
      phase: 'preparing',
      level: 'info',
      message: 'Preparing the rule test and attack-data selection.',
    }, now)],
  };
  statuses.set(runId, status);
  trimStoredRuns();
  return status;
}

export function updateRuleTestRunStatus(
  runId: string,
  patch: StatusPatch,
  event?: StatusEventInput,
): RuleTestRunStatus {
  const current = requireStatus(runId);
  const now = new Date().toISOString();
  const events = event
    ? [...current.events, eventFor(event, now)].slice(-maximumEventsPerRun)
    : current.events;
  const next: RuleTestRunStatus = {
    ...current,
    ...patch,
    updatedAt: now,
    events,
  };
  statuses.set(runId, next);
  return next;
}

export function completeRuleTestRunStatus(
  runId: string,
  result: RuleTestRunResult,
): RuleTestRunStatus {
  const current = requireStatus(runId);
  const now = result.completedAt;
  const next: RuleTestRunStatus = {
    ...current,
    state: 'completed',
    phase: 'complete',
    updatedAt: now,
    completedAt: now,
    ingestedFiles: result.ingestedFiles.length,
    searchAttempt: result.searchAttempts,
    searchAttempts: result.searchAttempts,
    resultCount: result.resultCount,
    passed: result.passed,
    events: [...current.events, eventFor({
      phase: 'complete',
      level: result.passed ? 'success' : 'warning',
      message: result.passed
        ? `Test completed with ${result.resultCount} matching result(s).`
        : 'Test completed after ingestion, but the rule returned no results.',
    }, now)].slice(-maximumEventsPerRun),
  };
  statuses.set(runId, next);
  return next;
}

export function failRuleTestRunStatus(runId: string, error: unknown): RuleTestRunStatus {
  const current = requireStatus(runId);
  const now = new Date().toISOString();
  const failure = error instanceof ApiError
    ? { code: error.code, message: error.message }
    : { code: 'internal_error', message: error instanceof Error ? error.message : 'Unexpected rule-test failure.' };
  const next: RuleTestRunStatus = {
    ...current,
    state: 'failed',
    phase: 'failed',
    updatedAt: now,
    completedAt: now,
    error: failure,
    events: [...current.events, eventFor({
      phase: 'failed',
      level: 'error',
      message: failure.message,
      detail: failure.code,
    }, now)].slice(-maximumEventsPerRun),
  };
  statuses.set(runId, next);
  return next;
}

export function getRuleTestRunStatus(runId: string): RuleTestRunStatus | null {
  return statuses.get(runId) ?? null;
}

function requireStatus(runId: string): RuleTestRunStatus {
  const status = statuses.get(runId);
  if (!status) {
    throw new ApiError(404, 'test_run_not_found', `Rule-test run ${runId} was not found.`);
  }
  return status;
}

function eventFor(input: StatusEventInput, timestamp: string): RuleTestRunEvent {
  return {
    id: nextEventId++,
    timestamp,
    ...input,
  };
}

function trimStoredRuns(): void {
  while (statuses.size > maximumStoredRuns) {
    const oldestRunId = statuses.keys().next().value as string | undefined;
    if (!oldestRunId) {
      return;
    }
    statuses.delete(oldestRunId);
  }
}
