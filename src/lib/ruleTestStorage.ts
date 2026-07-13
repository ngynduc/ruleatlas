import type { TemplateRecord } from '../types';
import type { AttackDataPreview, RuleTestRunResult, RuleTestRunStatus } from './ruleTestApi';

const storageKey = 'ruleatlas.rule-test.v1';

export interface RuleTestWorkspaceState {
  version: 1;
  testName: string;
  notes: string;
  rule: TemplateRecord | null;
  selectedDatasetPaths: string[];
  preview: AttackDataPreview | null;
  result: RuleTestRunResult | null;
  runStatus: RuleTestRunStatus | null;
  updatedAt: string | null;
}

export function emptyRuleTestWorkspace(): RuleTestWorkspaceState {
  return {
    version: 1,
    testName: '',
    notes: '',
    rule: null,
    selectedDatasetPaths: [],
    preview: null,
    result: null,
    runStatus: null,
    updatedAt: null,
  };
}

export function loadRuleTestWorkspace(
  storage: Pick<Storage, 'getItem'> = window.localStorage,
): RuleTestWorkspaceState {
  const raw = storage.getItem(storageKey);
  if (!raw) {
    return emptyRuleTestWorkspace();
  }

  try {
    return normalizeRuleTestWorkspace(JSON.parse(raw));
  } catch {
    return emptyRuleTestWorkspace();
  }
}

export function saveRuleTestWorkspace(
  state: RuleTestWorkspaceState,
  storage: Pick<Storage, 'setItem'> = window.localStorage,
): void {
  storage.setItem(storageKey, JSON.stringify(normalizeRuleTestWorkspace(state), null, 2));
}

export function normalizeRuleTestWorkspace(value: unknown): RuleTestWorkspaceState {
  if (!isObject(value)) {
    return emptyRuleTestWorkspace();
  }

  return {
    version: 1,
    testName: stringValue(value.testName),
    notes: stringValue(value.notes),
    rule: isTemplateRecord(value.rule) ? value.rule : null,
    selectedDatasetPaths: uniqueStrings(value.selectedDatasetPaths),
    preview: isAttackDataPreview(value.preview) ? value.preview : null,
    result: isRuleTestRunResult(value.result) ? value.result : null,
    runStatus: isRuleTestRunStatus(value.runStatus) ? value.runStatus : null,
    updatedAt: typeof value.updatedAt === 'string' ? value.updatedAt : null,
  };
}

function isTemplateRecord(value: unknown): value is TemplateRecord {
  return isObject(value)
    && typeof value.id === 'string'
    && isObject(value.data)
    && typeof value.archived === 'boolean'
    && typeof value.createdAt === 'string'
    && typeof value.updatedAt === 'string';
}

function uniqueStrings(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return [...new Set(value
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean))];
}

function isAttackDataPreview(value: unknown): value is AttackDataPreview {
  return isObject(value)
    && Array.isArray(value.matches)
    && typeof value.scannedManifests === 'number'
    && (value.selectionMode === 'explicit' || value.selectionMode === 'mapping')
    && Array.isArray(value.warnings);
}

function isRuleTestRunResult(value: unknown): value is RuleTestRunResult {
  return isObject(value)
    && typeof value.runId === 'string'
    && typeof value.passed === 'boolean'
    && typeof value.resultCount === 'number'
    && typeof value.durationMs === 'number'
    && (value.selectionMode === 'explicit' || value.selectionMode === 'mapping')
    && Array.isArray(value.ingestedFiles)
    && Array.isArray(value.selectedManifests)
    && Array.isArray(value.warnings);
}

function isRuleTestRunStatus(value: unknown): value is RuleTestRunStatus {
  return isObject(value)
    && typeof value.runId === 'string'
    && typeof value.ruleId === 'string'
    && (value.state === 'running' || value.state === 'completed' || value.state === 'failed')
    && typeof value.phase === 'string'
    && typeof value.startedAt === 'string'
    && typeof value.updatedAt === 'string'
    && typeof value.totalFiles === 'number'
    && typeof value.filesRequiringFetch === 'number'
    && typeof value.fetchedFiles === 'number'
    && typeof value.ingestedFiles === 'number'
    && typeof value.searchAttempt === 'number'
    && typeof value.searchAttempts === 'number'
    && typeof value.resultCount === 'number'
    && Array.isArray(value.events);
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
