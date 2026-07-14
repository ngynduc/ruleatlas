import type { TemplateRecord } from '../types';
import { requestJson } from './api';

const ruleTestApi = '/api/rule-tests';

export type RuleTestMode = 'attack_data' | 'historical';

export interface AttackDatasetFile {
  name: string;
  path: string;
  source: string;
  sourcetype: string;
  localPath: string;
  sha256?: string;
}

export interface AttackDataMatch extends Record<string, unknown> {
  id: string;
  manifestPath: string;
  description: string;
  environment: string;
  techniques: string[];
  matchedTechniques: string[];
  matchedTags: string[];
  score: number;
  datasets: AttackDatasetFile[];
}

export interface AttackDataPreview {
  matches: AttackDataMatch[];
  scannedManifests: number;
  selectionMode: 'explicit' | 'mapping';
  warnings: string[];
}

export interface AttackDataCatalogEntry extends Record<string, unknown> {
  id: string;
  manifestId: string;
  manifestPath: string;
  description: string;
  environment: string;
  techniques: string[];
  name: string;
  path: string;
  source: string;
  sourcetype: string;
  sha256?: string;
}

export interface AttackDataCatalog {
  datasets: AttackDataCatalogEntry[];
  maxDatasets: number;
  scannedManifests: number;
  warnings: string[];
}

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
  cleanupSucceeded?: boolean;
  pulledAttackData: boolean;
  selectionMode?: 'explicit' | 'mapping';
  selectedManifests: AttackDataMatch[];
  ingestedFiles: Array<{
    name: string;
    path: string;
    source: string;
    sourcetype: string;
    bytes: number;
  }>;
  warnings: string[];
}

export type RuleTestRunPhase = 'preparing' | 'fetching' | 'ingesting' | 'searching' | 'complete' | 'failed';

export interface RuleTestRunEvent {
  id: number;
  timestamp: string;
  phase: RuleTestRunPhase;
  level: 'info' | 'success' | 'warning' | 'error';
  message: string;
  detail?: string;
}

export interface RuleTestRunStatus {
  runId: string;
  ruleId: string;
  ruleName: string;
  mode: RuleTestMode;
  state: 'running' | 'completed' | 'failed';
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

export function listAttackDataCatalog(): Promise<AttackDataCatalog> {
  return requestJson(`${ruleTestApi}/datasets`);
}

export function previewRuleAttackData(
  rule: TemplateRecord,
  selectedDatasetPaths: string[] = [],
): Promise<AttackDataPreview> {
  return requestJson(`${ruleTestApi}/preview`, {
    body: JSON.stringify({ rule, selectedDatasetPaths }),
    method: 'POST',
  });
}

export interface RunRuleTestOptions {
  mode?: RuleTestMode;
  selectedDatasetPaths?: string[];
  runId?: string;
  earliestTime?: string;
  latestTime?: string;
}

export function runRuleTest(
  rule: TemplateRecord,
  selectedDatasetPathsOrOptions: string[] | RunRuleTestOptions = [],
  legacyRunId?: string,
): Promise<RuleTestRunResult> {
  const options: RunRuleTestOptions = Array.isArray(selectedDatasetPathsOrOptions)
    ? { selectedDatasetPaths: selectedDatasetPathsOrOptions, runId: legacyRunId }
    : selectedDatasetPathsOrOptions;
  return requestJson(`${ruleTestApi}/runs`, {
    body: JSON.stringify({
      rule,
      mode: options.mode ?? 'attack_data',
      selectedDatasetPaths: options.selectedDatasetPaths ?? [],
      ...(options.runId ? { runId: options.runId } : {}),
      ...(options.earliestTime ? { earliestTime: options.earliestTime } : {}),
      ...(options.latestTime ? { latestTime: options.latestTime } : {}),
    }),
    method: 'POST',
  });
}

export function getRuleTestRunStatus(runId: string): Promise<RuleTestRunStatus> {
  return requestJson(`${ruleTestApi}/runs/${encodeURIComponent(runId)}`);
}
