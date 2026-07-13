import type { TemplateRecord } from '../types';
import { requestJson } from './api';

const ruleTestApi = '/api/rule-tests';

export interface AttackDatasetFile {
  name: string;
  path: string;
  source: string;
  sourcetype: string;
  localPath: string;
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
  query: string;
  queryScoped: boolean;
  resultCount: number;
  searchAttempts: number;
  pulledAttackData: boolean;
  selectionMode: 'explicit' | 'mapping';
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

export function runRuleTest(
  rule: TemplateRecord,
  selectedDatasetPaths: string[] = [],
  runId?: string,
): Promise<RuleTestRunResult> {
  return requestJson(`${ruleTestApi}/runs`, {
    body: JSON.stringify({ rule, selectedDatasetPaths, ...(runId ? { runId } : {}) }),
    method: 'POST',
  });
}

export function getRuleTestRunStatus(runId: string): Promise<RuleTestRunStatus> {
  return requestJson(`${ruleTestApi}/runs/${encodeURIComponent(runId)}`);
}
