import type { IncomingMessage, ServerResponse } from 'node:http';
import type { RuleRepoConfig } from './ruleRepoPlugin';
import { discoverAttackData, listAttackData, pullAttackDataFiles } from './attackData';
import type { AttackDataPullProgress, RuleTestInput } from './attackData';
import { ApiError, assertObject, readJsonBody, requestPath, sendApiError, sendJson } from './http';
import { assertSplunkTestConfigured, executeSplunkRuleTest } from './splunkTestEngine';
import type { RuleTestMode, RuleTestRunResult, SplunkTestProgress } from './splunkTestEngine';
import {
  completeRuleTestRunStatus,
  createRuleTestRunStatus,
  failRuleTestRunStatus,
  getRuleTestRunStatus,
  updateRuleTestRunStatus,
} from './ruleTestStatus';

let testRunActive = false;

export async function handleRuleTestApi(
  request: IncomingMessage,
  response: ServerResponse,
  config: RuleRepoConfig,
) {
  try {
    const pathname = requestPath(request);
    if (pathname === '/datasets' && request.method === 'GET') {
      sendJson(response, 200, await listAttackData(config.attackDataPath, config.attackDataMaxDatasets));
      return;
    }

    if (pathname.startsWith('/runs/') && request.method === 'GET') {
      const runId = parseRunId(decodeURIComponent(pathname.slice('/runs/'.length)));
      const status = getRuleTestRunStatus(runId);
      if (!status) {
        throw new ApiError(404, 'test_run_not_found', `Rule-test run ${runId} was not found.`);
      }
      sendJson(response, 200, status);
      return;
    }

    if (request.method !== 'POST') {
      throw new ApiError(405, 'method_not_allowed', 'Rule-test operation does not support this method.');
    }

    if (pathname === '/preview') {
      const payload = assertObject(await readJsonBody(request));
      const rule = parseRule(payload.rule);
      const discovery = await discoverAttackData(
        config.attackDataPath,
        rule,
        config.attackDataMaxDatasets,
        parseSelectedDatasetPaths(payload.selectedDatasetPaths),
      );
      sendJson(response, 200, discovery);
      return;
    }

    if (pathname === '/runs') {
      if (testRunActive) {
        throw new ApiError(409, 'test_run_active', 'Another Splunk rule test is already running.');
      }
      testRunActive = true;
      let runId: string | null = null;
      try {
        const payload = assertObject(await readJsonBody(request));
        const rule = parseRule(payload.rule);
        const identity = ruleIdentity(rule);
        const mode = parseRuleTestMode(payload.mode);
        runId = parseRunId(payload.runId, identity.ruleId);
        createRuleTestRunStatus(runId, identity.ruleId, identity.ruleName, mode);
        assertSplunkTestConfigured(config, mode);
        let result: RuleTestRunResult;
        if (mode === 'historical') {
          result = await executeSplunkRuleTest(config, rule, {
            mode,
            earliestTime: parseSplunkTime(payload.earliestTime, '-24h', 'earliestTime'),
            latestTime: parseSplunkTime(payload.latestTime, 'now', 'latestTime'),
            runId,
            onProgress: (progress) => recordSplunkProgress(runId as string, progress, mode),
          });
        } else {
          const discovery = await discoverAttackData(
            config.attackDataPath,
            rule,
            config.attackDataMaxDatasets,
            parseSelectedDatasetPaths(payload.selectedDatasetPaths),
          );
          if (discovery.matches.length === 0) {
            throw new ApiError(422, 'attack_data_not_found', 'No attack-data datasets were selected or matched to the rule.', {
              scannedManifests: discovery.scannedManifests,
            });
          }
          const totalFiles = discovery.matches.reduce((count, match) => count + match.datasets.length, 0);
          updateRuleTestRunStatus(runId, {
            selectionMode: discovery.selectionMode,
            totalFiles,
          }, {
            phase: 'preparing',
            level: 'success',
            message: `Selected ${totalFiles} dataset file(s) from ${discovery.matches.length} manifest(s).`,
            detail: discovery.selectionMode === 'explicit' ? 'Explicit dataset selection' : 'Mapping fallback',
          });
          const materialized = await pullAttackDataFiles(
            config.attackDataPath,
            discovery.matches,
            (progress) => recordPullProgress(runId as string, progress),
          );
          result = await executeSplunkRuleTest(config, rule, {
            mode,
            discovery,
            files: materialized.files,
            pulledAttackData: materialized.pulled,
            runId,
            onProgress: (progress) => recordSplunkProgress(runId as string, progress, mode),
          });
        }
        completeRuleTestRunStatus(runId, result);
        sendJson(response, 201, result);
      } catch (error) {
        if (runId && getRuleTestRunStatus(runId)?.state === 'running') {
          failRuleTestRunStatus(runId, error);
        }
        throw error;
      } finally {
        testRunActive = false;
      }
      return;
    }

    throw new ApiError(404, 'route_not_found', 'Rule-test operation was not found.');
  } catch (error) {
    sendApiError(response, error);
  }
}

function parseRule(value: unknown): RuleTestInput {
  const rule = assertObject(value, 'invalid_rule');
  if (!rule.data || typeof rule.data !== 'object' || Array.isArray(rule.data)) {
    throw new ApiError(422, 'invalid_rule', 'Rule must include a data object.');
  }
  return rule as RuleTestInput;
}

function parseSelectedDatasetPaths(value: unknown): string[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new ApiError(422, 'invalid_dataset_selection', 'Selected dataset paths must be an array of strings.');
  }
  return value;
}

function parseRuleTestMode(value: unknown): RuleTestMode {
  if (value === undefined || value === 'attack_data') {
    return 'attack_data';
  }
  if (value === 'historical') {
    return value;
  }
  throw new ApiError(422, 'invalid_test_mode', 'Rule-test mode must be attack_data or historical.');
}

function parseSplunkTime(value: unknown, fallback: string, field: string): string {
  if (value === undefined) {
    return fallback;
  }
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed || parsed.length > 128 || /[\r\n\0]/.test(parsed)) {
    throw new ApiError(422, 'invalid_time_range', `${field} must be a valid non-empty Splunk time value.`);
  }
  return parsed;
}

function parseRunId(value: unknown, fallbackRuleId = 'rule'): string {
  const generated = `ruleatlas-${slug(fallbackRuleId)}-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const runId = value === undefined ? generated : typeof value === 'string' ? value.trim() : '';
  if (!runId || runId.length > 128 || !/^[a-zA-Z0-9_-]+$/.test(runId)) {
    throw new ApiError(422, 'invalid_run_id', 'Rule-test run ID must contain only letters, numbers, underscores, or hyphens.');
  }
  return runId;
}

function ruleIdentity(rule: RuleTestInput): { ruleId: string; ruleName: string } {
  const data = rule.data ?? {};
  const ruleId = stringValue(data.rule_id) || stringValue(rule.id) || 'rule';
  return {
    ruleId,
    ruleName: stringValue(data.name) || ruleId,
  };
}

function recordPullProgress(runId: string, progress: AttackDataPullProgress): void {
  if (progress.type === 'checking') {
    updateRuleTestRunStatus(runId, {
      phase: 'fetching',
      totalFiles: progress.totalFiles,
    }, {
      phase: 'fetching',
      level: 'info',
      message: `Checking ${progress.totalFiles} selected file(s) in the attack_data checkout.`,
    });
    return;
  }
  if (progress.type === 'fetching') {
    updateRuleTestRunStatus(runId, {
      phase: 'fetching',
      filesRequiringFetch: progress.paths.length,
    }, {
      phase: 'fetching',
      level: 'info',
      message: `Fetching ${progress.paths.length} file(s) with Git LFS.`,
      detail: `git lfs pull --include=${progress.paths.join(',')}`,
    });
    return;
  }
  if (progress.type === 'fetched') {
    updateRuleTestRunStatus(runId, {
      phase: 'fetching',
      fetchedFiles: progress.paths.length,
    }, {
      phase: 'fetching',
      level: 'success',
      message: `Git LFS fetched ${progress.paths.length} selected file(s).`,
    });
    return;
  }

  updateRuleTestRunStatus(runId, {
    phase: 'ingesting',
    fetchedFiles: progress.fetchedFiles,
  }, {
    phase: 'fetching',
    level: 'success',
    message: progress.fetchedFiles > 0
      ? 'Selected attack-data files are materialized and ready for replay.'
      : 'Selected attack-data files were already materialized; no Git LFS fetch was needed.',
  });
}

function recordSplunkProgress(
  runId: string,
  progress: SplunkTestProgress,
  mode: RuleTestMode = 'attack_data',
): void {
  if (progress.type === 'ingest_started') {
    updateRuleTestRunStatus(runId, { phase: 'ingesting' }, {
      phase: 'ingesting',
      level: 'info',
      message: `Sending dataset ${progress.currentFile}/${progress.totalFiles}: ${progress.file.name}.`,
      detail: `${progress.file.path} · index=${progress.index} · source=${progress.file.source} · sourcetype=${progress.file.sourcetype} · ${progress.bytes} bytes`,
    });
    return;
  }
  if (progress.type === 'ingest_accepted') {
    updateRuleTestRunStatus(runId, {
      phase: 'ingesting',
      ingestedFiles: progress.currentFile,
    }, {
      phase: 'ingesting',
      level: 'success',
      message: `Splunk HEC accepted ${progress.file.name}.`,
      detail: `HTTP ${progress.statusCode}${progress.hecCode === undefined ? '' : ` · HEC code=${progress.hecCode}`}${progress.hecText ? ` · ${progress.hecText}` : ''}`,
    });
    return;
  }
  if (progress.type === 'search_started') {
    updateRuleTestRunStatus(runId, {
      phase: 'searching',
      searchAttempts: progress.totalAttempts,
    }, {
      phase: 'searching',
      level: 'info',
      message: mode === 'historical'
        ? 'Searching existing Splunk data with the original rule query.'
        : 'Ingestion requests completed; checking when the replayed events become searchable.',
      detail: mode === 'historical'
        ? 'No attack-data files were ingested and the original index constraints are preserved.'
        : progress.queryScoped
          ? 'Search is scoped to this run host and the configured test index.'
          : 'Generating search could not be scoped to the run host or test index.',
    });
    return;
  }

  updateRuleTestRunStatus(runId, {
    phase: 'searching',
    searchAttempt: progress.attempt,
    searchAttempts: progress.totalAttempts,
    resultCount: progress.resultCount,
  }, {
    phase: 'searching',
    level: progress.resultCount > 0 ? 'success' : 'warning',
    message: mode === 'historical'
      ? progress.resultCount > 0
        ? `Historical search found ${progress.resultCount} result(s).`
        : 'Historical search returned no results.'
      : progress.resultCount > 0
        ? `Search attempt ${progress.attempt}/${progress.totalAttempts} found ${progress.resultCount} result(s).`
        : `Search attempt ${progress.attempt}/${progress.totalAttempts} returned no results yet.`,
  });
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : '';
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'rule';
}
