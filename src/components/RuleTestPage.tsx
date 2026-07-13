import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Banner,
  Button,
  Heading,
  HStack,
  Layout,
  LayoutContent,
  LayoutHeader,
  MultiSelector,
  pixel,
  proportional,
  SegmentedControl,
  SegmentedControlItem,
  Selector,
  StackItem,
  Table,
  Text,
  TextArea,
  TextInput,
  Token,
  VStack,
} from '@astryxdesign/core';
import type { TableColumn } from '@astryxdesign/core';
import {
  getRuleTestRunStatus,
  listAttackDataCatalog,
  previewRuleAttackData,
  runRuleTest,
} from '../lib/ruleTestApi';
import type {
  AttackDataCatalog,
  AttackDataCatalogEntry,
  AttackDataMatch,
  RuleTestMode,
  RuleTestRunStatus,
} from '../lib/ruleTestApi';
import {
  loadRuleTestWorkspace,
  saveRuleTestWorkspace,
} from '../lib/ruleTestStorage';
import type { RuleTestWorkspaceState } from '../lib/ruleTestStorage';
import type { TemplateRecord } from '../types';
import { RuleTestPanel } from './RuleTestPanel';
import { RuleTestStatusPanel } from './RuleTestStatusPanel';

interface RuleTestPageProps {
  rules: TemplateRecord[];
}

const datasetOptionLimit = 100;

const datasetColumns: TableColumn<AttackDataCatalogEntry>[] = [
  { key: 'name', header: 'Dataset', width: proportional(1.2, { minWidth: 180 }) },
  { key: 'manifestPath', header: 'Manifest', width: proportional(1.8, { minWidth: 240 }) },
  { key: 'source', header: 'Source', width: proportional(1, { minWidth: 140 }) },
  { key: 'sourcetype', header: 'Sourcetype', width: proportional(1, { minWidth: 160 }) },
];

const previewColumns: TableColumn<AttackDataMatch>[] = [
  { key: 'manifestPath', header: 'Manifest', width: proportional(1.7, { minWidth: 240 }) },
  {
    key: 'matchedTechniques',
    header: 'MITRE match',
    width: proportional(1, { minWidth: 130 }),
    renderCell: (match) => <Text type="supporting">{match.matchedTechniques.join(', ') || 'Explicit'}</Text>,
  },
  {
    key: 'matchedTags',
    header: 'Tag match',
    width: proportional(1, { minWidth: 130 }),
    renderCell: (match) => <Text type="supporting">{match.matchedTags.join(', ') || '—'}</Text>,
  },
  {
    key: 'datasets',
    header: 'Files',
    width: pixel(72),
    renderCell: (match) => <Text hasTabularNumbers type="supporting">{match.datasets.length}</Text>,
  },
];

export function RuleTestPage({ rules }: RuleTestPageProps) {
  const [workspace, setWorkspace] = useState<RuleTestWorkspaceState>(() => loadRuleTestWorkspace());
  const [catalog, setCatalog] = useState<AttackDataCatalog | null>(null);
  const [isCatalogLoading, setIsCatalogLoading] = useState(true);
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [datasetSearch, setDatasetSearch] = useState('');
  const activeRun = useRef<AbortController | null>(null);

  useEffect(() => {
    saveRuleTestWorkspace(workspace);
  }, [workspace]);

  useEffect(() => () => activeRun.current?.abort(), []);

  useEffect(() => {
    if (workspace.mode !== 'attack_data') {
      setIsCatalogLoading(false);
      return;
    }
    let active = true;
    setIsCatalogLoading(true);
    void listAttackDataCatalog()
      .then((nextCatalog) => {
        if (active) {
          setCatalog(nextCatalog);
          setCatalogError(null);
        }
      })
      .catch((catalogError: unknown) => {
        if (active) {
          setCatalogError(catalogError instanceof Error ? catalogError.message : 'Unable to load attack-data datasets.');
        }
      })
      .finally(() => {
        if (active) {
          setIsCatalogLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [workspace.mode]);

  const splunkRules = useMemo(
    () => rules.filter((rule) => String(rule.data.platform).toLowerCase() === 'splunk'),
    [rules],
  );
  const ruleOptions = useMemo(() => {
    const options = splunkRules.map((rule) => ({ value: rule.id, label: ruleLabel(rule) }));
    if (workspace.rule && !options.some((option) => option.value === workspace.rule?.id)) {
      options.unshift({ value: workspace.rule.id, label: `${ruleLabel(workspace.rule)} (stored snapshot)` });
    }
    return options;
  }, [splunkRules, workspace.rule]);
  const catalogDatasets = useMemo(() => uniqueCatalogDatasets(catalog?.datasets ?? []), [catalog]);
  const datasetByPath = useMemo(
    () => new Map(catalogDatasets.map((dataset) => [dataset.path, dataset])),
    [catalogDatasets],
  );
  const selectedDatasets = useMemo(
    () => workspace.selectedDatasetPaths.flatMap((datasetPath) => {
      const dataset = datasetByPath.get(datasetPath);
      return dataset ? [dataset] : [];
    }),
    [datasetByPath, workspace.selectedDatasetPaths],
  );
  const matchingDatasets = useMemo(() => {
    const query = datasetSearch.trim().toLowerCase();
    if (!query) {
      return catalogDatasets;
    }
    return catalogDatasets.filter((dataset) => [
      dataset.name,
      dataset.path,
      dataset.manifestPath,
      dataset.source,
      dataset.sourcetype,
      ...dataset.techniques,
    ].some((value) => value.toLowerCase().includes(query)));
  }, [catalogDatasets, datasetSearch]);
  const visibleDatasets = useMemo(() => {
    const byPath = new Map(selectedDatasets.map((dataset) => [dataset.path, dataset]));
    for (const dataset of matchingDatasets.slice(0, datasetOptionLimit)) {
      byPath.set(dataset.path, dataset);
    }
    return [...byPath.values()];
  }, [matchingDatasets, selectedDatasets]);
  const datasetOptions = useMemo(
    () => visibleDatasets.map((dataset) => ({
      value: dataset.path,
      label: `${dataset.name} · ${dataset.techniques.join(', ') || 'No MITRE'} · ${dataset.manifestPath}`,
    })),
    [visibleDatasets],
  );

  const updateWorkspace = (changes: Partial<RuleTestWorkspaceState>) => {
    setWorkspace((current) => ({
      ...current,
      ...changes,
      version: 1,
      updatedAt: new Date().toISOString(),
    }));
  };

  const selectRule = (ruleId: string) => {
    const rule = splunkRules.find((candidate) => candidate.id === ruleId);
    if (!rule) {
      return;
    }
    updateWorkspace({
      rule,
      testName: `${ruleLabel(rule)} test`,
      notes: '',
      selectedDatasetPaths: [],
      preview: null,
      result: null,
      runStatus: null,
    });
    setError(null);
  };

  const selectDatasets = (selectedDatasetPaths: string[]) => {
    if (catalog && selectedDatasetPaths.length > catalog.maxDatasets) {
      setError(`Select no more than ${catalog.maxDatasets} datasets for one test.`);
      return;
    }
    updateWorkspace({ selectedDatasetPaths, preview: null });
    setError(null);
  };

  const selectMode = (value: string) => {
    const mode: RuleTestMode = value === 'historical' ? 'historical' : 'attack_data';
    updateWorkspace({ mode, result: null, runStatus: null });
    setError(null);
  };

  const previewDatasets = async () => {
    if (!workspace.rule) {
      setError('Choose a stored Splunk rule before previewing attack-data.');
      return;
    }
    setIsPreviewing(true);
    setError(null);
    try {
      const preview = await previewRuleAttackData(workspace.rule, workspace.selectedDatasetPaths);
      updateWorkspace({ preview });
    } catch (previewError) {
      setError(previewError instanceof Error ? previewError.message : 'Unable to preview attack-data.');
    } finally {
      setIsPreviewing(false);
    }
  };

  const runTest = async () => {
    if (!workspace.rule) {
      setError('Choose a stored Splunk rule before running a test.');
      return;
    }
    activeRun.current?.abort();
    const controller = new AbortController();
    const runId = createRunId();
    activeRun.current = controller;
    setIsRunning(true);
    setError(null);
    updateWorkspace({ result: null, runStatus: null });
    const polling = pollRuleTestRunStatus(
      runId,
      (runStatus) => updateWorkspace({ runStatus }),
      controller.signal,
    );
    try {
      const result = await runRuleTest(workspace.rule, {
        mode: workspace.mode,
        selectedDatasetPaths: workspace.mode === 'attack_data' ? workspace.selectedDatasetPaths : [],
        earliestTime: workspace.earliestTime,
        latestTime: workspace.latestTime,
        runId,
      });
      const runStatus = await loadFinalRunStatus(runId);
      updateWorkspace({ result, ...(runStatus ? { runStatus } : {}) });
    } catch (runError) {
      const runStatus = await loadFinalRunStatus(runId);
      if (runStatus) {
        updateWorkspace({ runStatus });
      }
      setError(runError instanceof Error ? runError.message : 'Unable to run the Splunk rule test.');
    } finally {
      controller.abort();
      await polling;
      if (activeRun.current === controller) {
        activeRun.current = null;
      }
      setIsRunning(false);
    }
  };

  const usesMappingFallback = workspace.selectedDatasetPaths.length === 0;
  const attackDataUnavailable = isCatalogLoading || Boolean(catalogError && !catalog);
  const historicalWindowInvalid = workspace.mode === 'historical'
    && (!workspace.earliestTime.trim() || !workspace.latestTime.trim());

  return (
    <Layout
      height="fill"
      header={
        <LayoutHeader hasDivider label="Rule test header">
          <HStack align="center" gap={4} paddingInline={4} paddingBlock={3} wrap="wrap">
            <StackItem size="fill">
              <VStack gap={1}>
                <Heading level={1}>Rule testing</Heading>
                <Text as="p" color="secondary" type="supporting">
                  Replay controlled attack-data or validate the original rule against existing Splunk history.
                </Text>
              </VStack>
            </StackItem>
            <Button
              isDisabled={!workspace.rule
                || historicalWindowInvalid
                || (workspace.mode === 'attack_data' && attackDataUnavailable)}
              isLoading={isRunning}
              label={workspace.mode === 'attack_data' ? 'Run replay test' : 'Search historical data'}
              variant="primary"
              onClick={() => void runTest()}
            />
          </HStack>
        </LayoutHeader>
      }
    >
      <LayoutContent label="Rule test workspace">
        <VStack className="rule-test-workspace" gap={4} padding={4}>
          {splunkRules.length === 0 ? (
            <Banner status="warning" title="Save a Splunk rule before creating a test." />
          ) : null}
          {error ? <Banner isDismissable status="error" title={error} onDismiss={() => setError(null)} /> : null}

          <section className="rule-test-section" aria-labelledby="test-mode-heading">
            <VStack gap={3}>
              <VStack gap={1}>
                <Heading id="test-mode-heading" level={2}>Test mode</Heading>
                <Text as="p" color="secondary" type="supporting">
                  Choose whether the run uses controlled replay data or your existing Splunk indexes.
                </Text>
              </VStack>
              <SegmentedControl
                isDisabled={isRunning}
                label="Rule test mode"
                size="sm"
                value={workspace.mode}
                onChange={selectMode}
              >
                <SegmentedControlItem label="Attack data" value="attack_data" />
                <SegmentedControlItem label="Historical data" value="historical" />
              </SegmentedControl>
              <Text as="p" color="secondary" type="supporting">
                {workspace.mode === 'attack_data'
                  ? 'Replays selected files into the configured test index, overrides the base index constraint, and scopes the search to this run host.'
                  : 'Skips replay and HEC, preserves the original query and index constraints, and searches the selected historical window.'}
              </Text>
            </VStack>
          </section>

          <section className="rule-test-section" aria-labelledby="test-setup-heading">
            <VStack gap={4}>
              <VStack gap={1}>
                <Heading id="test-setup-heading" level={2}>Stored test setup</Heading>
                <Text as="p" color="secondary" type="supporting">
                  The mode, rule snapshot, notes, time window, dataset choices, preview, and latest result are saved in this browser.
                </Text>
              </VStack>
              <HStack align="start" gap={4} wrap="wrap">
                <StackItem size="fill">
                  <Selector
                    hasSearch
                    isDisabled={ruleOptions.length === 0}
                    label="Test rule"
                    options={ruleOptions}
                    placeholder="Choose a saved Splunk rule"
                    value={workspace.rule?.id ?? ''}
                    onChange={selectRule}
                  />
                </StackItem>
                <StackItem size="fill">
                  <TextInput
                    isDisabled={!workspace.rule}
                    label="Test name"
                    placeholder="Name this test"
                    value={workspace.testName}
                    onChange={(testName) => updateWorkspace({ testName })}
                  />
                </StackItem>
              </HStack>
              <TextArea
                isDisabled={!workspace.rule}
                isOptional
                label="Test notes"
                placeholder="Expected behavior, lab assumptions, or investigation notes"
                rows={3}
                value={workspace.notes}
                onChange={(notes) => updateWorkspace({ notes })}
              />
              {workspace.rule ? <RuleContext rule={workspace.rule} /> : null}
              {workspace.updatedAt ? (
                <Text as="p" color="secondary" type="supporting">
                  Stored {new Date(workspace.updatedAt).toLocaleString()}
                </Text>
              ) : null}
            </VStack>
          </section>

          {workspace.mode === 'historical' ? (
            <section className="rule-test-section" aria-labelledby="historical-window-heading">
              <VStack gap={4}>
                <VStack gap={1}>
                  <Heading id="historical-window-heading" level={2}>Historical search window</Heading>
                  <Text as="p" color="secondary" type="supporting">
                    Use Splunk relative or absolute time values. The original SPL and index filters remain unchanged.
                  </Text>
                </VStack>
                <HStack align="start" gap={4} wrap="wrap">
                  <StackItem size="fill">
                    <TextInput
                      isDisabled={!workspace.rule || isRunning}
                      isRequired
                      label="Earliest time"
                      placeholder="-24h"
                      value={workspace.earliestTime}
                      onChange={(earliestTime) => updateWorkspace({ earliestTime })}
                    />
                  </StackItem>
                  <StackItem size="fill">
                    <TextInput
                      isDisabled={!workspace.rule || isRunning}
                      isRequired
                      label="Latest time"
                      placeholder="now"
                      value={workspace.latestTime}
                      onChange={(latestTime) => updateWorkspace({ latestTime })}
                    />
                  </StackItem>
                </HStack>
              </VStack>
            </section>
          ) : null}

          {workspace.mode === 'attack_data' ? (
            <section className="rule-test-section" aria-labelledby="dataset-selection-heading">
              <VStack gap={4}>
                <VStack gap={1}>
                  <Heading id="dataset-selection-heading" level={2}>Attack-data datasets</Heading>
                  <Text as="p" color="secondary" type="supporting">
                    Choose concrete files, or leave the selection empty to fall back to MITRE, tags, and log-source mapping.
                  </Text>
                </VStack>
                {catalogError ? <Banner status="error" title={catalogError} /> : null}
                <TextInput
                  hasClear
                  isDisabled={!workspace.rule || attackDataUnavailable}
                  label="Filter dataset catalog"
                  placeholder="Search a name, MITRE technique, source, or manifest"
                  value={datasetSearch}
                  onChange={setDatasetSearch}
                />
                <MultiSelector
                  description={catalog
                    ? `Showing ${Math.min(matchingDatasets.length, datasetOptionLimit)} of ${matchingDatasets.length} matching datasets; maximum ${catalog.maxDatasets} per test.`
                    : 'Loading the configured attack_data repository.'}
                  isDisabled={!workspace.rule || visibleDatasets.length === 0 || Boolean(catalogError && !catalog)}
                  isLoading={isCatalogLoading}
                  label="Datasets"
                  options={datasetOptions}
                  placeholder="Use mapping fallback"
                  triggerDisplay="count"
                  value={workspace.selectedDatasetPaths}
                  onChange={selectDatasets}
                />
                <Banner
                  status={usesMappingFallback ? 'warning' : 'success'}
                  title={usesMappingFallback
                    ? 'Mapping fallback is active'
                    : `${workspace.selectedDatasetPaths.length} explicit dataset(s) selected`}
                  description={usesMappingFallback
                    ? 'RuleAtlas will rank matching manifests from the rule MITRE techniques, tags, and log source.'
                    : 'These files will be used directly; rule mapping will not replace the selection.'}
                />
                {selectedDatasets.length > 0 ? (
                  <Table
                    columns={datasetColumns}
                    data={selectedDatasets}
                    density="compact"
                    dividers="rows"
                    idKey="id"
                    textOverflow="truncate"
                  />
                ) : null}
                <HStack align="center" gap={2} wrap="wrap">
                  <Button
                    isDisabled={!workspace.rule || attackDataUnavailable}
                    isLoading={isPreviewing}
                    label={usesMappingFallback ? 'Preview fallback mapping' : 'Preview selected datasets'}
                    variant="secondary"
                    onClick={() => void previewDatasets()}
                  />
                  <Text color="secondary" type="supporting">
                    Previewing does not pull LFS files or send data to Splunk.
                  </Text>
                </HStack>
              </VStack>
            </section>
          ) : null}

          {workspace.mode === 'attack_data' && workspace.preview ? (
            <section className="rule-test-section" aria-labelledby="dataset-preview-heading">
              <VStack gap={3}>
                <VStack gap={1}>
                  <Heading id="dataset-preview-heading" level={2}>Selection preview</Heading>
                  <Text as="p" color="secondary" type="supporting">
                    {workspace.preview.selectionMode === 'explicit' ? 'Explicit selection' : 'Mapping fallback'} ·{' '}
                    {workspace.preview.matches.reduce((count, match) => count + match.datasets.length, 0)} file(s)
                  </Text>
                </VStack>
                <Table
                  columns={previewColumns}
                  data={workspace.preview.matches}
                  density="compact"
                  dividers="rows"
                  idKey="id"
                  textOverflow="truncate"
                />
              </VStack>
            </section>
          ) : null}

          <RuleTestStatusPanel status={workspace.runStatus} />

          <RuleTestPanel
            error={null}
            isTesting={false}
            result={isRunning ? null : workspace.result}
            onDismiss={() => updateWorkspace({ result: null, runStatus: null })}
          />
        </VStack>
      </LayoutContent>
    </Layout>
  );
}

function RuleContext({ rule }: { rule: TemplateRecord }) {
  const technique = displayValue(rule.data.mitre_technique) || 'No MITRE mapping';
  const logSource = displayValue(rule.data.log_source) || 'No log source';
  const platform = displayValue(rule.data.platform) || 'Unknown platform';
  return (
    <VStack gap={2}>
      <HStack align="center" gap={2} wrap="wrap">
        <Token color="blue" label={platform} size="sm" />
        <Token color="orange" label={technique} size="sm" />
        <Token color="gray" label={logSource} size="sm" />
      </HStack>
      <Text as="p" color="secondary" type="supporting">
        {displayValue(rule.data.query) || 'This rule has no query.'}
      </Text>
    </VStack>
  );
}

function uniqueCatalogDatasets(datasets: AttackDataCatalogEntry[]): AttackDataCatalogEntry[] {
  const byPath = new Map<string, AttackDataCatalogEntry>();
  for (const dataset of datasets) {
    if (!byPath.has(dataset.path)) {
      byPath.set(dataset.path, dataset);
    }
  }
  return [...byPath.values()];
}

function ruleLabel(rule: TemplateRecord): string {
  return displayValue(rule.data.name) || displayValue(rule.data.rule_id) || rule.id;
}

function displayValue(value: unknown): string {
  return Array.isArray(value) ? value.map(String).join(', ') : typeof value === 'string' ? value : '';
}

function createRunId(): string {
  return `ruleatlas-ui-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
}

async function pollRuleTestRunStatus(
  runId: string,
  onStatus: (status: RuleTestRunStatus) => void,
  signal: AbortSignal,
): Promise<void> {
  while (!signal.aborted) {
    try {
      const status = await getRuleTestRunStatus(runId);
      onStatus(status);
      if (status.state !== 'running') {
        return;
      }
    } catch {
      // The POST may not have registered the run yet; the final request still surfaces failures.
    }
    await waitForPoll(signal);
  }
}

async function loadFinalRunStatus(runId: string): Promise<RuleTestRunStatus | null> {
  try {
    return await getRuleTestRunStatus(runId);
  } catch {
    return null;
  }
}

function waitForPoll(signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const finish = () => {
      clearTimeout(timeout);
      signal.removeEventListener('abort', finish);
      resolve();
    };
    const timeout = setTimeout(finish, 500);
    signal.addEventListener('abort', finish, { once: true });
  });
}
