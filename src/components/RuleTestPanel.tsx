import { Banner, Heading, HStack, pixel, proportional, StackItem, Table, Text, VStack } from '@astryxdesign/core';
import type { TableColumn } from '@astryxdesign/core';
import type { AttackDataMatch, RuleTestRunResult } from '../lib/ruleTestApi';

interface RuleTestPanelProps {
  isTesting: boolean;
  error: string | null;
  result: RuleTestRunResult | null;
  onDismiss: () => void;
}

export function RuleTestPanel({ isTesting, error, result, onDismiss }: RuleTestPanelProps) {
  if (!isTesting && !error && !result) {
    return null;
  }

  const columns: TableColumn<AttackDataMatch>[] = [
    { key: 'manifestPath', header: 'Manifest', width: proportional(1.6, { minWidth: 220 }) },
    {
      key: 'matchedTechniques',
      header: 'MITRE match',
      width: proportional(1, { minWidth: 120 }),
      renderCell: (match) => <Text type="supporting">{match.matchedTechniques.join(', ') || '—'}</Text>,
    },
    {
      key: 'matchedTags',
      header: 'Tag match',
      width: proportional(1, { minWidth: 120 }),
      renderCell: (match) => <Text type="supporting">{match.matchedTags.join(', ') || '—'}</Text>,
    },
    {
      key: 'datasets',
      header: 'Files',
      width: pixel(72),
      renderCell: (match) => <Text hasTabularNumbers type="supporting">{match.datasets.length}</Text>,
    },
  ];
  const isHistorical = result?.mode === 'historical';
  const resultDescription = result
    ? isHistorical
      ? `Original query searched ${result.earliestTime} to ${result.latestTime} in ${(result.durationMs / 1000).toFixed(1)}s; no data was ingested.`
      : `${result.ingestedFiles.length} file(s) ingested from ${result.selectedManifests.length} manifest(s) using ${result.selectionMode === 'explicit' ? 'explicit selection' : 'mapping fallback'} in ${(result.durationMs / 1000).toFixed(1)}s. ${result.indexOverridden ? `The base index was forced to ${result.testIndex ?? 'the configured test index'}.` : 'The generating query could not be scoped to the test index or run host.'}`
    : '';

  return (
    <section className="rule-test-panel" aria-label="Latest Splunk rule test">
      <VStack gap={3}>
        {isTesting ? (
          <Banner status="warning" title="Testing rule with matching Splunk attack-data…" />
        ) : null}
        {error ? <Banner isDismissable status="error" title={error} onDismiss={onDismiss} /> : null}
        {result ? (
          <>
            <Banner
              isDismissable
              status={result.passed ? 'success' : 'warning'}
              title={result.passed ? `Rule matched ${result.resultCount} result(s)` : 'Rule returned no results'}
              description={resultDescription}
              onDismiss={onDismiss}
            />
            <HStack align="center" gap={2}>
              <StackItem size="fill">
                <Heading level={2}>{isHistorical ? 'Historical query' : 'Selected attack-data'}</Heading>
              </StackItem>
              <Text color="secondary" type="supporting">Run {result.runId}</Text>
            </HStack>
            {isHistorical ? (
              <Text as="p" color="secondary" type="supporting">{result.query}</Text>
            ) : (
              <Table
                columns={columns}
                data={result.selectedManifests}
                density="compact"
                dividers="rows"
                idKey="id"
                textOverflow="truncate"
              />
            )}
          </>
        ) : null}
      </VStack>
    </section>
  );
}
