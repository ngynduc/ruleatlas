import {
  Banner,
  Heading,
  HStack,
  List,
  ListItem,
  ProgressBar,
  StackItem,
  StatusDot,
  Text,
  Token,
  VStack,
} from '@astryxdesign/core';
import type { RuleTestRunEvent, RuleTestRunStatus } from '../lib/ruleTestApi';

interface RuleTestStatusPanelProps {
  status: RuleTestRunStatus | null;
}

export function RuleTestStatusPanel({ status }: RuleTestStatusPanelProps) {
  if (!status) {
    return null;
  }

  const isRunning = status.state === 'running';
  const isHistorical = status.mode === 'historical';
  const summary = statusSummary(status);
  const progress = progressFor(status);

  return (
    <section
      aria-labelledby="rule-test-status-heading"
      aria-live="polite"
      className="rule-test-section rule-test-status-panel"
    >
      <VStack gap={3}>
        <HStack align="center" gap={2} wrap="wrap">
          <StatusDot
            isPulsing={isRunning}
            label={summary.title}
            variant={summary.dot}
          />
          <StackItem size="fill">
            <Heading id="rule-test-status-heading" level={2}>
              {isHistorical ? 'Historical search status' : 'Replay ingest status'}
            </Heading>
          </StackItem>
          <Text color="secondary" type="supporting">Run {status.runId}</Text>
        </HStack>

        <Banner
          status={summary.banner}
          title={summary.title}
          description={summary.description}
        />

        <ProgressBar
          hasValueLabel={!progress.isIndeterminate}
          isIndeterminate={progress.isIndeterminate}
          label={progress.label}
          max={progress.max}
          value={progress.value}
          variant={summary.progress}
          formatValueLabel={progress.formatValueLabel}
        />

        <HStack align="center" gap={2} wrap="wrap">
          {!isHistorical ? <Token color="gray" label={`${status.totalFiles} selected`} size="sm" /> : null}
          {!isHistorical ? <Token color="blue" label={`${status.filesRequiringFetch} LFS fetch`} size="sm" /> : null}
          {!isHistorical ? <Token color="green" label={`${status.ingestedFiles} HEC accepted`} size="sm" /> : null}
          <Token color="orange" label={`${status.searchAttempt}/${status.searchAttempts || 0} searches`} size="sm" />
          <Token color="purple" label={`${status.resultCount} matches`} size="sm" />
        </HStack>

        <Text as="p" color="secondary" type="supporting">
          {isHistorical
            ? 'Historical mode sends only the original rule query to Splunk; it does not fetch files or send events through HEC.'
            : '“HEC accepted” confirms Splunk returned a successful collector response. The search attempts separately confirm when those events are searchable and match the rule.'}
        </Text>

        <List
          density="compact"
          hasDividers
          header={<Heading level={3}>Activity</Heading>}
        >
          {status.events.map((event) => (
            <ListItem
              key={event.id}
              label={event.message}
              description={event.detail ? (
                <Text as="p" className="rule-test-event-detail" color="secondary" type="supporting">
                  {event.detail}
                </Text>
              ) : undefined}
              endContent={<Text hasTabularNumbers color="secondary" type="supporting">{formatTime(event.timestamp)}</Text>}
              startContent={<StatusDot label={event.message} variant={eventVariant(event)} />}
            />
          ))}
        </List>
      </VStack>
    </section>
  );
}

function statusSummary(status: RuleTestRunStatus): {
  title: string;
  description: string;
  banner: 'success' | 'warning' | 'error';
  dot: 'success' | 'warning' | 'error' | 'accent';
  progress: 'success' | 'warning' | 'error' | 'accent';
} {
  if (status.state === 'failed') {
    return {
      title: status.mode === 'historical'
        ? 'Historical search stopped with an operational error'
        : 'Replay stopped with an operational error',
      description: status.error?.message ?? 'The rule test could not complete.',
      banner: 'error',
      dot: 'error',
      progress: 'error',
    };
  }
  if (status.state === 'completed') {
    if (status.mode === 'historical') {
      return status.passed ? {
        title: `Historical search completed with ${status.resultCount} matching result(s)`,
        description: 'The original rule query matched existing Splunk data in the selected time window.',
        banner: 'success',
        dot: 'success',
        progress: 'success',
      } : {
        title: 'Historical search completed with no results',
        description: 'Review the original index constraints and selected time window.',
        banner: 'warning',
        dot: 'warning',
        progress: 'warning',
      };
    }
    return status.passed ? {
      title: `Replay completed with ${status.resultCount} matching result(s)`,
      description: 'The selected files were materialized, accepted by HEC, and matched by the rule search.',
      banner: 'success',
      dot: 'success',
      progress: 'success',
    } : {
      title: 'Replay completed, but the rule returned no results',
      description: 'Review the HEC acknowledgements and search attempts below to separate ingestion from detection logic.',
      banner: 'warning',
      dot: 'warning',
      progress: 'warning',
    };
  }

  const phaseLabels: Record<RuleTestRunStatus['phase'], string> = status.mode === 'historical'
    ? {
      preparing: 'Preparing historical search',
      fetching: 'Preparing historical search',
      ingesting: 'Preparing historical search',
      searching: 'Searching existing Splunk data',
      complete: 'Completing historical search',
      failed: 'Historical search stopped',
    }
    : {
      preparing: 'Selecting attack-data for replay',
      fetching: 'Fetching selected Git LFS data',
      ingesting: 'Sending replay data to Splunk HEC',
      searching: 'Waiting for replayed events to become searchable',
      complete: 'Completing replay',
      failed: 'Replay stopped',
    };
  return {
    title: phaseLabels[status.phase],
    description: 'Live status is saved with this test in your browser.',
    banner: 'warning',
    dot: 'accent',
    progress: 'accent',
  };
}

function progressFor(status: RuleTestRunStatus): {
  label: string;
  max: number;
  value: number;
  isIndeterminate: boolean;
  formatValueLabel?: (value: number, max: number) => string;
} {
  if (status.state === 'failed') {
    return {
      label: status.mode === 'historical' ? 'Historical search failed' : 'Replay failed',
      max: 1,
      value: 1,
      isIndeterminate: false,
    };
  }
  if (status.state === 'completed') {
    return {
      label: status.mode === 'historical' ? 'Historical search complete' : 'Replay complete',
      max: 1,
      value: 1,
      isIndeterminate: false,
    };
  }
  if (status.mode === 'historical' && status.phase === 'preparing') {
    return { label: 'Preparing historical search', max: 1, value: 0, isIndeterminate: true };
  }
  if (status.phase === 'preparing' || status.phase === 'fetching') {
    return {
      label: status.phase === 'fetching' ? 'Git LFS fetch progress' : 'Attack-data selection progress',
      max: Math.max(status.filesRequiringFetch, 1),
      value: status.fetchedFiles,
      isIndeterminate: status.phase === 'preparing' || status.filesRequiringFetch > status.fetchedFiles,
    };
  }
  if (status.phase === 'ingesting') {
    return {
      label: 'Splunk HEC ingest progress',
      max: Math.max(status.totalFiles, 1),
      value: status.ingestedFiles,
      isIndeterminate: false,
      formatValueLabel: (value, max) => `${value}/${max} files`,
    };
  }
  return {
    label: 'Splunk search progress',
    max: Math.max(status.searchAttempts, 1),
    value: status.searchAttempt,
    isIndeterminate: false,
    formatValueLabel: (value, max) => `${value}/${max} attempts`,
  };
}

function eventVariant(event: RuleTestRunEvent): 'success' | 'warning' | 'error' | 'accent' {
  if (event.level === 'success') return 'success';
  if (event.level === 'warning') return 'warning';
  if (event.level === 'error') return 'error';
  return 'accent';
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString();
}
