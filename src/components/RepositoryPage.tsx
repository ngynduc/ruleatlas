import { useEffect, useState } from 'react';
import {
  Banner,
  Button,
  Heading,
  HStack,
  Layout,
  LayoutContent,
  LayoutHeader,
  pixel,
  proportional,
  StackItem,
  StatusDot,
  Table,
  Text,
  TextArea,
  TextInput,
  useToast,
  VStack,
} from '@astryxdesign/core';
import {
  createRepositoryBranch,
  fetchRepository,
  loadRepositoryStatus,
  publishRepositoryPullRequest,
  pullRepository,
} from '../lib/repositoryApi';
import type {
  GitRepositoryStatus,
  PublishPullRequestResult,
  RepositoryChangedFile,
} from '../lib/repositoryApi';
import type { TableColumn } from '@astryxdesign/core';

type RepositoryAction = 'branch' | 'fetch' | 'load' | 'pull' | 'publish' | null;

export function RepositoryPage() {
  const toast = useToast();
  const [status, setStatus] = useState<GitRepositoryStatus | null>(null);
  const [action, setAction] = useState<RepositoryAction>('load');
  const [error, setError] = useState<string | null>(null);
  const [published, setPublished] = useState<PublishPullRequestResult | null>(null);
  const [branch, setBranch] = useState('feat/ruleatlas-update');
  const [baseBranch, setBaseBranch] = useState('main');
  const [commitMessage, setCommitMessage] = useState('feat(rules): update detection content');
  const [pullRequestTitle, setPullRequestTitle] = useState('Update detection rules');
  const [pullRequestBody, setPullRequestBody] = useState('Managed and tested with RuleAtlas.');

  useEffect(() => {
    let mounted = true;
    void loadRepositoryStatus()
      .then((nextStatus) => {
        if (!mounted) return;
        applyStatus(nextStatus);
      })
      .catch((loadError: unknown) => {
        if (mounted) setError(errorMessage(loadError));
      })
      .finally(() => {
        if (mounted) setAction(null);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const applyStatus = (nextStatus: GitRepositoryStatus) => {
    setStatus(nextStatus);
    setBaseBranch(nextStatus.baseBranch || 'main');
    if (nextStatus.branch && nextStatus.branch !== nextStatus.baseBranch) {
      setBranch(nextStatus.branch);
    }
  };

  const runStatusAction = async (
    nextAction: Exclude<RepositoryAction, 'publish' | null>,
    operation: () => Promise<GitRepositoryStatus>,
    successMessage: string,
  ) => {
    setAction(nextAction);
    setError(null);
    setPublished(null);
    try {
      applyStatus(await operation());
      toast({
        body: successMessage,
        collisionBehavior: 'overwrite',
        uniqueID: `repository-${nextAction}`,
      });
    } catch (operationError) {
      const nextError = errorMessage(operationError);
      setError(nextError);
      toast({
        body: nextError,
        collisionBehavior: 'overwrite',
        type: 'error',
        uniqueID: `repository-${nextAction}`,
      });
    } finally {
      setAction(null);
    }
  };

  const publish = async () => {
    setAction('publish');
    setError(null);
    setPublished(null);
    try {
      const result = await publishRepositoryPullRequest({
        baseBranch,
        body: pullRequestBody,
        branch,
        commitMessage,
        title: pullRequestTitle,
      });
      setPublished(result);
      applyStatus(result.repository);
      toast({
        body: result.created ? 'Pull request created.' : 'Branch pushed; the open pull request was reused.',
        collisionBehavior: 'overwrite',
        uniqueID: 'repository-publish',
      });
    } catch (publishError) {
      const nextError = errorMessage(publishError);
      setError(nextError);
      toast({
        body: nextError,
        collisionBehavior: 'overwrite',
        type: 'error',
        uniqueID: 'repository-publish',
      });
    } finally {
      setAction(null);
    }
  };

  const publishBlocker = repositoryPublishBlocker(status, baseBranch);

  const columns: TableColumn<RepositoryChangedFile>[] = [
    {
      key: 'path',
      header: 'Path',
      width: proportional(1, { minWidth: 240 }),
      renderCell: (file) => <Text type="supporting">{file.path}</Text>,
    },
    {
      key: 'indexStatus',
      header: 'Index',
      width: pixel(80),
      renderCell: (file) => <Text hasTabularNumbers type="supporting">{file.indexStatus.trim() || '—'}</Text>,
    },
    {
      key: 'worktreeStatus',
      header: 'Worktree',
      width: pixel(104),
      renderCell: (file) => <Text hasTabularNumbers type="supporting">{file.worktreeStatus.trim() || '—'}</Text>,
    },
  ];

  return (
    <Layout
      height="fill"
      header={
        <LayoutHeader hasDivider label="Repository header">
          <HStack align="center" gap={4} paddingInline={4} paddingBlock={3} wrap="wrap">
            <StackItem size="fill">
              <VStack gap={1}>
                <Heading level={1}>Repository</Heading>
                <Text as="p" color="secondary" type="supporting">
                  Inspect, synchronize, commit, push, and open a GitHub pull request from the configured rules checkout.
                </Text>
              </VStack>
            </StackItem>
            <HStack align="center" gap={2} wrap="wrap">
              <Button
                isLoading={action === 'load'}
                label="Refresh"
                size="sm"
                variant="secondary"
                onClick={() => void runStatusAction('load', loadRepositoryStatus, 'Repository status refreshed.')}
              />
              <Button
                isDisabled={!status?.isGitRepository}
                isLoading={action === 'fetch'}
                label="Fetch"
                size="sm"
                variant="secondary"
                onClick={() => void runStatusAction('fetch', fetchRepository, 'Remote refs fetched.')}
              />
              <Button
                isDisabled={!status?.isGitRepository || !status.clean}
                isLoading={action === 'pull'}
                label="Pull (fast-forward)"
                size="sm"
                variant="secondary"
                onClick={() => void runStatusAction('pull', pullRepository, 'Current branch updated.')}
              />
            </HStack>
          </HStack>
        </LayoutHeader>
      }
    >
      <LayoutContent label="Repository operations">
        <VStack gap={4} padding={4}>
          {error ? <Banner status="error" title={error} /> : null}
          {status && !status.isGitRepository ? (
            <Banner
              status="warning"
              title="Configured path is not a Git repository"
              description={`Update Config or initialize ${status.repositoryPath} before using repository actions.`}
            />
          ) : null}

          <section className="summary-grid" aria-label="Repository summary">
            <SummaryCell label="Working tree" value={status?.clean ? 'Clean' : `${status?.changedFiles.length ?? 0} changed`} success={status?.clean} />
            <SummaryCell label="Branch" value={status?.branch || 'Not available'} />
            <SummaryCell label="HEAD" value={status?.head || 'Not available'} />
            <SummaryCell label="Remote" value={status?.remoteUrl || 'Not configured'} />
            <SummaryCell label="Ahead / behind" value={`${status?.ahead ?? 0} / ${status?.behind ?? 0}`} />
            <SummaryCell label="GitHub" value={status?.github ? `${status.github.owner}/${status.github.repository}` : 'Not detected'} />
          </section>

          <section className="repository-section" aria-label="Changed files">
            <VStack gap={2}>
              <HStack align="center" gap={2}>
                <StackItem size="fill"><Heading level={2}>Changed files</Heading></StackItem>
                <Text color="secondary" type="supporting">
                  {status?.changedFiles.length ?? 0}{status?.changedFilesTruncated ? '+' : ''} shown
                </Text>
              </HStack>
              {status?.changedFiles.length ? (
                <Table
                  columns={columns}
                  data={status.changedFiles}
                  density="compact"
                  dividers="rows"
                  idKey="path"
                  textOverflow="truncate"
                />
              ) : (
                <Text color="secondary" type="supporting">No local changes.</Text>
              )}
            </VStack>
          </section>

          <section className="repository-section" aria-label="Branch and pull request">
            <VStack gap={4}>
              <VStack gap={1}>
                <Heading level={2}>Publish a pull request</Heading>
                <Text color="secondary" type="supporting">
                  RuleAtlas stages the configured repository, commits when needed, pushes the feature branch, then creates or reuses an open GitHub PR.
                </Text>
              </VStack>
              <HStack align="end" gap={3} wrap="wrap">
                <StackItem size="fill">
                  <TextInput isRequired label="Feature branch" value={branch} onChange={setBranch} />
                </StackItem>
                <StackItem size="fill">
                  <TextInput isRequired label="Base branch" value={baseBranch} onChange={setBaseBranch} />
                </StackItem>
                <Button
                  isDisabled={!status?.isGitRepository || !branch.trim()}
                  isLoading={action === 'branch'}
                  label="Create branch"
                  variant="secondary"
                  onClick={() => void runStatusAction(
                    'branch',
                    () => createRepositoryBranch(branch),
                    `Created and switched to ${branch}.`,
                  )}
                />
              </HStack>
              {publishBlocker ? (
                <Banner
                  status="warning"
                  title={publishBlocker.title}
                  description={publishBlocker.description}
                />
              ) : null}
              <TextInput isRequired label="Commit message" value={commitMessage} onChange={setCommitMessage} />
              <TextInput isRequired label="Pull request title" value={pullRequestTitle} onChange={setPullRequestTitle} />
              <TextArea
                isRequired
                label="Pull request body"
                rows={4}
                value={pullRequestBody}
                onChange={setPullRequestBody}
              />
              <HStack align="center" gap={3} wrap="wrap">
                <Button
                  isDisabled={
                    !status?.isGitRepository ||
                    !branch.trim() ||
                    !baseBranch.trim() ||
                    !commitMessage.trim() ||
                    !pullRequestTitle.trim() ||
                    Boolean(publishBlocker)
                  }
                  isLoading={action === 'publish'}
                  label="Commit, push & create PR"
                  variant="primary"
                  onClick={() => void publish()}
                />
                <Text color="secondary" type="supporting">
                  Authentication: {status?.githubAuthAvailable ? 'GitHub token detected' : 'uses authenticated gh CLI when no token is set'}
                </Text>
              </HStack>
              {published?.pullRequest.url ? (
                <Banner
                  isDismissable
                  status="success"
                  title={`Pull request #${published.pullRequest.number ?? '—'} is ${published.pullRequest.state}`}
                  description={
                    <a href={published.pullRequest.url} rel="noreferrer" target="_blank">
                      {published.pullRequest.url}
                    </a>
                  }
                  onDismiss={() => setPublished(null)}
                />
              ) : null}
            </VStack>
          </section>
        </VStack>
      </LayoutContent>
    </Layout>
  );
}

function repositoryPublishBlocker(
  status: GitRepositoryStatus | null,
  baseBranch: string,
): { title: string; description: string } | null {
  if (!status?.isGitRepository || baseBranch.trim() !== status.baseBranch) {
    return null;
  }

  if (!status.baseBranchAvailable) {
    return {
      title: `Base branch ${status.baseBranch} is not available from ${status.remote}`,
      description: 'Fetch the remote, or create and push the base branch before publishing a pull request.',
    };
  }

  if (status.clean && status.commitsAheadOfBase === 0) {
    return {
      title: 'Nothing to publish yet',
      description: `Edit a rule or add a commit on ${status.branch} before creating a pull request.`,
    };
  }

  return null;
}

function SummaryCell({ label, value, success }: { label: string; value: string; success?: boolean }) {
  return (
    <section className="summary-cell">
      <VStack gap={1}>
        <HStack align="center" gap={2}>
          {success !== undefined ? (
            <StatusDot label={success ? 'Clean repository' : 'Repository has changes'} variant={success ? 'success' : 'warning'} />
          ) : null}
          <Text color="secondary" type="supporting">{label}</Text>
        </HStack>
        <Text type="body">{value}</Text>
      </VStack>
    </section>
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Repository operation failed.';
}
