import { requestJson } from './api';

const repositoryApi = '/api/rule-repo/git';

export interface RepositoryChangedFile extends Record<string, unknown> {
  path: string;
  indexStatus: string;
  worktreeStatus: string;
}

export interface GitRepositoryStatus {
  repositoryPath: string;
  isGitRepository: boolean;
  branch: string;
  head: string;
  remote: string;
  remoteUrl: string;
  baseBranch: string;
  baseBranchAvailable: boolean;
  commitsAheadOfBase: number;
  trackingBranch: string | null;
  ahead: number;
  behind: number;
  clean: boolean;
  changedFiles: RepositoryChangedFile[];
  changedFilesTruncated: boolean;
  github: { owner: string; repository: string } | null;
  githubAuthAvailable: boolean;
}

export interface PublishPullRequestInput {
  branch: string;
  baseBranch: string;
  commitMessage: string;
  title: string;
  body: string;
}

export interface PublishPullRequestResult {
  created: boolean;
  commitCreated: boolean;
  commit: string;
  pullRequest: {
    number: number | null;
    state: string;
    title: string;
    url: string;
  };
  repository: GitRepositoryStatus;
}

export function loadRepositoryStatus(): Promise<GitRepositoryStatus> {
  return requestJson(`${repositoryApi}/status`);
}

export function fetchRepository(): Promise<GitRepositoryStatus> {
  return requestJson(`${repositoryApi}/fetch`, { method: 'POST' });
}

export function pullRepository(): Promise<GitRepositoryStatus> {
  return requestJson(`${repositoryApi}/pull`, { method: 'POST' });
}

export function createRepositoryBranch(branch: string): Promise<GitRepositoryStatus> {
  return requestJson(`${repositoryApi}/branches`, {
    body: JSON.stringify({ branch }),
    method: 'POST',
  });
}

export function publishRepositoryPullRequest(
  input: PublishPullRequestInput,
): Promise<PublishPullRequestResult> {
  return requestJson(`${repositoryApi}/pull-requests`, {
    body: JSON.stringify(input),
    method: 'POST',
  });
}
