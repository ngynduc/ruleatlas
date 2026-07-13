import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { RuleRepoConfig } from './ruleRepoPlugin';
import {
  ApiError,
  assertObject,
  readJsonBody,
  requestPath,
  requiredString,
  sendApiError,
  sendJson,
} from './http';

const execFileAsync = promisify(execFile);
const branchPattern = /^(?![-/])(?!.*(?:\.\.|@\{|\/\/))[A-Za-z0-9._/-]+(?<![./])$/;
const remotePattern = /^[A-Za-z0-9._-]+$/;
const maxChangedFiles = 250;

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

interface ChangedFile {
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
  trackingBranch: string | null;
  ahead: number;
  behind: number;
  clean: boolean;
  changedFiles: ChangedFile[];
  changedFilesTruncated: boolean;
  github: {
    owner: string;
    repository: string;
  } | null;
  githubAuthAvailable: boolean;
}

export async function handleGitRepositoryApi(
  request: IncomingMessage,
  response: ServerResponse,
  config: RuleRepoConfig,
) {
  try {
    const pathname = requestPath(request);

    if (request.method === 'GET' && pathname === '/status') {
      sendJson(response, 200, await getGitRepositoryStatus(config));
      return;
    }

    if (request.method === 'POST' && pathname === '/fetch') {
      sendJson(response, 200, await fetchGitRepository(config));
      return;
    }

    if (request.method === 'POST' && pathname === '/pull') {
      sendJson(response, 200, await pullGitRepository(config));
      return;
    }

    if (request.method === 'POST' && pathname === '/branches') {
      const payload = assertObject(await readJsonBody(request));
      const branch = validateGitBranchName(requiredString(payload.branch, 'branch', { maxLength: 160 }));
      await assertGitRepository(config.repoPath);
      const existing = await runGit(config.repoPath, ['show-ref', '--verify', '--quiet', `refs/heads/${branch}`], [0, 1]);
      if (existing.exitCode === 0) {
        throw new ApiError(409, 'branch_exists', `Branch ${branch} already exists.`);
      }
      await runGit(config.repoPath, ['switch', '-c', branch]);
      sendJson(response, 201, await getGitRepositoryStatus(config));
      return;
    }

    if (request.method === 'POST' && pathname === '/pull-requests') {
      const payload = assertObject(await readJsonBody(request));
      const result = await publishPullRequest(config, {
        baseBranch: optionalString(payload.baseBranch) || config.githubBaseBranch,
        body: optionalString(payload.body),
        branch: requiredString(payload.branch, 'branch', { maxLength: 160 }),
        commitMessage: requiredString(payload.commitMessage, 'commitMessage', { maxLength: 240 }),
        title: requiredString(payload.title, 'title', { maxLength: 240 }),
      });
      sendJson(response, result.created ? 201 : 200, result);
      return;
    }

    sendApiError(response, new ApiError(404, 'route_not_found', 'Repository operation was not found.'));
  } catch (error) {
    sendApiError(response, normalizeGitError(error));
  }
}

export async function fetchGitRepository(config: RuleRepoConfig): Promise<GitRepositoryStatus> {
  validateGitRemoteName(config.githubRemote);
  await assertGitRepository(config.repoPath);
  await runGit(config.repoPath, ['fetch', config.githubRemote, '--prune']);
  return getGitRepositoryStatus(config);
}

export async function pullGitRepository(config: RuleRepoConfig): Promise<GitRepositoryStatus> {
  validateGitRemoteName(config.githubRemote);
  const status = await getRequiredStatus(config);
  if (!status.clean) {
    throw new ApiError(409, 'repository_dirty', 'Commit or discard local changes before pulling.');
  }
  await runGit(config.repoPath, ['pull', '--ff-only', config.githubRemote, status.branch]);
  return getGitRepositoryStatus(config);
}

export async function getGitRepositoryStatus(config: RuleRepoConfig): Promise<GitRepositoryStatus> {
  validateGitRemoteName(config.githubRemote);
  const isGitRepository = await isGitRepo(config.repoPath);
  if (!isGitRepository) {
    return emptyStatus(config);
  }

  const [branchResult, headResult, remoteUrlResult, trackingResult, statusResult] = await Promise.all([
    runGit(config.repoPath, ['branch', '--show-current']),
    runGit(config.repoPath, ['rev-parse', '--short', '--verify', '--quiet', 'HEAD'], [0, 1]),
    runGit(config.repoPath, ['remote', 'get-url', config.githubRemote], [0, 2]),
    runGit(config.repoPath, ['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{upstream}'], [0, 128]),
    runGit(config.repoPath, ['status', '--porcelain=v1', '--untracked-files=all']),
  ]);

  const branch = branchResult.stdout.trim() || '(detached HEAD)';
  const trackingBranch = trackingResult.exitCode === 0 ? trackingResult.stdout.trim() : null;
  const divergence = trackingBranch
    ? await runGit(config.repoPath, ['rev-list', '--left-right', '--count', `${trackingBranch}...HEAD`], [0, 128])
    : null;
  const [behind = 0, ahead = 0] = divergence?.exitCode === 0
    ? divergence.stdout.trim().split(/\s+/).map((value) => Number(value) || 0)
    : [0, 0];
  const changedFiles = parseChangedFiles(statusResult.stdout);
  const remoteUrl = remoteUrlResult.exitCode === 0 ? remoteUrlResult.stdout.trim() : '';

  return {
    repositoryPath: config.repoPath,
    isGitRepository: true,
    branch,
    head: headResult.stdout.trim(),
    remote: config.githubRemote,
    remoteUrl,
    baseBranch: config.githubBaseBranch,
    trackingBranch,
    ahead,
    behind,
    clean: changedFiles.length === 0,
    changedFiles: changedFiles.slice(0, maxChangedFiles),
    changedFilesTruncated: changedFiles.length > maxChangedFiles,
    github: parseGitHubRemote(remoteUrl),
    githubAuthAvailable: Boolean(process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_PAT),
  };
}

export interface PublishRequest {
  baseBranch: string;
  body: string;
  branch: string;
  commitMessage: string;
  title: string;
}

interface PullRequestResult {
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

export async function publishPullRequest(config: RuleRepoConfig, input: PublishRequest): Promise<PullRequestResult> {
  const status = await getRequiredStatus(config);
  const branch = validateGitBranchName(input.branch);
  const baseBranch = validateGitBranchName(input.baseBranch);
  validateGitRemoteName(config.githubRemote);

  if (!status.github) {
    throw new ApiError(422, 'unsupported_remote', 'The configured remote is not a GitHub repository.', {
      remoteUrl: status.remoteUrl,
    });
  }
  if (branch === baseBranch) {
    throw new ApiError(422, 'invalid_branch', 'Pull request branch must differ from the base branch.');
  }

  if (status.branch !== branch) {
    const branchExists = await runGit(config.repoPath, ['show-ref', '--verify', '--quiet', `refs/heads/${branch}`], [0, 1]);
    await runGit(config.repoPath, branchExists.exitCode === 0 ? ['switch', branch] : ['switch', '-c', branch]);
  }

  await runGit(config.repoPath, ['add', '--all']);
  const staged = await runGit(config.repoPath, ['diff', '--cached', '--quiet'], [0, 1]);
  const commitCreated = staged.exitCode === 1;
  if (commitCreated) {
    await runGit(config.repoPath, ['commit', '-m', input.commitMessage]);
  }

  const aheadOfBase = await runGit(config.repoPath, ['rev-list', '--count', `${baseBranch}..HEAD`], [0, 128]);
  if (!commitCreated && (aheadOfBase.exitCode !== 0 || Number(aheadOfBase.stdout.trim()) === 0)) {
    throw new ApiError(409, 'nothing_to_publish', 'There are no commits or working-tree changes to publish.');
  }

  await runGit(config.repoPath, ['push', '--set-upstream', config.githubRemote, `HEAD:${branch}`]);
  const pullRequest = await createOrFindPullRequest(status.github, branch, baseBranch, input.title, input.body);
  const commit = (await runGit(config.repoPath, ['rev-parse', 'HEAD'])).stdout.trim();

  return {
    created: pullRequest.created,
    commitCreated,
    commit,
    pullRequest: pullRequest.pullRequest,
    repository: await getGitRepositoryStatus(config),
  };
}

async function createOrFindPullRequest(
  github: NonNullable<GitRepositoryStatus['github']>,
  branch: string,
  baseBranch: string,
  title: string,
  body: string,
) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_PAT;
  if (!token) {
    return createPullRequestWithGh(github, branch, baseBranch, title, body);
  }

  const repositoryApi = `https://api.github.com/repos/${github.owner}/${github.repository}`;
  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    'User-Agent': 'RuleAtlas',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  const existingResponse = await fetch(
    `${repositoryApi}/pulls?state=open&head=${encodeURIComponent(`${github.owner}:${branch}`)}&base=${encodeURIComponent(baseBranch)}`,
    { headers },
  );
  if (!existingResponse.ok) {
    throw await githubApiError(existingResponse, 'Unable to check existing pull requests.');
  }
  const existing = (await existingResponse.json()) as Array<Record<string, unknown>>;
  if (existing[0]) {
    return { created: false, pullRequest: githubPullRequest(existing[0]) };
  }

  const response = await fetch(`${repositoryApi}/pulls`, {
    body: JSON.stringify({ base: baseBranch, body, head: branch, title }),
    headers,
    method: 'POST',
  });
  if (!response.ok) {
    throw await githubApiError(response, 'Unable to create pull request.');
  }
  return { created: true, pullRequest: githubPullRequest(await response.json() as Record<string, unknown>) };
}

async function createPullRequestWithGh(
  github: NonNullable<GitRepositoryStatus['github']>,
  branch: string,
  baseBranch: string,
  title: string,
  body: string,
) {
  const repository = `${github.owner}/${github.repository}`;
  const existing = await runCommand('gh', [
    'pr', 'view', branch, '--repo', repository, '--json', 'number,state,title,url',
  ], process.cwd(), [0, 1]);
  if (existing.exitCode === 0) {
    return { created: false, pullRequest: githubPullRequest(JSON.parse(existing.stdout) as Record<string, unknown>) };
  }

  const created = await runCommand('gh', [
    'pr', 'create', '--repo', repository, '--head', branch, '--base', baseBranch, '--title', title, '--body', body,
  ], process.cwd());
  const url = created.stdout.trim().split(/\s+/).find((value) => value.startsWith('https://')) ?? '';
  const viewed = await runCommand('gh', [
    'pr', 'view', url || branch, '--repo', repository, '--json', 'number,state,title,url',
  ], process.cwd());
  return { created: true, pullRequest: githubPullRequest(JSON.parse(viewed.stdout) as Record<string, unknown>) };
}

function githubPullRequest(value: Record<string, unknown>) {
  return {
    number: typeof value.number === 'number' ? value.number : null,
    state: typeof value.state === 'string' ? value.state : 'open',
    title: typeof value.title === 'string' ? value.title : '',
    url: typeof value.html_url === 'string' ? value.html_url : typeof value.url === 'string' ? value.url : '',
  };
}

async function githubApiError(response: Response, fallbackMessage: string): Promise<ApiError> {
  const payload = await response.json().catch(() => null) as { message?: string } | null;
  const statusCode = response.status === 401 ? 401 : response.status === 403 ? 403 : response.status === 422 ? 422 : 502;
  return new ApiError(statusCode, 'github_api_error', payload?.message || fallbackMessage, {
    githubStatus: response.status,
  });
}

async function getRequiredStatus(config: RuleRepoConfig) {
  const status = await getGitRepositoryStatus(config);
  if (!status.isGitRepository) {
    throw new ApiError(422, 'repository_not_git', `${config.repoPath} is not a Git repository.`);
  }
  return status;
}

async function assertGitRepository(repoPath: string) {
  if (!await isGitRepo(repoPath)) {
    throw new ApiError(422, 'repository_not_git', `${repoPath} is not a Git repository.`);
  }
}

async function isGitRepo(repoPath: string): Promise<boolean> {
  const result = await runGit(repoPath, ['rev-parse', '--is-inside-work-tree'], [0, 128]);
  return result.exitCode === 0 && result.stdout.trim() === 'true';
}

async function runGit(repoPath: string, args: string[], acceptedExitCodes: number[] = [0]) {
  return runCommand('git', ['-c', 'credential.interactive=never', ...args], repoPath, acceptedExitCodes);
}

async function runCommand(
  command: string,
  args: string[],
  cwd: string,
  acceptedExitCodes: number[] = [0],
): Promise<CommandResult> {
  try {
    const result = await execFileAsync(command, args, {
      cwd,
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024,
      timeout: 120_000,
    });
    return { exitCode: 0, stderr: result.stderr, stdout: result.stdout };
  } catch (error) {
    const commandError = error as Error & { code?: number | string; stdout?: string; stderr?: string };
    const exitCode = typeof commandError.code === 'number' ? commandError.code : 1;
    if (acceptedExitCodes.includes(exitCode)) {
      return { exitCode, stderr: commandError.stderr ?? '', stdout: commandError.stdout ?? '' };
    }
    throw new ApiError(502, 'command_failed', `${command} failed: ${(commandError.stderr || commandError.message).trim()}`, {
      command,
      exitCode,
    });
  }
}

function parseChangedFiles(output: string): ChangedFile[] {
  return output.split('\n').filter(Boolean).map((line) => ({
    indexStatus: line[0] || ' ',
    worktreeStatus: line[1] || ' ',
    path: line.slice(3).replace(/^"|"$/g, ''),
  }));
}

export function parseGitHubRemote(remoteUrl: string): GitRepositoryStatus['github'] {
  const normalized = remoteUrl.trim().replace(/\.git$/, '');
  const match = normalized.match(/^(?:https?:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([^/]+)\/([^/]+)$/i);
  return match ? { owner: match[1], repository: match[2] } : null;
}

function emptyStatus(config: RuleRepoConfig): GitRepositoryStatus {
  return {
    repositoryPath: config.repoPath,
    isGitRepository: false,
    branch: '',
    head: '',
    remote: config.githubRemote,
    remoteUrl: '',
    baseBranch: config.githubBaseBranch,
    trackingBranch: null,
    ahead: 0,
    behind: 0,
    clean: true,
    changedFiles: [],
    changedFilesTruncated: false,
    github: null,
    githubAuthAvailable: Boolean(process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_PAT),
  };
}

export function validateGitBranchName(branch: string): string {
  if (!branchPattern.test(branch)) {
    throw new ApiError(422, 'invalid_branch', 'Branch contains unsupported characters or Git ref syntax.');
  }
  return branch;
}

export function validateGitRemoteName(remote: string): string {
  if (!remotePattern.test(remote)) {
    throw new ApiError(422, 'invalid_remote', 'Remote name contains unsupported characters.');
  }
  return remote;
}

function optionalString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeGitError(error: unknown): unknown {
  if (error instanceof ApiError) {
    return error;
  }
  return new ApiError(500, 'repository_operation_failed', error instanceof Error ? error.message : 'Repository operation failed.');
}
