import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  fetchGitRepository,
  getGitRepositoryStatus,
  parseGitHubRemote,
  pullGitRepository,
  publishPullRequest,
  validateGitBranchName,
  validateGitRemoteName,
} from './gitRepo';
import type { RuleRepoConfig } from './ruleRepoPlugin';

const execFileAsync = promisify(execFile);
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })));
  delete process.env.GITHUB_TOKEN;
  vi.unstubAllGlobals();
});

describe('Git repository service', () => {
  it('reports branch, GitHub remote, and working-tree changes', async () => {
    const repository = await mkdtemp(path.join(tmpdir(), 'ruleatlas-git-'));
    temporaryDirectories.push(repository);
    await git(repository, ['init', '-b', 'main']);
    await git(repository, ['config', 'user.email', 'ruleatlas@example.test']);
    await git(repository, ['config', 'user.name', 'RuleAtlas Test']);
    await writeFile(path.join(repository, 'rule.json'), '{}\n');
    await git(repository, ['add', 'rule.json']);
    await git(repository, ['commit', '-m', 'initial']);
    await git(repository, ['remote', 'add', 'origin', 'git@github.com:splunk/attack_data.git']);
    await writeFile(path.join(repository, 'rule.json'), '{"updated":true}\n');

    const status = await getGitRepositoryStatus(configFor(repository));

    expect(status.isGitRepository).toBe(true);
    expect(status.branch).toBe('main');
    expect(status.clean).toBe(false);
    expect(status.changedFiles[0]).toMatchObject({ path: 'rule.json', worktreeStatus: 'M' });
    expect(status.github).toEqual({ owner: 'splunk', repository: 'attack_data' });
  });

  it.each([
    'https://github.com/splunk/attack_data.git',
    'git@github.com:splunk/attack_data.git',
    'ssh://git@github.com/splunk/attack_data.git',
  ])('parses GitHub remote %s', (remote) => {
    expect(parseGitHubRemote(remote)).toEqual({ owner: 'splunk', repository: 'attack_data' });
  });

  it('rejects Git option injection in remote and branch inputs', () => {
    expect(() => validateGitRemoteName('--upload-pack=malicious')).toThrowError('Remote name contains unsupported characters.');
    expect(() => validateGitBranchName('--exec')).toThrowError('Branch contains unsupported characters');
  });

  it('commits, pushes, and creates a pull request without contacting a real remote', async () => {
    const fixtureRoot = await mkdtemp(path.join(tmpdir(), 'ruleatlas-publish-'));
    temporaryDirectories.push(fixtureRoot);
    const repository = path.join(fixtureRoot, 'working');
    const bareRemote = path.join(fixtureRoot, 'remote.git');
    await mkdir(repository);
    await execFileAsync('git', ['init', '--bare', bareRemote], { cwd: fixtureRoot });
    await git(repository, ['init', '-b', 'main']);
    await git(repository, ['config', 'user.email', 'ruleatlas@example.test']);
    await git(repository, ['config', 'user.name', 'RuleAtlas Test']);
    await writeFile(path.join(repository, 'rule.json'), '{}\n');
    await git(repository, ['add', 'rule.json']);
    await git(repository, ['commit', '-m', 'initial']);
    await git(repository, ['remote', 'add', 'origin', 'https://github.com/example/detections.git']);
    await git(repository, ['remote', 'set-url', '--push', 'origin', bareRemote]);
    await writeFile(path.join(repository, 'rule.json'), '{"updated":true}\n');

    process.env.GITHUB_TOKEN = 'test-token';
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        html_url: 'https://github.com/example/detections/pull/42',
        number: 42,
        state: 'open',
        title: 'Update detection',
      }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await publishPullRequest(configFor(repository), {
      baseBranch: 'main',
      body: 'Tested by RuleAtlas.',
      branch: 'feat/update-detection',
      commitMessage: 'feat(rules): update detection',
      title: 'Update detection',
    });

    expect(result.created).toBe(true);
    expect(result.commitCreated).toBe(true);
    expect(result.pullRequest.url).toBe('https://github.com/example/detections/pull/42');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const remoteCommit = await execFileAsync('git', [
      '--git-dir', bareRemote, 'rev-parse', 'refs/heads/feat/update-detection',
    ]);
    expect(remoteCommit.stdout.trim()).toBe(result.commit);
  });

  it('fetches and fast-forward pulls a clean branch from its remote', async () => {
    const fixtureRoot = await mkdtemp(path.join(tmpdir(), 'ruleatlas-sync-'));
    temporaryDirectories.push(fixtureRoot);
    const repository = path.join(fixtureRoot, 'working');
    const peer = path.join(fixtureRoot, 'peer');
    const bareRemote = path.join(fixtureRoot, 'remote.git');
    await mkdir(repository);
    await execFileAsync('git', ['init', '--bare', bareRemote], { cwd: fixtureRoot });
    await git(repository, ['init', '-b', 'main']);
    await git(repository, ['config', 'user.email', 'ruleatlas@example.test']);
    await git(repository, ['config', 'user.name', 'RuleAtlas Test']);
    await writeFile(path.join(repository, 'rule.json'), '{}\n');
    await git(repository, ['add', 'rule.json']);
    await git(repository, ['commit', '-m', 'initial']);
    await git(repository, ['remote', 'add', 'origin', bareRemote]);
    await git(repository, ['push', '--set-upstream', 'origin', 'main']);

    await execFileAsync('git', ['clone', '--branch', 'main', bareRemote, peer], { cwd: fixtureRoot });
    await git(peer, ['config', 'user.email', 'ruleatlas@example.test']);
    await git(peer, ['config', 'user.name', 'RuleAtlas Test']);
    await writeFile(path.join(peer, 'rule.json'), '{"remote":true}\n');
    await git(peer, ['add', 'rule.json']);
    await git(peer, ['commit', '-m', 'remote update']);
    await git(peer, ['push', 'origin', 'main']);

    const fetched = await fetchGitRepository(configFor(repository));
    expect(fetched.behind).toBe(1);
    const pulled = await pullGitRepository(configFor(repository));
    expect(pulled.behind).toBe(0);
    expect(pulled.clean).toBe(true);
    expect(await readFile(path.join(repository, 'rule.json'), 'utf-8')).toBe('{"remote":true}\n');
  });
});

function configFor(repository: string): RuleRepoConfig {
  return {
    configPath: path.join(repository, 'ruleatlas.config.json'),
    repoPathInput: repository,
    repoPath: repository,
    contentRoot: 'contents',
    contentRootPath: path.join(repository, 'contents'),
    githubRemote: 'origin',
    githubBaseBranch: 'main',
    attackDataPathInput: repository,
    attackDataPath: repository,
    attackDataMaxDatasets: 5,
    splunkHecUrl: '',
    splunkApiUrl: '',
    splunkIndex: 'attack_data',
    splunkVerifyTls: true,
  };
}

async function git(repository: string, args: string[]) {
  await execFileAsync('git', args, { cwd: repository });
}
