import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import {
  readRepositoryStore,
  reserveRuleId,
  writeRepositoryStore,
} from './repositoryStore';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })));
});

describe('repository YAML store', () => {
  it('migrates UUID rule identities and writes canonical category YAML', async () => {
    const location = await createLocation();
    await mkdir(path.join(location.repoPath, 'config'), { recursive: true });
    await writeFile(path.join(location.repoPath, 'config', 'id-sequences.yml'), 'EXEC: 4\n');
    await writeFile(path.join(location.repoPath, 'ruleatlas-store.json'), '{}\n');

    const result = await writeRepositoryStore(location, {
      rules: [{
        id: '08cf5128-3e17-44ce-9087-f27105609360',
        createdAt: '2026-07-08T10:00:00Z',
        updatedAt: '2026-07-14T12:30:00Z',
        data: {
          rule_id: '08cf5128-3e17-44ce-9087-f27105609360',
          name: 'Suspicious PowerShell Download',
          category: 'execution',
          last_reviewed: '2026-07-09',
        },
      }],
    });

    expect(result.store.rules[0]).toMatchObject({
      id: 'EXEC-0005',
      data: {
        rule_id: 'EXEC-0005',
        uuid: '08cf5128-3e17-44ce-9087-f27105609360',
      },
    });
    const rulePath = path.join(
      location.contentRootPath,
      'rules',
      'execution',
      'EXEC-0005-suspicious-powershell-download.yml',
    );
    const document = parseYaml(await readFile(rulePath, 'utf-8')) as Record<string, unknown>;
    expect(document).toMatchObject({
      id: 'EXEC-0005',
      uuid: '08cf5128-3e17-44ce-9087-f27105609360',
      created_at: '2026-07-08T10:00:00Z',
      updated_at: '2026-07-14T12:30:00Z',
    });
    expect(document).not.toHaveProperty('last_reviewed');
    await expect(readFile(path.join(location.repoPath, 'ruleatlas-store.json'))).rejects.toMatchObject({ code: 'ENOENT' });

    const loaded = await readRepositoryStore(location);
    expect(loaded.rules[0]).toMatchObject({
      id: 'EXEC-0005',
      data: { rule_id: 'EXEC-0005', uuid: '08cf5128-3e17-44ce-9087-f27105609360' },
    });
  });

  it('serializes concurrent reservations through the shared sequence file', async () => {
    const location = await createLocation();
    const ids = await Promise.all([
      reserveRuleId(location, 'credential access'),
      reserveRuleId(location, 'credential access'),
      reserveRuleId(location, 'general'),
    ]);

    expect(ids).toEqual(['CRED-0001', 'CRED-0002', 'DET-0001']);
    expect(parseYaml(await readFile(path.join(location.repoPath, 'config', 'id-sequences.yml'), 'utf-8')))
      .toEqual({ CRED: 2, DET: 1 });
  });

  it('reuses the migrated ID when stale clients save the same UUID again', async () => {
    const location = await createLocation();
    const input = {
      rules: [{
        id: '08cf5128-3e17-44ce-9087-f27105609360',
        data: {
          rule_id: '08cf5128-3e17-44ce-9087-f27105609360',
          name: 'Concurrent migration',
          category: 'execution',
        },
      }],
    };

    const first = await writeRepositoryStore(location, structuredClone(input));
    const second = await writeRepositoryStore(location, structuredClone(input));

    expect(first.store.rules[0].id).toBe('EXEC-0001');
    expect(second.store.rules[0].id).toBe('EXEC-0001');
    expect(parseYaml(await readFile(path.join(location.repoPath, 'config', 'id-sequences.yml'), 'utf-8')))
      .toEqual({ EXEC: 1 });
  });
});

async function createLocation() {
  const repoPath = await mkdtemp(path.join(tmpdir(), 'ruleatlas-repository-'));
  temporaryDirectories.push(repoPath);
  return { repoPath, contentRootPath: path.join(repoPath, 'contents') };
}
