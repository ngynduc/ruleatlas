import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  discoverAttackData,
  listAttackData,
  normalizeMitreTechniques,
  normalizeRuleTags,
  pullAttackDataFiles,
} from './attackData';
import type { AttackDataPullProgress } from './attackData';

const temporaryDirectories: string[] = [];

beforeEach(async () => {
  const cache = await mkdtemp(path.join(tmpdir(), 'ruleatlas-dataset-cache-'));
  temporaryDirectories.push(cache);
  process.env.RULEATLAS_DATASET_CACHE = cache;
});

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })));
  delete process.env.RULEATLAS_DATASET_CACHE;
});

describe('attack-data discovery', () => {
  it('selects MITRE matches and uses tags to rank matching manifests', async () => {
    const repository = await createAttackDataFixture();
    const discovery = await discoverAttackData(repository, {
      id: 'RA-1',
      data: {
        log_source: 'Sysmon',
        mitre_technique: 'T1053.005',
        tags: ['scheduled task', 'windows'],
      },
    }, 2);

    expect(discovery.scannedManifests).toBe(2);
    expect(discovery.selectionMode).toBe('mapping');
    expect(discovery.matches).toHaveLength(1);
    expect(discovery.matches[0].matchedTechniques).toEqual(['T1053.005']);
    expect(discovery.matches[0].matchedTags).toContain('scheduled task');
    expect(discovery.matches[0].datasets[0].sourcetype).toBe('XmlWinEventLog');
  });

  it('normalizes technique and tag inputs without duplicates', () => {
    expect(normalizeMitreTechniques('T1053, t1053.005 and T1053')).toEqual(['T1053', 'T1053.005']);
    expect(normalizeRuleTags([' Windows ', 'windows', 'test', 'PowerShell'])).toEqual(['windows', 'powershell']);
  });

  it('uses explicit dataset paths instead of rule mapping when selected', async () => {
    const repository = await createAttackDataFixture();
    const discovery = await discoverAttackData(repository, {
      data: {},
    }, 2, [
      '/datasets/attack_techniques/T1003/credential_dump/credential_dump.log',
    ]);

    expect(discovery.selectionMode).toBe('explicit');
    expect(discovery.matches).toHaveLength(1);
    expect(discovery.matches[0].techniques).toEqual(['T1003']);
    expect(discovery.matches[0].matchedTechniques).toEqual([]);
    expect(discovery.matches[0].datasets[0].name).toBe('credential-dump');
  });

  it('lists selectable datasets without requiring rule metadata', async () => {
    const repository = await createAttackDataFixture();
    const catalog = await listAttackData(repository, 5);

    expect(catalog.scannedManifests).toBe(2);
    expect(catalog.maxDatasets).toBe(5);
    expect(catalog.datasets).toHaveLength(2);
    expect(catalog.datasets.map((dataset) => dataset.path)).toContain(
      '/datasets/attack_techniques/T1053.005/scheduled_task/windows-sysmon.log',
    );
  });

  it('repairs a missing manifest path when a sibling file matches the dataset name', async () => {
    const repository = await mkdtemp(path.join(tmpdir(), 'ruleatlas-attack-data-'));
    temporaryDirectories.push(repository);
    const datasetDirectory = path.join(repository, 'datasets', 'attack_techniques', 'T1003', 'snapattack');
    await mkdir(datasetDirectory, { recursive: true });
    await writeFile(path.join(datasetDirectory, 'snapattack.log'), 'event data\n');
    await writeFile(path.join(datasetDirectory, 'snapattack.yml'), `
description: Credential dumping
mitre_technique: [T1003]
datasets:
  - name: snapattack
    path: /datasets/attack_techniques/T1003/snapattack/snaattack.log
    sourcetype: XmlWinEventLog
    source: XmlWinEventLog:Security
`);

    const discovery = await discoverAttackData(repository, {
      data: { mitre_technique: 'T1003' },
    }, 1);
    const progress: AttackDataPullProgress[] = [];
    const materialized = await pullAttackDataFiles(
      repository,
      discovery.matches,
      (event) => progress.push(event),
    );

    expect(discovery.matches[0].datasets[0].path).toBe(
      '/datasets/attack_techniques/T1003/snapattack/snapattack.log',
    );
    expect(discovery.warnings).toContainEqual(expect.stringContaining('Corrected missing dataset path'));
    expect(materialized.files[0].localPath).toContain(path.join('sha256'));
    expect(await readFile(materialized.files[0].localPath, 'utf-8')).toBe('event data\n');
    expect(materialized.pulled).toBe(false);
    expect(progress).toEqual([
      { type: 'checking', totalFiles: 1 },
      { type: 'ready', fetchedFiles: 0, totalFiles: 1 },
    ]);
  });

  it('reuses a verified content-addressed cache and rejects checksum mismatches', async () => {
    const repository = await mkdtemp(path.join(tmpdir(), 'ruleatlas-attack-data-'));
    const cache = await mkdtemp(path.join(tmpdir(), 'ruleatlas-dataset-cache-'));
    temporaryDirectories.push(repository, cache);
    process.env.RULEATLAS_DATASET_CACHE = cache;
    const directory = path.join(repository, 'datasets', 'attack_techniques', 'T1059.001', 'test');
    await mkdir(directory, { recursive: true });
    const body = 'verified event\n';
    const checksum = createHash('sha256').update(body).digest('hex');
    await writeFile(path.join(directory, 'events.log'), body);
    await writeFile(path.join(directory, 'manifest.yml'), `
mitre_technique: [T1059.001]
datasets:
  - name: events
    path: /datasets/attack_techniques/T1059.001/test/events.log
    sha256: ${checksum}
`);
    const discovery = await discoverAttackData(repository, { data: { mitre_technique: 'T1059.001' } }, 1);
    const first = await pullAttackDataFiles(repository, discovery.matches);
    await writeFile(path.join(directory, 'events.log'), 'changed source\n');
    const second = await pullAttackDataFiles(repository, discovery.matches);

    expect(second.files[0].localPath).toBe(first.files[0].localPath);
    expect(await readFile(second.files[0].localPath, 'utf-8')).toBe(body);
    expect(second.files[0].sha256).toBe(checksum);

    const bad = structuredClone(discovery.matches);
    bad[0].datasets[0].sha256 = '0'.repeat(64);
    await expect(pullAttackDataFiles(repository, bad)).rejects.toMatchObject({
      code: 'dataset_checksum_mismatch',
    });
  });
});

async function createAttackDataFixture() {
  const repository = await mkdtemp(path.join(tmpdir(), 'ruleatlas-attack-data-'));
  temporaryDirectories.push(repository);
  const matchingDirectory = path.join(repository, 'datasets', 'attack_techniques', 'T1053.005', 'scheduled_task');
  const otherDirectory = path.join(repository, 'datasets', 'attack_techniques', 'T1003', 'credential_dump');
  await mkdir(matchingDirectory, { recursive: true });
  await mkdir(otherDirectory, { recursive: true });
  await writeFile(path.join(matchingDirectory, 'windows-sysmon.log'), 'event data\n');
  await writeFile(path.join(matchingDirectory, 'scheduled_task.yml'), `
author: RuleAtlas
id: 11111111-1111-1111-1111-111111111111
date: '2026-07-13'
description: Windows scheduled task created through PowerShell
environment: lab
directory: scheduled_task
mitre_technique:
  - T1053.005
datasets:
  - name: windows-sysmon
    path: /datasets/attack_techniques/T1053.005/scheduled_task/windows-sysmon.log
    sourcetype: XmlWinEventLog
    source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
`);
  await writeFile(path.join(otherDirectory, 'credential_dump.log'), 'other event\n');
  await writeFile(path.join(otherDirectory, 'credential_dump.yml'), `
author: RuleAtlas
id: 22222222-2222-2222-2222-222222222222
date: '2026-07-13'
description: Credential dumping
environment: lab
mitre_technique: [T1003]
datasets:
  - name: credential-dump
    path: /datasets/attack_techniques/T1003/credential_dump/credential_dump.log
    sourcetype: XmlWinEventLog
    source: Security
`);
  return repository;
}
