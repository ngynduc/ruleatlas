import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, mkdir, open, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { parse as parseYaml } from 'yaml';
import { ApiError } from './http';

const execFileAsync = promisify(execFile);
const mitrePattern = /\bT\d{4}(?:\.\d{3})?\b/gi;
const ignoredTagTerms = new Set(['attack', 'data', 'detection', 'rule', 'splunk', 'test']);

export interface RuleTestInput {
  id?: unknown;
  archived?: unknown;
  data?: Record<string, unknown>;
}

export interface AttackDatasetFile {
  name: string;
  path: string;
  source: string;
  sourcetype: string;
  localPath: string;
  sha256?: string;
}

export interface AttackDataMatch {
  id: string;
  manifestPath: string;
  description: string;
  environment: string;
  techniques: string[];
  matchedTechniques: string[];
  matchedTags: string[];
  score: number;
  datasets: AttackDatasetFile[];
}

export interface AttackDataDiscovery {
  matches: AttackDataMatch[];
  scannedManifests: number;
  selectionMode: 'explicit' | 'mapping';
  warnings: string[];
}

export interface AttackDataCatalogEntry extends Record<string, unknown> {
  id: string;
  manifestId: string;
  manifestPath: string;
  description: string;
  environment: string;
  techniques: string[];
  name: string;
  path: string;
  source: string;
  sourcetype: string;
  sha256?: string;
}

export interface AttackDataCatalog {
  datasets: AttackDataCatalogEntry[];
  maxDatasets: number;
  scannedManifests: number;
  warnings: string[];
}

export type AttackDataPullProgress =
  | { type: 'checking'; totalFiles: number }
  | { type: 'fetching'; paths: string[]; totalFiles: number }
  | { type: 'fetched'; paths: string[]; totalFiles: number }
  | { type: 'ready'; fetchedFiles: number; totalFiles: number };

export async function discoverAttackData(
  attackDataRepo: string,
  rule: RuleTestInput,
  maxDatasets: number,
  selectedDatasetPaths: string[] = [],
): Promise<AttackDataDiscovery> {
  const requestedPaths = normalizeSelectedDatasetPaths(selectedDatasetPaths);
  if (requestedPaths.length > maxDatasets) {
    throw new ApiError(
      422,
      'too_many_datasets',
      `Select no more than ${maxDatasets} attack-data datasets for one test.`,
      { maxDatasets, selectedDatasets: requestedPaths.length },
    );
  }

  const metadata = ruleMetadata(rule);
  if (requestedPaths.length === 0 && metadata.techniques.length === 0 && metadata.tags.length === 0) {
    throw new ApiError(
      422,
      'rule_mapping_missing',
      'Rule must include a MITRE technique or at least one tag/log source before attack-data can be selected.',
    );
  }

  const scan = await scanAttackData(
    attackDataRepo,
    (relativeManifest, parsed) => requestedPaths.length > 0
      ? catalogCandidate(attackDataRepo, relativeManifest, parsed)
      : manifestCandidate(attackDataRepo, relativeManifest, parsed, metadata),
  );

  if (requestedPaths.length > 0) {
    const remaining = new Set(requestedPaths);
    const matches = scan.matches.flatMap((candidate) => {
      const datasets = candidate.datasets.filter((dataset) => {
        if (!remaining.has(dataset.path)) {
          return false;
        }
        remaining.delete(dataset.path);
        return true;
      });
      return datasets.length > 0 ? [{ ...candidate, datasets }] : [];
    });
    const missing = [...remaining];
    if (missing.length > 0) {
      throw new ApiError(
        422,
        'invalid_dataset_selection',
        'One or more selected attack-data datasets are no longer available.',
        { missing },
      );
    }

    return {
      matches,
      scannedManifests: scan.scannedManifests,
      selectionMode: 'explicit',
      warnings: scan.warnings,
    };
  }

  const sorted = scan.matches.sort((left, right) =>
    right.score - left.score || left.manifestPath.localeCompare(right.manifestPath),
  );
  const matches: AttackDataMatch[] = [];
  let selectedDatasets = 0;
  for (const candidate of sorted) {
    const available = Math.max(0, maxDatasets - selectedDatasets);
    if (available === 0) {
      break;
    }
    const datasets = candidate.datasets.slice(0, available);
    if (datasets.length > 0) {
      matches.push({ ...candidate, datasets });
      selectedDatasets += datasets.length;
    }
  }

  return {
    matches,
    scannedManifests: scan.scannedManifests,
    selectionMode: 'mapping',
    warnings: scan.warnings,
  };
}

export async function listAttackData(
  attackDataRepo: string,
  maxDatasets: number,
): Promise<AttackDataCatalog> {
  const scan = await scanAttackData(
    attackDataRepo,
    (relativeManifest, parsed) => catalogCandidate(attackDataRepo, relativeManifest, parsed),
  );
  const datasetsByPath = new Map<string, AttackDataCatalogEntry>();
  for (const match of scan.matches) {
    for (const dataset of match.datasets) {
      if (!datasetsByPath.has(dataset.path)) {
        datasetsByPath.set(dataset.path, {
          id: `${match.manifestPath}:${dataset.path}`,
          manifestId: match.id,
          manifestPath: match.manifestPath,
          description: match.description,
          environment: match.environment,
          techniques: match.techniques,
          name: dataset.name,
          path: dataset.path,
          source: dataset.source,
          sourcetype: dataset.sourcetype,
          ...(dataset.sha256 ? { sha256: dataset.sha256 } : {}),
        });
      }
    }
  }

  return {
    datasets: [...datasetsByPath.values()],
    maxDatasets,
    scannedManifests: scan.scannedManifests,
    warnings: scan.warnings,
  };
}

export async function pullAttackDataFiles(
  attackDataRepo: string,
  matches: AttackDataMatch[],
  onProgress?: (progress: AttackDataPullProgress) => void,
) {
  const files = matches.flatMap((match) => match.datasets);
  onProgress?.({ type: 'checking', totalFiles: files.length });
  if (files.length === 0) {
    onProgress?.({ type: 'ready', fetchedFiles: 0, totalFiles: 0 });
    return { pulled: false, files: [] as AttackDatasetFile[] };
  }

  const pathsToPull: string[] = [];
  const cachedFiles = new Map<string, AttackDatasetFile>();
  for (const file of files) {
    if (!isWithin(attackDataRepo, file.localPath)) {
      throw new ApiError(422, 'invalid_dataset_path', `Dataset path escapes the attack-data repository: ${file.path}`);
    }
    const cached = await verifiedCachedDataset(file);
    if (cached) {
      cachedFiles.set(file.path, cached);
    } else if (!await isMaterializedFile(file.localPath)) {
      pathsToPull.push(relativeGitPath(attackDataRepo, file.localPath));
    }
  }

  if (pathsToPull.length > 0) {
    onProgress?.({ type: 'fetching', paths: pathsToPull, totalFiles: files.length });
    try {
      await execFileAsync('git', ['lfs', 'pull', `--include=${pathsToPull.join(',')}`], {
        cwd: attackDataRepo,
        encoding: 'utf-8',
        maxBuffer: 10 * 1024 * 1024,
        timeout: 10 * 60_000,
      });
    } catch (error) {
      const commandError = error as Error & { stderr?: string };
      throw new ApiError(
        502,
        'attack_data_pull_failed',
        `Unable to pull selected Git LFS data: ${(commandError.stderr || commandError.message).trim()}`,
      );
    }
    onProgress?.({ type: 'fetched', paths: pathsToPull, totalFiles: files.length });
  }

  const materializedFiles: AttackDatasetFile[] = [];
  for (const file of files) {
    const cached = cachedFiles.get(file.path);
    if (cached) {
      materializedFiles.push(cached);
      continue;
    }
    if (!await isMaterializedFile(file.localPath)) {
      throw new ApiError(422, 'dataset_unavailable', `Attack-data file is unavailable after pull: ${file.path}`);
    }
    materializedFiles.push(await cacheDataset(file));
  }

  onProgress?.({ type: 'ready', fetchedFiles: pathsToPull.length, totalFiles: files.length });
  return { pulled: pathsToPull.length > 0, files: materializedFiles };
}

export function normalizeMitreTechniques(value: unknown): string[] {
  const input = Array.isArray(value) ? value.map(String).join(' ') : typeof value === 'string' ? value : '';
  return [...new Set((input.match(mitrePattern) ?? []).map((item) => item.toUpperCase()))];
}

export function normalizeRuleTags(value: unknown): string[] {
  const values = Array.isArray(value) ? value : typeof value === 'string' ? value.split(/[\n,]/) : [];
  return [...new Set(values
    .map(String)
    .map((item) => item.trim().toLowerCase())
    .filter((item) => item.length >= 3 && !ignoredTagTerms.has(item)))];
}

interface RuleMetadata {
  techniques: string[];
  tags: string[];
}

function ruleMetadata(rule: RuleTestInput): RuleMetadata {
  const data = rule.data ?? {};
  const tags = normalizeRuleTags(data.tags);
  const logSource = typeof data.log_source === 'string' ? normalizeRuleTags([data.log_source]) : [];
  return {
    techniques: normalizeMitreTechniques(data.mitre_technique),
    tags: [...new Set([...tags, ...logSource])],
  };
}

function manifestCandidate(
  attackDataRepo: string,
  relativeManifest: string,
  parsed: unknown,
  rule: RuleMetadata,
): AttackDataMatch | null {
  if (!isObject(parsed)) {
    return null;
  }

  const techniques = extractManifestTechniques(parsed, relativeManifest);
  const matchedTechniques = techniques.filter((technique) =>
    rule.techniques.some((ruleTechnique) => techniquesOverlap(technique, ruleTechnique)),
  );
  const haystack = [
    relativeManifest,
    stringValue(parsed.description),
    stringValue(parsed.directory),
    stringValue(parsed.environment),
    JSON.stringify(parsed.datasets ?? parsed.dataset ?? ''),
  ].join(' ').toLowerCase();
  const matchedTags = rule.tags.filter((tag) => haystack.includes(tag));

  if (rule.techniques.length > 0 ? matchedTechniques.length === 0 : matchedTags.length === 0) {
    return null;
  }

  const datasets = extractDatasets(attackDataRepo, parsed);
  if (datasets.length === 0) {
    return null;
  }
  const exactTechniqueMatches = matchedTechniques.filter((technique) => rule.techniques.includes(technique)).length;
  const score = exactTechniqueMatches * 100 + (matchedTechniques.length - exactTechniqueMatches) * 70 + matchedTags.length * 10;

  return {
    id: stringValue(parsed.id) || relativeManifest,
    manifestPath: relativeGitPath(path.join(attackDataRepo, 'datasets'), path.join(attackDataRepo, 'datasets', relativeManifest)),
    description: stringValue(parsed.description),
    environment: stringValue(parsed.environment),
    techniques,
    matchedTechniques,
    matchedTags,
    score,
    datasets,
  };
}

function catalogCandidate(
  attackDataRepo: string,
  relativeManifest: string,
  parsed: unknown,
): AttackDataMatch | null {
  if (!isObject(parsed)) {
    return null;
  }

  const datasets = extractDatasets(attackDataRepo, parsed);
  if (datasets.length === 0) {
    return null;
  }

  return {
    id: stringValue(parsed.id) || relativeManifest,
    manifestPath: relativeGitPath(
      path.join(attackDataRepo, 'datasets'),
      path.join(attackDataRepo, 'datasets', relativeManifest),
    ),
    description: stringValue(parsed.description),
    environment: stringValue(parsed.environment),
    techniques: extractManifestTechniques(parsed, relativeManifest),
    matchedTechniques: [],
    matchedTags: [],
    score: 0,
    datasets,
  };
}

async function scanAttackData(
  attackDataRepo: string,
  candidateFor: (relativeManifest: string, parsed: unknown) => AttackDataMatch | null,
): Promise<{ matches: AttackDataMatch[]; scannedManifests: number; warnings: string[] }> {
  const datasetsRoot = path.join(attackDataRepo, 'datasets');
  await assertDirectory(
    datasetsRoot,
    'attack_data_missing',
    `Attack-data datasets directory was not found at ${datasetsRoot}.`,
  );
  const relativeEntries = await readdir(datasetsRoot, { recursive: true });
  const manifests = relativeEntries
    .filter((entry) => typeof entry === 'string' && /\.ya?ml$/i.test(entry))
    .filter((entry) => path.basename(entry).toLowerCase() !== 'template.yml')
    .sort();
  const matches: AttackDataMatch[] = [];
  const warnings: string[] = [];

  for (const relativeManifest of manifests) {
    const manifestPath = path.join(datasetsRoot, relativeManifest);
    try {
      const raw = await readFile(manifestPath, 'utf-8');
      const parsed = parseYaml(raw) as unknown;
      const candidate = candidateFor(relativeManifest, parsed);
      if (candidate) {
        const repaired = await repairDatasetPaths(attackDataRepo, candidate);
        matches.push({ ...candidate, datasets: repaired.datasets });
        warnings.push(...repaired.warnings);
      }
    } catch (error) {
      if (warnings.length < 25) {
        warnings.push(`${relativeManifest}: ${error instanceof Error ? error.message : 'Unable to parse manifest.'}`);
      }
    }
  }

  return { matches, scannedManifests: manifests.length, warnings };
}

function normalizeSelectedDatasetPaths(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return [...new Set(value
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean))];
}

function extractManifestTechniques(parsed: Record<string, unknown>, relativeManifest: string): string[] {
  const explicit = normalizeMitreTechniques(parsed.mitre_technique);
  const references = normalizeMitreTechniques(parsed.references);
  const pathname = normalizeMitreTechniques(relativeManifest);
  return [...new Set([...explicit, ...references, ...pathname])];
}

function extractDatasets(attackDataRepo: string, parsed: Record<string, unknown>): AttackDatasetFile[] {
  if (Array.isArray(parsed.datasets)) {
    return parsed.datasets.flatMap((value, index) => {
      if (!isObject(value)) {
        return [];
      }
      const datasetPath = stringValue(value.path);
      if (!datasetPath) {
        return [];
      }
      return [{
        name: stringValue(value.name) || path.basename(datasetPath),
        path: datasetPath,
        source: stringValue(value.source) || 'attack_data',
        sourcetype: stringValue(value.sourcetype) || '_json',
        localPath: resolveDatasetPath(attackDataRepo, datasetPath),
        ...(normalizeSha256(value.sha256) ? { sha256: normalizeSha256(value.sha256) } : {}),
      } satisfies AttackDatasetFile];
    });
  }

  const legacyDatasets = arrayStrings(parsed.dataset);
  const legacySourcetypes = arrayStrings(parsed.sourcetypes);
  return legacyDatasets.flatMap((datasetUrl, index) => {
    const datasetPath = legacyDatasetPath(datasetUrl);
    if (!datasetPath) {
      return [];
    }
    return [{
      name: path.basename(datasetPath),
      path: datasetPath,
      source: 'attack_data',
      sourcetype: legacySourcetypes[index] || legacySourcetypes[0] || '_json',
      localPath: resolveDatasetPath(attackDataRepo, datasetPath),
    } satisfies AttackDatasetFile];
  });
}

async function verifiedCachedDataset(file: AttackDatasetFile): Promise<AttackDatasetFile | null> {
  if (!file.sha256) {
    return null;
  }
  const cachePath = datasetCachePath(file.sha256);
  if (!await isMaterializedFile(cachePath)) {
    return null;
  }
  if (await sha256File(cachePath) !== file.sha256) {
    return null;
  }
  return { ...file, localPath: cachePath };
}

async function cacheDataset(file: AttackDatasetFile): Promise<AttackDatasetFile> {
  const sha256 = await sha256File(file.localPath);
  if (file.sha256 && file.sha256 !== sha256) {
    throw new ApiError(
      422,
      'dataset_checksum_mismatch',
      `Dataset checksum does not match its manifest: ${file.path}`,
      { actual: sha256, expected: file.sha256, path: file.path },
    );
  }

  const cachePath = datasetCachePath(sha256);
  await mkdir(path.dirname(cachePath), { recursive: true });
  if (!await isMaterializedFile(cachePath)) {
    const temporaryPath = `${cachePath}.${process.pid}.tmp`;
    await copyFile(file.localPath, temporaryPath);
    await rename(temporaryPath, cachePath);
  }
  await updateDatasetCacheMetadata(file, sha256);
  return { ...file, localPath: cachePath, sha256 };
}

async function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function updateDatasetCacheMetadata(file: AttackDatasetFile, sha256: string): Promise<void> {
  const metadataPath = path.join(datasetCacheRoot(), 'metadata', 'datasets.json');
  let metadata: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(await readFile(metadataPath, 'utf-8')) as unknown;
    if (isObject(parsed)) metadata = parsed;
  } catch {
    // A missing or invalid local cache index is rebuilt from verified files.
  }
  metadata[file.path] = {
    name: file.name,
    path: file.path,
    sha256,
    source: file.source,
    sourcetype: file.sourcetype,
    verified_at: new Date().toISOString(),
  };
  await mkdir(path.dirname(metadataPath), { recursive: true });
  const temporaryPath = `${metadataPath}.${process.pid}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(metadata, null, 2)}\n`, 'utf-8');
  await rename(temporaryPath, metadataPath);
}

function datasetCachePath(sha256: string): string {
  return path.join(datasetCacheRoot(), 'sha256', sha256.slice(0, 2), sha256);
}

function datasetCacheRoot(): string {
  const explicit = process.env.RULEATLAS_DATASET_CACHE?.trim();
  if (explicit) return path.resolve(explicit);
  const base = process.env.XDG_CACHE_HOME?.trim() || path.join(os.homedir(), '.cache');
  return path.join(base, 'ruleatlas', 'datasets');
}

function normalizeSha256(value: unknown): string {
  const checksum = stringValue(value).toLowerCase();
  return /^[0-9a-f]{64}$/.test(checksum) ? checksum : '';
}

async function repairDatasetPaths(
  attackDataRepo: string,
  match: AttackDataMatch,
): Promise<{ datasets: AttackDatasetFile[]; warnings: string[] }> {
  const datasets: AttackDatasetFile[] = [];
  const warnings: string[] = [];

  for (const dataset of match.datasets) {
    const repaired = await repairDatasetPath(attackDataRepo, dataset);
    datasets.push(repaired.dataset);
    if (repaired.warning) {
      warnings.push(`${match.manifestPath}: ${repaired.warning}`);
    }
  }

  return { datasets, warnings };
}

async function repairDatasetPath(
  attackDataRepo: string,
  dataset: AttackDatasetFile,
): Promise<{ dataset: AttackDatasetFile; warning?: string }> {
  if (await isExistingFile(dataset.localPath)) {
    return { dataset };
  }

  const directory = path.dirname(dataset.localPath);
  const expectedStem = path.basename(dataset.name, path.extname(dataset.name)).toLowerCase();
  const expectedExtension = path.extname(dataset.localPath).toLowerCase();
  if (!expectedStem || !expectedExtension) {
    return { dataset };
  }

  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return { dataset };
  }

  const candidates = entries.filter((entry) =>
    entry.isFile()
    && path.extname(entry.name).toLowerCase() === expectedExtension
    && path.basename(entry.name, path.extname(entry.name)).toLowerCase() === expectedStem,
  );
  if (candidates.length !== 1) {
    return { dataset };
  }

  const localPath = path.join(directory, candidates[0].name);
  if (!isWithin(attackDataRepo, localPath)) {
    return { dataset };
  }
  const correctedPath = `/${relativeGitPath(attackDataRepo, localPath)}`;
  return {
    dataset: { ...dataset, localPath, path: correctedPath },
    warning: `Corrected missing dataset path ${dataset.path} to ${correctedPath} using dataset name "${dataset.name}".`,
  };
}

function legacyDatasetPath(value: string): string {
  try {
    const url = new URL(value);
    const marker = '/master/';
    const index = url.pathname.indexOf(marker);
    return index >= 0 ? `/${url.pathname.slice(index + marker.length)}` : '';
  } catch {
    return value.startsWith('/datasets/') ? value : '';
  }
}

function resolveDatasetPath(attackDataRepo: string, datasetPath: string): string {
  const resolved = path.resolve(attackDataRepo, datasetPath.replace(/^[/\\]+/, ''));
  if (!isWithin(attackDataRepo, resolved)) {
    throw new ApiError(422, 'invalid_dataset_path', `Dataset path escapes the attack-data repository: ${datasetPath}`);
  }
  return resolved;
}

function techniquesOverlap(left: string, right: string): boolean {
  return left === right || left.startsWith(`${right}.`) || right.startsWith(`${left}.`);
}

async function isMaterializedFile(filePath: string): Promise<boolean> {
  try {
    const fileStat = await stat(filePath);
    if (!fileStat.isFile() || fileStat.size === 0) {
      return false;
    }
    const handle = await open(filePath, 'r');
    try {
      const header = Buffer.alloc(128);
      const { bytesRead } = await handle.read(header, 0, header.length, 0);
      return !header.subarray(0, bytesRead).toString('utf-8').startsWith('version https://git-lfs.github.com/spec/v1');
    } finally {
      await handle.close();
    }
  } catch {
    return false;
  }
}

async function isExistingFile(filePath: string): Promise<boolean> {
  try {
    return (await stat(filePath)).isFile();
  } catch {
    return false;
  }
}

async function assertDirectory(directory: string, code: string, message: string) {
  try {
    if ((await stat(directory)).isDirectory()) {
      return;
    }
  } catch {
    // Converted to a stable API error below.
  }
  throw new ApiError(422, code, message);
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function relativeGitPath(root: string, filePath: string): string {
  return path.relative(root, filePath).split(path.sep).join('/');
}

function arrayStrings(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map(String).map((item) => item.trim()).filter(Boolean);
  }
  return typeof value === 'string' && value.trim() ? [value.trim()] : [];
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : '';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
