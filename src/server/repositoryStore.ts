import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

export interface StoredRecord {
  id?: unknown;
  archived?: unknown;
  createdAt?: unknown;
  updatedAt?: unknown;
  data?: Record<string, unknown>;
}

export type StorePayload = Record<string, StoredRecord[]>;

interface RepositoryLocation {
  repoPath: string;
  contentRootPath: string;
}

interface SequenceFile {
  [prefix: string]: unknown;
}

const legacyStoreFileName = 'ruleatlas-store.json';
const ruleIdPattern = /^([A-Z][A-Z0-9]*)-(\d{4,})$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const templateFolders: Record<string, string> = {
  dataSources: 'data-sources',
  detectionObjectives: 'detection-objectives',
  inventory: 'inventories',
  mitreMappings: 'mitre-mappings',
  owners: 'owners',
  rules: 'rules',
};
const legacyFolderStoreKeys: Record<string, string> = {
  inventory: 'inventory',
  'existing-rules': 'rules',
  'new-rules': 'rules',
};
const categoryPrefixes: Record<string, string> = {
  execution: 'EXEC',
  persistence: 'PERS',
  'privilege escalation': 'PRIV',
  'defense evasion': 'DEFE',
  'credential access': 'CRED',
  discovery: 'DISC',
  'lateral movement': 'LAT',
  collection: 'COLL',
  'command and control': 'C2',
  exfiltration: 'EXFIL',
  impact: 'IMPACT',
};

let sequenceQueue = Promise.resolve();

export function repositoryStorePath(location: RepositoryLocation): string {
  return location.contentRootPath;
}

export async function readRepositoryStore(location: RepositoryLocation): Promise<StorePayload> {
  const output: StorePayload = {};

  try {
    const folders = await readdir(location.contentRootPath, { withFileTypes: true });
    for (const folder of folders) {
      if (!folder.isDirectory()) {
        continue;
      }
      const storeKey = storeKeyForFolder(folder.name);
      if (!storeKey) {
        continue;
      }
      const folderPath = path.join(location.contentRootPath, folder.name);
      const documents = await documentPaths(folderPath);
      output[storeKey] = output[storeKey] ?? [];
      for (const documentPath of documents) {
        const parsed = await readDocument(documentPath);
        if (isObject(parsed)) {
          output[storeKey].push(recordFromDocument(parsed, storeKey));
        }
      }
    }
  } catch (error) {
    if (isMissingFile(error)) {
      return output;
    }
    throw error;
  }

  return output;
}

export async function writeRepositoryStore(
  location: RepositoryLocation,
  input: unknown,
): Promise<{ savedFiles: string[]; store: StorePayload }> {
  return withSequenceLock(async () => {
    const store = normalizeStore(input);
    const sequences = await readSequences(location);
    const currentStore = await readRepositoryStore(location);
    const existingIdsByUuid = ruleIdsByUuid(currentStore.rules ?? []);
    migrateRuleIdentities(store.rules ?? [], sequences, existingIdsByUuid);

    await mkdir(location.contentRootPath, { recursive: true });
    const savedFiles: string[] = [];
    const sequencePath = await writeSequences(location, sequences);
    savedFiles.push(sequencePath);

    for (const [storeKey, records] of Object.entries(store)) {
      const folder = templateFolders[storeKey] ?? slugify(storeKey);
      const targetFolder = path.join(location.contentRootPath, folder);
      await mkdir(targetFolder, { recursive: true });
      await removeManagedDocuments(targetFolder);

      for (const record of records) {
        if (record.archived === true) {
          continue;
        }
        const document = recordDocument(record, storeKey);
        const filePath = recordPath(targetFolder, record, storeKey);
        await writeYaml(filePath, document);
        savedFiles.push(filePath);
      }
    }

    await removeLegacyStore(location.repoPath);
    return { savedFiles, store };
  });
}

export async function reserveRuleId(location: RepositoryLocation, category: unknown): Promise<string> {
  return withSequenceLock(async () => {
    const sequences = await readSequences(location);
    const prefix = prefixForCategory(category);
    const next = (sequences[prefix] ?? 0) + 1;
    sequences[prefix] = next;
    await writeSequences(location, sequences);
    return formatRuleId(prefix, next);
  });
}

function migrateRuleIdentities(
  records: StoredRecord[],
  sequences: Record<string, number>,
  existingIdsByUuid: Map<string, string>,
): void {
  for (const record of records) {
    const data = record.data ?? {};
    const currentRuleId = stringValue(data.rule_id) || stringValue(record.id);
    const match = currentRuleId.match(ruleIdPattern);
    if (match) {
      sequences[match[1]] = Math.max(sequences[match[1]] ?? 0, Number(match[2]));
    }
  }

  for (const record of records) {
    const data = record.data ?? {};
    const currentRuleId = stringValue(data.rule_id) || stringValue(record.id);
    if (ruleIdPattern.test(currentRuleId)) {
      data.uuid = validUuid(data.uuid) || validUuid(record.id) || randomUUID();
      data.rule_id = currentRuleId;
      record.id = currentRuleId;
      record.data = data;
      continue;
    }

    const uuid = validUuid(data.uuid) || validUuid(currentRuleId) || randomUUID();
    const existingRuleId = existingIdsByUuid.get(uuid);
    if (existingRuleId) {
      data.uuid = uuid;
      data.rule_id = existingRuleId;
      record.id = existingRuleId;
      record.data = data;
      continue;
    }

    const prefix = prefixForCategory(data.category);
    const next = (sequences[prefix] ?? 0) + 1;
    sequences[prefix] = next;
    const ruleId = formatRuleId(prefix, next);
    data.uuid = uuid;
    data.rule_id = ruleId;
    record.id = ruleId;
    record.data = data;
  }
}

function ruleIdsByUuid(records: StoredRecord[]): Map<string, string> {
  const ids = new Map<string, string>();
  for (const record of records) {
    const ruleId = stringValue(record.data?.rule_id) || stringValue(record.id);
    const uuid = validUuid(record.data?.uuid);
    if (uuid && ruleIdPattern.test(ruleId)) ids.set(uuid, ruleId);
  }
  return ids;
}

function recordFromDocument(input: Record<string, unknown>, storeKey: string): StoredRecord {
  const wrappedData = isObject(input.rule) ? input.rule : isObject(input.data) ? input.data : input;
  const data = { ...wrappedData };
  const createdAt = stringValue(input.createdAt) || stringValue(input.created_at) || stringValue(data.created_at);
  const updatedAt = stringValue(input.updatedAt) || stringValue(input.updated_at) || stringValue(data.updated_at);
  delete data.created_at;
  delete data.updated_at;

  if (storeKey === 'rules') {
    const diskId = stringValue(data.id);
    data.rule_id = stringValue(data.rule_id) || (uuidPattern.test(diskId) ? '' : diskId);
    data.uuid = validUuid(data.uuid) || (uuidPattern.test(diskId) ? diskId : '');
    delete data.id;
  }

  return {
    id: stringValue(input.id) || stringValue(data.rule_id) || stringValue(data.name),
    archived: input.archived === true,
    createdAt: createdAt || new Date().toISOString(),
    updatedAt: updatedAt || createdAt || new Date().toISOString(),
    data,
  };
}

function recordDocument(record: StoredRecord, storeKey: string): Record<string, unknown> {
  const data = { ...(record.data ?? {}) };
  delete data.last_review;
  delete data.last_reviewed;
  const createdAt = stringValue(record.createdAt) || new Date().toISOString();
  const updatedAt = stringValue(record.updatedAt) || createdAt;

  if (storeKey === 'rules') {
    const ruleId = stringValue(data.rule_id) || stringValue(record.id);
    delete data.rule_id;
    return {
      id: ruleId,
      uuid: validUuid(data.uuid) || randomUUID(),
      ...withoutKey(data, 'uuid'),
      created_at: createdAt,
      updated_at: updatedAt,
    };
  }

  return {
    ...data,
    created_at: createdAt,
    updated_at: updatedAt,
  };
}

function recordPath(targetFolder: string, record: StoredRecord, storeKey: string): string {
  const data = record.data ?? {};
  const name = stringValue(data.name) || stringValue(data.title) || 'record';
  if (storeKey === 'rules') {
    const ruleId = stringValue(data.rule_id) || stringValue(record.id);
    const categoryFolder = slugify(stringValue(data.category) || 'general');
    return path.join(targetFolder, categoryFolder, `${ruleId}-${slugify(name)}.yml`);
  }
  return path.join(targetFolder, `${slugify(stringValue(record.id) || name)}.yml`);
}

function normalizeStore(input: unknown): StorePayload {
  if (!isObject(input)) {
    return {};
  }
  const source = isObject(input.templates) ? input.templates : input;
  const output: StorePayload = {};
  for (const [key, value] of Object.entries(source)) {
    const normalizedKey = key === 'newRules' || key === 'existingRules' ? 'rules' : key;
    const records = Array.isArray(value) ? value.filter(isObject) as StoredRecord[] : [];
    output[normalizedKey] = [...(output[normalizedKey] ?? []), ...records];
  }
  if (output.rules) {
    output.rules = dedupeRecords(output.rules);
  }
  return output;
}

function dedupeRecords(records: StoredRecord[]): StoredRecord[] {
  const recordsByKey = new Map<string, StoredRecord>();
  for (const record of records) {
    const key = stringValue(record.id) || stringValue(record.data?.rule_id) || JSON.stringify(record);
    recordsByKey.set(key, record);
  }
  return [...recordsByKey.values()];
}

async function documentPaths(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true, recursive: true });
  return entries
    .filter((entry) => entry.isFile() && /\.(?:json|ya?ml)$/i.test(entry.name))
    .map((entry) => path.join(entry.parentPath, entry.name))
    .sort();
}

async function readDocument(filePath: string): Promise<unknown> {
  const raw = await readFile(filePath, 'utf-8');
  return filePath.endsWith('.json') ? JSON.parse(raw) : parseYaml(raw);
}

async function removeManagedDocuments(root: string): Promise<void> {
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true, recursive: true });
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  await Promise.all(entries
    .filter((entry) => entry.isFile() && /\.(?:json|ya?ml)$/i.test(entry.name))
    .map((entry) => unlink(path.join(entry.parentPath, entry.name))));
}

async function readSequences(location: RepositoryLocation): Promise<Record<string, number>> {
  const filePath = sequenceFilePath(location);
  try {
    const parsed = parseYaml(await readFile(filePath, 'utf-8')) as SequenceFile;
    if (!isObject(parsed)) return {};
    return Object.fromEntries(Object.entries(parsed).flatMap(([key, value]) => {
      const numeric = Number(value);
      return /^[A-Z][A-Z0-9]*$/.test(key) && Number.isInteger(numeric) && numeric >= 0
        ? [[key, numeric]]
        : [];
    }));
  } catch (error) {
    if (isMissingFile(error)) return {};
    throw error;
  }
}

async function writeSequences(location: RepositoryLocation, sequences: Record<string, number>): Promise<string> {
  const filePath = sequenceFilePath(location);
  const sorted = Object.fromEntries(Object.entries(sequences).sort(([left], [right]) => left.localeCompare(right)));
  await writeYaml(filePath, sorted);
  return filePath;
}

async function writeYaml(filePath: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  const temporaryPath = `${filePath}.${process.pid}.tmp`;
  await writeFile(temporaryPath, stringifyYaml(value, { lineWidth: 0 }), 'utf-8');
  await rename(temporaryPath, filePath);
}

async function removeLegacyStore(repoPath: string): Promise<void> {
  try {
    await unlink(path.join(repoPath, legacyStoreFileName));
  } catch (error) {
    if (!isMissingFile(error)) throw error;
  }
}

function withSequenceLock<T>(operation: () => Promise<T>): Promise<T> {
  const result = sequenceQueue.then(operation, operation);
  sequenceQueue = result.then(() => undefined, () => undefined);
  return result;
}

function sequenceFilePath(location: RepositoryLocation): string {
  return path.join(location.repoPath, 'config', 'id-sequences.yml');
}

function storeKeyForFolder(folder: string): string | undefined {
  return legacyFolderStoreKeys[folder]
    ?? Object.entries(templateFolders).find(([, candidate]) => candidate === folder)?.[0];
}

function prefixForCategory(value: unknown): string {
  return categoryPrefixes[stringValue(value).toLowerCase()] ?? 'DET';
}

function formatRuleId(prefix: string, sequence: number): string {
  return `${prefix}-${String(sequence).padStart(4, '0')}`;
}

function validUuid(value: unknown): string {
  const candidate = stringValue(value);
  return uuidPattern.test(candidate) ? candidate : '';
}

function withoutKey(input: Record<string, unknown>, key: string): Record<string, unknown> {
  const output = { ...input };
  delete output[key];
  return output;
}

function slugify(value: string): string {
  return value.toLowerCase().replace(/https?:\/\//g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 96) || 'record';
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : '';
}

function isMissingFile(error: unknown): boolean {
  return isObject(error) && error.code === 'ENOENT';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
