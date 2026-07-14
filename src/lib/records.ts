import { defaultTemplateId, getTemplate, templates } from '../data/templates';
import type {
  RecordValue,
  TemplateDefinition,
  TemplateExport,
  TemplateField,
  TemplateRecord,
  TemplateStore,
  ValidationErrors,
} from '../types';

const storeKeys = new Set(templates.map((template) => template.storageKey));
const legacyRuleStorageKeys = ['newRules', 'existingRules'];
const legacyRuleTemplateIds = ['new-rule', 'existing-rule'];

export function routeToTemplateId(pathname: string): string {
  const [, root, leaf] = pathname.split('/');

  if (root !== 'templates') {
    return defaultTemplateId;
  }

  if (leaf === 'import-export') {
    return 'import-export';
  }
  if (leaf === 'config') {
    return 'config';
  }
  if (leaf === 'repository') {
    return 'repository';
  }
  if (leaf === 'tests') {
    return 'tests';
  }
  if (leaf && legacyRuleTemplateIds.includes(leaf)) {
    return defaultTemplateId;
  }

  return templates.some((template) => template.id === leaf) ? leaf : defaultTemplateId;
}

export function templatePath(templateId: string): string {
  return `/templates/${templateId}`;
}

export function emptyStore(): TemplateStore {
  return templates.reduce<TemplateStore>((store, template) => {
    store[template.storageKey] = [];
    return store;
  }, {});
}

export function createRuleUuid(): string {
  return createUuid();
}

export function createBlankRecord(template: TemplateDefinition): TemplateRecord {
  const now = new Date().toISOString();
  const data = template.fields.reduce<Record<string, RecordValue>>((recordData, field) => {
    recordData[field.key] = defaultValue(field);
    return recordData;
  }, {});
  const uuid = template.id === 'rules' ? String(data.uuid || createRuleUuid()) : '';

  return {
    id: uuid || `${template.id}-${Date.now()}`,
    data,
    archived: false,
    createdAt: now,
    updatedAt: now,
  };
}

function defaultValue(field: TemplateField): RecordValue {
  if (field.key === 'rule_id') {
    return '';
  }
  if (field.key === 'uuid') {
    return createRuleUuid();
  }
  if (field.type === 'boolean') {
    return false;
  }
  if (field.type === 'number') {
    return 0;
  }
  if (field.type === 'tags' || field.type === 'multiselect') {
    return [];
  }
  return field.options?.[0] ?? '';
}

export function coerceRecord(input: unknown, template: TemplateDefinition): TemplateRecord {
  const fallback = createBlankRecord(template);

  if (!isObject(input)) {
    return fallback;
  }

  const rawData = inputData(input, template);
  const data = template.fields.reduce<Record<string, RecordValue>>((recordData, field) => {
    recordData[field.key] = coerceValue(rawData[field.key], field);
    return recordData;
  }, {});
  if (template.id === 'rules') {
    const legacyUuid = isUuid(data.rule_id) ? String(data.rule_id) : '';
    data.uuid = isUuid(data.uuid) ? data.uuid : legacyUuid || createRuleUuid();
    data.rule_id = isRuleId(data.rule_id) ? data.rule_id : '';
  }
  const recordId = template.id === 'rules'
    ? String(data.rule_id || data.uuid)
    : stringOr(input.id, stringOr(rawData.id, fallback.id));

  return {
    id: recordId,
    data,
    archived: typeof input.archived === 'boolean' ? input.archived : false,
    createdAt: stringOr(input.createdAt, stringOr(input.created_at, fallback.createdAt)),
    updatedAt: stringOr(input.updatedAt, stringOr(input.updated_at, fallback.updatedAt)),
  };
}

export function coerceValue(value: unknown, field: TemplateField): RecordValue {
  if (field.type === 'boolean') {
    return Boolean(value);
  }
  if (field.type === 'number') {
    if (typeof value === 'number') {
      return Number.isFinite(value) ? value : 0;
    }
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  if (field.type === 'tags' || field.type === 'multiselect') {
    return parseList(value);
  }
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return '';
}

export function parseList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map(String).map((item) => item.trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return [String(value)];
  }
  return [];
}

export function normalizeStore(input: unknown): TemplateStore {
  if (!isObject(input)) {
    return emptyStore();
  }

  return templates.reduce<TemplateStore>((store, template) => {
    store[template.storageKey] = recordsForTemplate(input, template).map((record) =>
      coerceRecord(record, template),
    );
    return store;
  }, emptyStore());
}

export function importStorePayload(input: unknown): TemplateStore {
  if (isObject(input) && isObject(input.templates)) {
    return normalizeStore(input.templates);
  }
  return normalizeStore(input);
}

export function exportStore(store: TemplateStore): TemplateExport {
  return {
    exportedAt: new Date().toISOString(),
    version: 1,
    templates: normalizeStore(store),
  };
}

export function importTemplateRecords(
  template: TemplateDefinition,
  input: unknown,
): TemplateRecord[] {
  const records = recordsFromPayload(template, input);
  return records.map((record) => coerceRecord(record, template));
}

function recordsFromPayload(template: TemplateDefinition, input: unknown): unknown[] {
  if (Array.isArray(input)) {
    return input;
  }
  if (isObject(input) && Array.isArray(input.records)) {
    return input.records;
  }
  if (isObject(input) && Array.isArray(input[template.storageKey])) {
    return input[template.storageKey] as unknown[];
  }
  if (isObject(input) && isObject(input.templates)) {
    return recordsForTemplate(input.templates, template);
  }
  if (isObject(input)) {
    return [input];
  }
  return [];
}

function recordsForTemplate(
  input: Record<string, unknown>,
  template: TemplateDefinition,
): unknown[] {
  const records = input[template.storageKey];
  const current = Array.isArray(records) ? records : [];

  if (template.storageKey !== 'rules') {
    return current;
  }

  const legacy = legacyRuleStorageKeys.flatMap((storageKey) => {
    const legacyRecords = input[storageKey];
    return Array.isArray(legacyRecords) ? legacyRecords : [];
  });

  return dedupeRecords([...current, ...legacy]);
}

function dedupeRecords(records: unknown[]): unknown[] {
  const recordsByKey = new Map<string, unknown>();

  for (const record of records) {
    recordsByKey.set(recordKey(record), record);
  }

  return [...recordsByKey.values()];
}

function inputData(
  input: Record<string, unknown>,
  template: TemplateDefinition,
): Record<string, unknown> {
  if (isObject(input.data)) {
    return input.data;
  }

  const source = isObject(input.result) ? input.result : input;
  if (template.id === 'rules') {
    return ruleDataFromObject(source);
  }

  return source;
}

function ruleDataFromObject(source: Record<string, unknown>): Record<string, unknown> {
  const title = stringValue(source.title) || savedSearchName(source.id);
  const owner = stringValue(source.owner) || stringValue(source.author) || stringValue(source['eai:acl.owner']);
  const platform = stringValue(source.platform) || (hasAnySplunkField(source) ? 'Splunk' : '');
  const query = queryText(source);
  const sourceId = stringValue(source.id);
  const ruleId = stringValue(source.rule_id) || (isRuleId(sourceId) ? sourceId : '');
  const uuid = stringValue(source.uuid) || (isUuid(sourceId) ? sourceId : createRuleUuid());

  return {
    ...source,
    rule_id: ruleId,
    uuid,
    name: stringValue(source.name) || title,
    description: stringValue(source.description),
    owner,
    status: statusValue(source),
    severity: severityValue(source),
    platform,
    product: stringValue(source.product),
    log_source: stringValue(source.log_source) || platform || 'Splunk saved search',
    mitre_tactic: firstListValue(source.mitre_tactic, source['mitre.tactics'], source.mitre),
    mitre_technique: firstListValue(
      source.mitre_technique,
      source['mitre.techniques'],
      source.mitre,
      'techniques',
    ),
    query,
    tags: source.tags,
  };
}

function statusValue(source: Record<string, unknown>): string {
  const status = stringValue(source.status).toLowerCase();
  if (['draft', 'testing', 'enabled', 'disabled', 'deprecated'].includes(status)) {
    return status;
  }

  if ('enabled' in source) {
    return boolValue(source.enabled) ? 'enabled' : 'disabled';
  }
  if ('disabled' in source) {
    return boolValue(source.disabled) ? 'disabled' : 'enabled';
  }
  return 'draft';
}

function severityValue(source: Record<string, unknown>): string {
  const severity = source.severity ?? source['alert.severity'];
  const normalized = stringValue(severity).toLowerCase();

  if (['critical', 'high', 'medium', 'low', 'informational'].includes(normalized)) {
    return normalized;
  }

  const numeric = Number(normalized);
  if (numeric >= 5) {
    return 'critical';
  }
  if (numeric === 4) {
    return 'high';
  }
  if (numeric === 3) {
    return 'medium';
  }
  if (numeric === 2) {
    return 'low';
  }
  if (numeric === 1) {
    return 'informational';
  }

  return 'medium';
}

function queryText(source: Record<string, unknown>): string {
  if (isObject(source.query)) {
    return stringValue(source.query.search);
  }
  return stringValue(source.query) || stringValue(source.search) || stringValue(source.qualifiedSearch);
}

function firstListValue(
  primary: unknown,
  secondary: unknown,
  mitre: unknown,
  mitreKey = 'tactics',
): string {
  const direct = parseList(primary)[0] ?? parseList(secondary)[0];
  if (direct) {
    return direct;
  }
  if (isObject(mitre)) {
    return parseList(mitre[mitreKey])[0] ?? '';
  }
  return '';
}

function savedSearchName(value: unknown): string {
  const text = stringValue(value);
  if (!text) {
    return '';
  }

  const lastSegment = text.split('/').filter(Boolean).pop() ?? text;
  try {
    return decodeURIComponent(lastSegment);
  } catch {
    return lastSegment;
  }
}

function hasAnySplunkField(source: Record<string, unknown>): boolean {
  return ['search', 'qualifiedSearch', 'cron_schedule', 'dispatch.earliest_time'].some(
    (field) => field in source,
  );
}

function boolValue(value: unknown): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }
  if (typeof value === 'string') {
    return ['1', 'true', 'yes', 'y', 'on', 'enabled'].includes(value.trim().toLowerCase());
  }
  return false;
}

function stringValue(value: unknown): string {
  if (typeof value === 'string') {
    return value.trim();
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return '';
}

export function fieldByKey(
  template: TemplateDefinition,
  fieldKey: string,
): TemplateField | undefined {
  return template.fields.find((field) => field.key === fieldKey);
}

export function formatValue(value: RecordValue | undefined): string {
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  if (typeof value === 'boolean') {
    return value ? 'Yes' : 'No';
  }
  if (typeof value === 'number') {
    return String(value);
  }
  return value ?? '';
}

export function recordLabel(record: TemplateRecord): string {
  const candidates = [
    record.data.name,
    record.data.rule_id,
    record.data.asset_id,
    record.data.source_id,
    record.data.objective_id,
    record.data.mapping_id,
    record.data.owner_id,
  ];

  return candidates.map(formatValue).find(Boolean) ?? record.id;
}

export function validateRecord(
  template: TemplateDefinition,
  record: TemplateRecord,
): ValidationErrors {
  return template.fields.reduce<ValidationErrors>((errors, field) => {
    const value = record.data[field.key];
    const emptyArray = Array.isArray(value) && value.length === 0;
    const emptyScalar = value == null || value === '';

    if (field.required && (emptyArray || emptyScalar)) {
      errors[field.key] = `${field.label} is required.`;
    }

    return errors;
  }, {});
}

export function filterRecords(
  template: TemplateDefinition,
  records: TemplateRecord[],
  searchTerm: string,
  filters: Record<string, string>,
  showArchived: boolean,
): TemplateRecord[] {
  const search = searchTerm.trim().toLowerCase();

  return records.filter((record) => {
    if (!showArchived && record.archived) {
      return false;
    }

    if (search && !Object.values(record.data).some((value) => formatValue(value).toLowerCase().includes(search))) {
      return false;
    }

    return template.filterFields.every((fieldKey) => {
      const selected = filters[fieldKey] ?? 'all';
      if (selected === 'all') {
        return true;
      }

      const value = record.data[fieldKey];
      return Array.isArray(value) ? value.includes(selected) : String(value) === selected;
    });
  });
}

export function filterOptions(
  template: TemplateDefinition,
  records: TemplateRecord[],
  fieldKey: string,
): string[] {
  const field = fieldByKey(template, fieldKey);
  if (field?.options) {
    return [...field.options];
  }

  const values = new Set<string>();
  for (const record of records) {
    const value = record.data[fieldKey];
    if (Array.isArray(value)) {
      value.forEach((item) => values.add(item));
    } else if (value !== undefined && value !== '') {
      values.add(String(value));
    }
  }

  return [...values].sort((a, b) => a.localeCompare(b));
}

export function updateStoreRecords(
  store: TemplateStore,
  template: TemplateDefinition,
  records: TemplateRecord[],
): TemplateStore {
  return {
    ...store,
    [template.storageKey]: records,
  };
}

export function getTemplateRecords(
  store: TemplateStore,
  templateId: string,
): TemplateRecord[] {
  const template = getTemplate(templateId);
  return store[template.storageKey] ?? [];
}

export function isKnownStoreKey(key: string): boolean {
  return storeKeys.has(key);
}

function recordKey(record: unknown): string {
  if (!isObject(record)) {
    return JSON.stringify(record);
  }

  const data = isObject(record.data) ? record.data : record;
  return (
    stringOr(record.id, '') ||
    stringOr(data.rule_id, '') ||
    stringOr(data.name, '') ||
    stringOr(data.title, '') ||
    JSON.stringify(record)
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

function createUuid(): string {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }

  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (token) => {
    const random = Math.floor(Math.random() * 16);
    const value = token === 'x' ? random : (random & 0x3) | 0x8;
    return value.toString(16);
  });
}

function isUuid(value: unknown): boolean {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

function isRuleId(value: unknown): boolean {
  return /^[A-Z][A-Z0-9]*-\d{4,}$/.test(stringValue(value));
}
