export type FieldType =
  | 'text'
  | 'textarea'
  | 'code'
  | 'date'
  | 'select'
  | 'boolean'
  | 'number'
  | 'tags'
  | 'multiselect';

export type RecordValue = string | number | boolean | string[];

export interface TemplateField {
  key: string;
  label: string;
  type: FieldType;
  required?: boolean;
  options?: readonly string[];
  placeholder?: string;
}

export interface TemplateDefinition {
  id: string;
  name: string;
  pluralName: string;
  description: string;
  storageKey: string;
  tableFields: readonly string[];
  filterFields: readonly string[];
  fields: readonly TemplateField[];
}

export interface TemplateRecord {
  id: string;
  data: Record<string, RecordValue>;
  archived: boolean;
  createdAt: string;
  updatedAt: string;
}

export type TemplateStore = Record<string, TemplateRecord[]>;

export interface TemplateExport {
  exportedAt: string;
  version: number;
  templates: TemplateStore;
}

export type ValidationErrors = Record<string, string>;

export interface JsonPreview {
  title: string;
  value: unknown;
}
