import {
  Button,
  DialogHeader,
  Field,
  FormLayout,
  HStack,
  Layout,
  LayoutContent,
  LayoutFooter,
  Selector,
  StackItem,
  Switch,
  TextArea,
  TextInput,
} from '@astryxdesign/core';
import { coerceValue, formatValue, parseList } from '../lib/records';
import type {
  RecordValue,
  TemplateDefinition,
  TemplateField,
  TemplateRecord,
  ValidationErrors,
} from '../types';

interface RecordEditorProps {
  template: TemplateDefinition;
  record: TemplateRecord;
  errors: ValidationErrors;
  onChange: (record: TemplateRecord) => void;
  onSubmit: () => void;
  onPreview: () => void;
  onCancel: () => void;
  onDuplicate?: () => void;
  onArchive?: () => void;
  onDelete?: () => void;
}

export function RecordEditor({
  template,
  record,
  errors,
  onChange,
  onSubmit,
  onPreview,
  onCancel,
  onDuplicate,
  onArchive,
  onDelete,
}: RecordEditorProps) {
  const hasRecordActions = Boolean(onDuplicate || onArchive || onDelete);

  const updateField = (field: TemplateField, value: unknown) => {
    onChange({
      ...record,
      data: {
        ...record.data,
        [field.key]: normalizeInputValue(field, value),
      },
      updatedAt: new Date().toISOString(),
    });
  };

  return (
    <Layout
      height="fill"
      header={
        <DialogHeader
          hasDivider
          title={`Edit ${template.name}`}
          subtitle="Required fields validate before saving."
          onOpenChange={(isOpen) => {
            if (!isOpen) {
              onCancel();
            }
          }}
        />
      }
      footer={
        <LayoutFooter hasDivider label="Editor actions">
          <HStack align="center" gap={2} padding={3} wrap="wrap">
            <StackItem size="fill">
              {hasRecordActions ? (
                <HStack align="center" gap={2} wrap="wrap">
                  {onDuplicate ? <Button label="Duplicate" size="sm" variant="secondary" onClick={onDuplicate} /> : null}
                  {onArchive ? (
                    <Button
                      label={record.archived ? 'Restore' : 'Archive'}
                      size="sm"
                      variant="secondary"
                      onClick={onArchive}
                    />
                  ) : null}
                  {onDelete ? <Button label="Delete" size="sm" variant="destructive" onClick={onDelete} /> : null}
                </HStack>
              ) : null}
            </StackItem>
            <Button label="Preview JSON" size="sm" variant="secondary" onClick={onPreview} />
            <Button label="Cancel" size="sm" variant="secondary" onClick={onCancel} />
            <Button label="Save" size="sm" variant="primary" onClick={onSubmit} />
          </HStack>
        </LayoutFooter>
      }
    >
      <LayoutContent label={`${template.name} fields`}>
        <FormLayout className="record-form-grid">
          {template.fields.map((field) => (
            <FieldControl
              error={errors[field.key]}
              field={field}
              key={field.key}
              value={record.data[field.key]}
              onChange={(value) => updateField(field, value)}
            />
          ))}
        </FormLayout>
      </LayoutContent>
    </Layout>
  );
}

interface FieldControlProps {
  field: TemplateField;
  value: RecordValue;
  error?: string;
  onChange: (value: unknown) => void;
}

function FieldControl({ field, value, error, onChange }: FieldControlProps) {
  const stringValue = formatValue(value);

  return renderControl(field, value, stringValue, error, onChange);
}

function renderControl(
  field: TemplateField,
  value: RecordValue,
  stringValue: string,
  error: string | undefined,
  onChange: (value: unknown) => void,
) {
  const status = error ? { type: 'error' as const, message: error } : undefined;

  if (field.type === 'code') {
    return (
      <Field
        className="wide-field"
        inputID={`${field.key}-code-editor`}
        isRequired={field.required}
        label={field.label}
        status={status}
        statusVariant="detached"
      >
        <textarea
          id={`${field.key}-code-editor`}
          className="native-code-editor"
          placeholder={field.placeholder}
          rows={10}
          spellCheck={false}
          value={stringValue}
          wrap="off"
          onChange={(event) => onChange(event.target.value)}
        />
      </Field>
    );
  }

  if (field.type === 'textarea') {
    return (
      <TextArea
        className={field.key === 'description' ? 'wide-field compact-textarea-field' : undefined}
        hasSpellCheck
        isRequired={field.required}
        label={field.label}
        placeholder={field.placeholder}
        rows={field.key === 'description' ? 2 : 4}
        status={status}
        value={stringValue}
        onChange={onChange}
      />
    );
  }

  if (field.type === 'select') {
    return (
      <Selector
        isRequired={field.required}
        label={field.label}
        options={(field.options ?? []).map((option) => ({ value: option, label: option }))}
        placeholder={field.placeholder}
        status={status}
        value={stringValue}
        onChange={onChange}
      />
    );
  }

  if (field.type === 'boolean') {
    return (
      <Switch
        isRequired={field.required}
        label={field.label}
        status={status}
        value={Boolean(value)}
        onChange={onChange}
      />
    );
  }

  if (field.key === 'rule_id') {
    return (
      <TextInput
        disabledMessage="Rule IDs are generated when the record is created."
        isDisabled
        isRequired={field.required}
        label={field.label}
        placeholder={field.placeholder}
        status={status}
        value={stringValue}
      />
    );
  }

  if (field.type === 'number') {
    return (
      <Field
        inputID={`${field.key}-number`}
        isRequired={field.required}
        label={field.label}
        status={status}
        statusVariant="detached"
      >
        <input
          id={`${field.key}-number`}
          className="native-number-input"
          min="0"
          placeholder={field.placeholder}
          type="number"
          value={stringValue}
          onChange={(event) => onChange(event.target.value)}
        />
      </Field>
    );
  }

  if (field.type === 'date') {
    return (
      <Field
        inputID={`${field.key}-date`}
        isRequired={field.required}
        label={field.label}
        status={status}
        statusVariant="detached"
      >
        <input
          id={`${field.key}-date`}
          className="native-date-input"
          placeholder={field.placeholder}
          type="date"
          value={dateInputValue(stringValue)}
          onChange={(event) => onChange(event.target.value)}
        />
      </Field>
    );
  }

  return (
    <TextInput
      isRequired={field.required}
      label={field.label}
      placeholder={field.placeholder}
      status={status}
      value={stringValue}
      onChange={onChange}
    />
  );
}

function dateInputValue(value: string): string {
  if (!value) {
    return '';
  }
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return value;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toISOString().slice(0, 10);
}

function normalizeInputValue(field: TemplateField, value: unknown): RecordValue {
  if (field.type === 'tags' || field.type === 'multiselect') {
    return parseList(value);
  }
  return coerceValue(value, field);
}
