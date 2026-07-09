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
}

export function RecordEditor({
  template,
  record,
  errors,
  onChange,
  onSubmit,
  onPreview,
  onCancel,
}: RecordEditorProps) {
  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit();
  };

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
    <form
      aria-label={`Edit ${template.name}`}
      aria-modal="true"
      className="editor-panel"
      role="dialog"
      onSubmit={handleSubmit}
    >
      <div className="panel-heading editor-heading">
        <div>
          <h1>Edit {template.name}</h1>
          <p>Required fields validate before saving.</p>
        </div>
        <div className="button-row">
          <button type="button" onClick={onPreview}>
            Preview JSON
          </button>
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button className="primary-button" type="submit">
            Save
          </button>
        </div>
      </div>

      <div className="form-grid">
        {template.fields.map((field) => (
          <FieldControl
            error={errors[field.key]}
            field={field}
            key={field.key}
            value={record.data[field.key]}
            onChange={(value) => updateField(field, value)}
          />
        ))}
      </div>
    </form>
  );
}

interface FieldControlProps {
  field: TemplateField;
  value: RecordValue;
  error?: string;
  onChange: (value: unknown) => void;
}

function FieldControl({ field, value, error, onChange }: FieldControlProps) {
  const label = `${field.label}${field.required ? ' *' : ''}`;
  const stringValue = formatValue(value);

  return (
    <label className={`field field-${field.type}`}>
      <span>
        {label}
        {error ? <em>{error}</em> : null}
      </span>

      {renderControl(field, value, stringValue, onChange)}
    </label>
  );
}

function renderControl(
  field: TemplateField,
  value: RecordValue,
  stringValue: string,
  onChange: (value: unknown) => void,
) {
  if (field.type === 'textarea' || field.type === 'code') {
    return (
      <textarea
        className={field.type === 'code' ? 'code-textarea' : undefined}
        placeholder={field.placeholder}
        spellCheck={field.type === 'code' ? false : undefined}
        value={stringValue}
        onChange={(event) => onChange(event.target.value)}
      />
    );
  }

  if (field.type === 'select') {
    return (
      <select value={stringValue} onChange={(event) => onChange(event.target.value)}>
        {field.options?.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    );
  }

  if (field.type === 'boolean') {
    return (
      <span className="checkbox-line">
        <input
          checked={Boolean(value)}
          type="checkbox"
          onChange={(event) => onChange(event.target.checked)}
        />
        Enabled
      </span>
    );
  }

  if (field.type === 'number') {
    return (
      <input
        min="0"
        placeholder={field.placeholder}
        type="number"
        value={stringValue}
        onChange={(event) => onChange(event.target.value)}
      />
    );
  }

  return (
    <input
      placeholder={field.placeholder}
      readOnly={field.key === 'rule_id'}
      value={stringValue}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

function normalizeInputValue(field: TemplateField, value: unknown): RecordValue {
  if (field.type === 'tags' || field.type === 'multiselect') {
    return parseList(value);
  }
  return coerceValue(value, field);
}
