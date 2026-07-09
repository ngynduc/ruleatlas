import { useEffect, useMemo, useRef, useState } from 'react';
import {
  createBlankRecord,
  createRuleId,
  filterOptions,
  filterRecords,
  importTemplateRecords,
  recordLabel,
  updateStoreRecords,
  validateRecord,
} from '../lib/records';
import type {
  JsonPreview,
  TemplateDefinition,
  TemplateRecord,
  TemplateStore,
  ValidationErrors,
} from '../types';
import { RecordEditor } from './RecordEditor';
import { RecordTable } from './RecordTable';

interface TemplateWorkspaceProps {
  template: TemplateDefinition;
  records: TemplateRecord[];
  store: TemplateStore;
  onStoreChange: (store: TemplateStore) => void;
  onExportTemplate: (template: TemplateDefinition) => void;
  onPreview: (preview: JsonPreview) => void;
}

export function TemplateWorkspace({
  template,
  records,
  store,
  onStoreChange,
  onExportTemplate,
  onPreview,
}: TemplateWorkspaceProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(records[0]?.id ?? null);
  const [draft, setDraft] = useState<TemplateRecord>(records[0] ?? createBlankRecord(template));
  const [errors, setErrors] = useState<ValidationErrors>({});
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [showArchived, setShowArchived] = useState(false);
  const [editing, setEditing] = useState(false);
  const [importMessage, setImportMessage] = useState<string | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  useEffect(() => {
    setSelectedId(records[0]?.id ?? null);
    setDraft(records[0] ?? createBlankRecord(template));
    setErrors({});
    setSearch('');
    setFilters({});
    setShowArchived(false);
    setEditing(false);
    setImportMessage(null);
    setImportError(null);
  }, [template.id]);

  const visibleRecords = useMemo(
    () => filterRecords(template, records, search, filters, showArchived),
    [filters, records, search, showArchived, template],
  );

  const replaceRecords = (nextRecords: TemplateRecord[]) => {
    onStoreChange(updateStoreRecords(store, template, nextRecords));
  };

  const startAdd = () => {
    const nextDraft = createBlankRecord(template);
    setSelectedId(nextDraft.id);
    setDraft(nextDraft);
    setErrors({});
    setEditing(true);
  };

  const startEdit = (record: TemplateRecord) => {
    setSelectedId(record.id);
    setDraft(record);
    setErrors({});
    setEditing(true);
  };

  const saveDraft = () => {
    const nextErrors = validateRecord(template, draft);
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) {
      return;
    }

    const saved = {
      ...draft,
      updatedAt: new Date().toISOString(),
    };
    const exists = records.some((record) => record.id === saved.id);
    const nextRecords = exists
      ? records.map((record) => (record.id === saved.id ? saved : record))
      : [saved, ...records];

    replaceRecords(nextRecords);
    setSelectedId(saved.id);
    setDraft(saved);
    setEditing(false);
  };

  const duplicateRecord = (record: TemplateRecord) => {
    const nextRuleId = template.id === 'rules' ? createRuleId() : undefined;
    const duplicated = {
      ...record,
      id: nextRuleId ?? `${record.id}-copy-${Date.now()}`,
      data: {
        ...record.data,
        rule_id: nextRuleId ?? record.data.rule_id,
        name: `${recordLabel(record)} Copy`,
      },
      archived: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    replaceRecords([duplicated, ...records]);
    startEdit(duplicated);
  };

  const toggleArchive = (record: TemplateRecord) => {
    const updated = {
      ...record,
      archived: !record.archived,
      updatedAt: new Date().toISOString(),
    };
    replaceRecords(records.map((item) => (item.id === record.id ? updated : item)));
    if (draft.id === record.id) {
      setDraft(updated);
    }
  };

  const deleteRecord = (record: TemplateRecord) => {
    const nextRecords = records.filter((item) => item.id !== record.id);
    replaceRecords(nextRecords);

    if (record.id === selectedId) {
      setSelectedId(nextRecords[0]?.id ?? null);
      setDraft(nextRecords[0] ?? createBlankRecord(template));
      setEditing(false);
    }
  };

  const importRecords = async (file: File) => {
    try {
      const text = await file.text();
      const imported = importTemplateRecords(template, JSON.parse(text));

      if (imported.length === 0) {
        setImportMessage(null);
        setImportError(`No ${template.pluralName.toLowerCase()} found in ${file.name}.`);
        return;
      }

      replaceRecords(imported);
      setSelectedId(imported[0]?.id ?? null);
      setDraft(imported[0] ?? createBlankRecord(template));
      setEditing(false);
      setImportError(null);
      setImportMessage(`Imported ${imported.length} ${imported.length === 1 ? template.name : template.pluralName}.`);
    } catch (error) {
      setImportMessage(null);
      setImportError(error instanceof Error ? error.message : 'Unable to import JSON file.');
    }
  };

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      void importRecords(file);
    }
    event.target.value = '';
  };

  return (
    <main className="workspace">
      <section className="list-panel">
        <div className="panel-heading">
          <div>
            <h1>{template.pluralName}</h1>
            <p>
              {records.length} saved, {records.filter((record) => record.archived).length} archived
            </p>
          </div>
          <button className="primary-button" type="button" onClick={startAdd}>
            Add item
          </button>
        </div>

        <div className="template-description">{template.description}</div>

        <div className="toolbar">
          <input
            aria-label={`Search ${template.pluralName}`}
            placeholder={`Search ${template.pluralName.toLowerCase()}...`}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />

          {template.filterFields.map((fieldKey) => (
            <select
              aria-label={`Filter by ${fieldKey}`}
              key={fieldKey}
              value={filters[fieldKey] ?? 'all'}
              onChange={(event) => setFilters({ ...filters, [fieldKey]: event.target.value })}
            >
              <option value="all">All {fieldKey.replaceAll('_', ' ')}</option>
              {filterOptions(template, records, fieldKey).map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          ))}

          <label className="compact-check">
            <input
              checked={showArchived}
              type="checkbox"
              onChange={(event) => setShowArchived(event.target.checked)}
            />
            Archived
          </label>
        </div>

        <div className="action-bar">
          <button type="button" onClick={() => onPreview({ title: `${template.name} collection`, value: records })}>
            Preview JSON
          </button>
          <button type="button" onClick={() => onExportTemplate(template)}>
            Export JSON
          </button>
          <button type="button" onClick={() => fileInputRef.current?.click()}>
            Import JSON
          </button>
          <input
            ref={fileInputRef}
            className="hidden-input"
            type="file"
            accept="application/json"
            onChange={handleImport}
          />
        </div>

        {importMessage ? <div className="import-status">{importMessage}</div> : null}
        {importError ? <div className="import-status import-status-error">{importError}</div> : null}

        <RecordTable
          records={visibleRecords}
          selectedId={selectedId}
          template={template}
          onArchive={toggleArchive}
          onDelete={deleteRecord}
          onDuplicate={duplicateRecord}
          onEdit={startEdit}
          onPreview={(record) => onPreview({ title: recordLabel(record), value: record })}
        />
      </section>

      {editing ? (
        <div className="modal-backdrop edit-modal-backdrop" role="presentation">
          <RecordEditor
            errors={errors}
            record={draft}
            template={template}
            onCancel={() => {
              setErrors({});
              setEditing(false);
            }}
            onChange={setDraft}
            onPreview={() => onPreview({ title: recordLabel(draft), value: draft })}
            onSubmit={saveDraft}
          />
        </div>
      ) : null}
    </main>
  );
}
