import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Banner,
  Button,
  Dialog,
  Heading,
  HStack,
  Layout,
  LayoutContent,
  LayoutHeader,
  Selector,
  StackItem,
  Switch,
  Text,
  TextInput,
  VStack,
} from '@astryxdesign/core';
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
  const draftIsSaved = records.some((record) => record.id === draft.id);

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
    <>
      <Layout
        height="fill"
        header={
          <LayoutHeader hasDivider label={`${template.pluralName} header`}>
            <HStack align="center" gap={4} paddingInline={4} paddingBlock={3} wrap="wrap">
              <StackItem size="fill">
                <VStack gap={1}>
                  <Heading level={1}>{template.pluralName}</Heading>
                  <Text as="p" color="secondary" type="supporting">
                    {template.description}
                  </Text>
                  <Text as="p" color="secondary" type="supporting">
                    {records.length} saved, {records.filter((record) => record.archived).length} archived
                  </Text>
                </VStack>
              </StackItem>
              <Button label={`Add ${template.name}`} variant="primary" onClick={startAdd} />
            </HStack>
          </LayoutHeader>
        }
      >
        <LayoutContent label={`${template.pluralName} records`}>
          <VStack gap={0}>
            <section className="workspace-toolbar-shell" aria-label={`${template.pluralName} filters`}>
              <HStack align="center" className="workspace-toolbar" gap={2} wrap="wrap">
                <HStack align="center" className="toolbar-filter-group" gap={2} wrap="wrap">
                  <TextInput
                    hasClear
                    isLabelHidden
                    label={`Search ${template.pluralName}`}
                    placeholder={`Search ${template.pluralName.toLowerCase()}...`}
                    value={search}
                    width={280}
                    onChange={setSearch}
                  />
                  {template.filterFields.map((fieldKey) => (
                    <Selector
                      isLabelHidden
                      key={fieldKey}
                      label={`Filter by ${fieldKey.replaceAll('_', ' ')}`}
                      options={[
                        { value: 'all', label: `All ${fieldKey.replaceAll('_', ' ')}` },
                        ...filterOptions(template, records, fieldKey).map((option) => ({
                          value: option,
                          label: option,
                        })),
                      ]}
                      value={filters[fieldKey] ?? 'all'}
                      onChange={(value) => setFilters({ ...filters, [fieldKey]: value })}
                    />
                  ))}
                  <Switch
                    label="Archived"
                    value={showArchived}
                    onChange={setShowArchived}
                  />
                </HStack>
                <span className="toolbar-spacer" aria-hidden="true" />
                <HStack align="center" className="toolbar-actions" gap={2} wrap="wrap">
                  <Button
                    label="Preview JSON"
                    variant="secondary"
                    onClick={() => onPreview({ title: `${template.name} collection`, value: records })}
                  />
                  <Button label="Export JSON" variant="secondary" onClick={() => onExportTemplate(template)} />
                  <Button label="Import JSON" variant="secondary" onClick={() => fileInputRef.current?.click()} />
                  <input
                    ref={fileInputRef}
                    className="hidden-input"
                    type="file"
                    accept="application/json"
                    onChange={handleImport}
                  />
                </HStack>
              </HStack>
            </section>

            {importMessage ? <Banner status="success" title={importMessage} /> : null}
            {importError ? <Banner status="error" title={importError} /> : null}
            <RecordTable
              records={visibleRecords}
              selectedId={selectedId}
              template={template}
              onEdit={startEdit}
            />
          </VStack>
        </LayoutContent>
      </Layout>

      <Dialog
        isOpen={editing}
        maxHeight="calc(100dvh - 32px)"
        purpose="form"
        width="min(1040px, calc(100vw - 32px))"
        onOpenChange={(isOpen) => {
          if (!isOpen) {
            setErrors({});
            setEditing(false);
          }
        }}
      >
          <RecordEditor
            errors={errors}
            record={draft}
            template={template}
            onCancel={() => {
              setErrors({});
              setEditing(false);
            }}
            onArchive={draftIsSaved ? () => toggleArchive(draft) : undefined}
            onChange={setDraft}
            onDelete={draftIsSaved ? () => deleteRecord(draft) : undefined}
            onDuplicate={draftIsSaved ? () => duplicateRecord(draft) : undefined}
            onPreview={() => onPreview({ title: recordLabel(draft), value: draft })}
            onSubmit={saveDraft}
          />
      </Dialog>
    </>
  );
}
