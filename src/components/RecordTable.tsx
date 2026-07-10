import { Button, EmptyState, pixel, proportional, Table, Text, Token } from '@astryxdesign/core';
import type { TableColumn, TokenColor } from '@astryxdesign/core';
import { fieldByKey, formatValue, recordLabel } from '../lib/records';
import type { TemplateDefinition, TemplateRecord } from '../types';

interface RecordTableProps {
  template: TemplateDefinition;
  records: TemplateRecord[];
  selectedId: string | null;
  onEdit: (record: TemplateRecord) => void;
}

export function RecordTable({
  template,
  records,
  selectedId,
  onEdit,
}: RecordTableProps) {
  const visibleTableFields = template.tableFields.filter((fieldKey) => fieldKey !== 'rule_id');

  const rows: RecordTableRow[] = records.map((record) => {
    const row: RecordTableRow = {
      id: record.id,
      record,
      state: record.archived ? 'Archived' : 'Current',
      updatedAt: record.updatedAt,
    };

    visibleTableFields.forEach((fieldKey) => {
      row[fieldKey] = formatValue(record.data[fieldKey]);
    });

    return row;
  });

  const columns: TableColumn<RecordTableRow>[] = [
    ...visibleTableFields.map((fieldKey, index) => ({
      key: fieldKey,
      header: fieldByKey(template, fieldKey)?.label ?? fieldKey,
      width: tableColumnWidth(fieldKey, index),
      renderCell: (row: RecordTableRow) => {
        const value = formatValue(row.record.data[fieldKey]);
        if (fieldKey === 'status') {
          return (
            <Token
              color={statusColor(value)}
              label={value || '-'}
              size="sm"
            />
          );
        }
        if (index === 0) {
          return (
            <Button
              label={value || recordLabel(row.record)}
              size="sm"
              variant="ghost"
              onClick={() => onEdit(row.record)}
            />
          );
        }
        return (
          <Text maxLines={2} type="supporting">
            {value || '-'}
          </Text>
        );
      },
    })),
    {
      key: 'state',
      header: 'Catalog',
      width: pixel(104),
      renderCell: (row: RecordTableRow) => (
        <Token
          color={row.record.archived ? 'gray' : 'green'}
          label={row.record.archived ? 'Archived' : 'Current'}
          size="sm"
        />
      ),
    },
    {
      key: 'updatedAt',
      header: 'Updated',
      width: pixel(104),
      renderCell: (row: RecordTableRow) => (
        <Text hasTabularNumbers type="supporting">
          {new Date(row.record.updatedAt).toLocaleDateString()}
        </Text>
      ),
    },
  ];

  return (
    <section className="record-table" aria-label={`${template.pluralName} records`}>
      {records.length === 0 ? (
        <EmptyState title="No records match the current view" description="Adjust filters or add a new item." />
      ) : (
        <Table
          columns={columns}
          data={rows}
          density="compact"
          dividers="rows"
          hasHover
          idKey="id"
          textOverflow="truncate"
          verticalAlign="top"
        />
      )}
    </section>
  );
}

function tableColumnWidth(fieldKey: string, index: number) {
  if (index === 0 || fieldKey === 'name') {
    return proportional(1.8, { minWidth: 144 });
  }
  if (fieldKey.includes('mitre') || fieldKey === 'tags') {
    return proportional(1.1, { minWidth: 88 });
  }
  if (fieldKey.endsWith('_reviewed')) {
    return pixel(112);
  }
  return proportional(1, { minWidth: 80 });
}

function statusColor(status: string): TokenColor {
  switch (status.toLowerCase()) {
    case 'enabled':
    case 'available':
    case 'approved':
    case 'covered':
      return 'green';
    case 'disabled':
    case 'missing':
    case 'retired':
    case 'deprecated':
      return 'gray';
    case 'testing':
    case 'partial':
    case 'in_progress':
      return 'blue';
    case 'draft':
    case 'planned':
    case 'proposed':
      return 'yellow';
    case 'deferred':
      return 'orange';
    default:
      return 'default';
  }
}

interface RecordTableRow extends Record<string, unknown> {
  id: string;
  record: TemplateRecord;
  state: string;
  updatedAt: string;
}
