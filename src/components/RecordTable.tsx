import { fieldByKey, formatValue, recordLabel } from '../lib/records';
import type { TemplateDefinition, TemplateRecord } from '../types';

interface RecordTableProps {
  template: TemplateDefinition;
  records: TemplateRecord[];
  selectedId: string | null;
  onEdit: (record: TemplateRecord) => void;
  onPreview: (record: TemplateRecord) => void;
  onDuplicate: (record: TemplateRecord) => void;
  onArchive: (record: TemplateRecord) => void;
  onDelete: (record: TemplateRecord) => void;
}

export function RecordTable({
  template,
  records,
  selectedId,
  onEdit,
  onPreview,
  onDuplicate,
  onArchive,
  onDelete,
}: RecordTableProps) {
  const columnCount = template.tableFields.length + 3;

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {template.tableFields.map((fieldKey) => (
              <th key={fieldKey}>{fieldByKey(template, fieldKey)?.label ?? fieldKey}</th>
            ))}
            <th>State</th>
            <th>Updated</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {records.length === 0 ? (
            <tr>
              <td className="empty-state" colSpan={columnCount}>
                No records match the current view.
              </td>
            </tr>
          ) : (
            records.map((record) => (
              <tr className={record.id === selectedId ? 'selected-row' : ''} key={record.id}>
                {template.tableFields.map((fieldKey, index) => (
                  <td key={fieldKey}>
                    {index === 0 ? (
                      <button className="link-button record-title" type="button" onClick={() => onEdit(record)}>
                        {formatValue(record.data[fieldKey]) || recordLabel(record)}
                      </button>
                    ) : (
                      formatValue(record.data[fieldKey])
                    )}
                  </td>
                ))}
                <td>
                  <span className={`state-chip ${record.archived ? 'state-archived' : 'state-active'}`}>
                    {record.archived ? 'Archived' : 'Active'}
                  </span>
                </td>
                <td>{new Date(record.updatedAt).toLocaleDateString()}</td>
                <td>
                  <div className="row-actions">
                    <button type="button" onClick={() => onEdit(record)}>
                      Edit
                    </button>
                    <button type="button" onClick={() => onPreview(record)}>
                      JSON
                    </button>
                    <button type="button" onClick={() => onDuplicate(record)}>
                      Duplicate
                    </button>
                    <button type="button" onClick={() => onArchive(record)}>
                      {record.archived ? 'Restore' : 'Archive'}
                    </button>
                    <button className="danger-button" type="button" onClick={() => onDelete(record)}>
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
