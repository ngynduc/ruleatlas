import { templates } from '../data/templates';
import type { JsonPreview, TemplateStore } from '../types';

interface ImportExportPageProps {
  store: TemplateStore;
  onImport: (file: File) => void;
  onExport: () => void;
  onPreview: (preview: JsonPreview) => void;
}

export function ImportExportPage({
  store,
  onImport,
  onExport,
  onPreview,
}: ImportExportPageProps) {
  const summary = templates.map((template) => ({
    name: template.pluralName,
    count: store[template.storageKey]?.length ?? 0,
  }));

  return (
    <main className="workspace single-column">
      <section className="list-panel">
        <div className="panel-heading">
          <div>
            <h1>Import / Export</h1>
            <p>Move all RuleAtlas local data as JSON.</p>
          </div>
          <div className="button-row">
            <button type="button" onClick={() => onPreview({ title: 'All RuleAtlas templates', value: store })}>
              Preview JSON
            </button>
            <button className="primary-button" type="button" onClick={onExport}>
              Export all JSON
            </button>
            <label className="file-button">
              Import JSON
              <input
                type="file"
                accept="application/json"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) {
                    onImport(file);
                  }
                  event.target.value = '';
                }}
              />
            </label>
          </div>
        </div>

        <div className="summary-grid">
          {summary.map((item) => (
            <div className="summary-cell" key={item.name}>
              <span>{item.name}</span>
              <strong>{item.count}</strong>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
