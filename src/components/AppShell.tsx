import { templates } from '../data/templates';
import { templatePath } from '../lib/records';

interface AppShellProps {
  activeTemplateId: string;
  onNavigate: (path: string) => void;
}

export function AppShell({ activeTemplateId, onNavigate }: AppShellProps) {
  return (
    <aside className="sidebar">
      <div className="brand-block">
        <strong>RuleAtlas</strong>
        <span>Detection template workspace</span>
      </div>

      <nav aria-label="RuleAtlas templates">
        <div className="nav-group">
          <span>Template Input</span>
          {templates.map((template) => (
            <button
              className={activeTemplateId === template.id ? 'nav-item active' : 'nav-item'}
              key={template.id}
              type="button"
              onClick={() => onNavigate(templatePath(template.id))}
            >
              {template.pluralName}
            </button>
          ))}
        </div>

        <button
          className={activeTemplateId === 'import-export' ? 'nav-item active' : 'nav-item'}
          type="button"
          onClick={() => onNavigate('/templates/import-export')}
        >
          Import / Export
        </button>
      </nav>
    </aside>
  );
}
