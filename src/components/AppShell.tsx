import { Badge, SideNav, SideNavHeading, SideNavItem, SideNavSection } from '@astryxdesign/core';
import { templates } from '../data/templates';
import { templatePath } from '../lib/records';

interface AppShellProps {
  activeTemplateId: string;
  onNavigate: (path: string) => void;
}

export function AppShell({ activeTemplateId, onNavigate }: AppShellProps) {
  const navigate = (path: string) => (event: React.MouseEvent) => {
    event.preventDefault();
    onNavigate(path);
  };

  return (
    <SideNav
      collapsible={{ defaultIsCollapsed: false, buttonLabel: 'Collapse RuleAtlas navigation' }}
      header={
        <SideNavHeading
          heading="RuleAtlas"
          subheading="Detection templates"
          superheading="Workspace"
          headerEndContent={<Badge label={`${templates.length}`} />}
        />
      }
    >
      <SideNavSection title="Template input">
        {templates.map((template) => (
          <SideNavItem
            href={templatePath(template.id)}
            isSelected={activeTemplateId === template.id}
            key={template.id}
            label={template.pluralName}
            onClick={navigate(templatePath(template.id))}
          />
        ))}
      </SideNavSection>
      <SideNavSection title="Utilities">
        <SideNavItem
          href="/templates/tests"
          isSelected={activeTemplateId === 'tests'}
          label="Rule testing"
          onClick={navigate('/templates/tests')}
        />
        <SideNavItem
          href="/templates/repository"
          isSelected={activeTemplateId === 'repository'}
          label="Repository"
          onClick={navigate('/templates/repository')}
        />
        <SideNavItem
          href="/templates/import-export"
          isSelected={activeTemplateId === 'import-export'}
          label="Import / Export"
          onClick={navigate('/templates/import-export')}
        />
        <SideNavItem
          href="/templates/config"
          isSelected={activeTemplateId === 'config'}
          label="Config"
          onClick={navigate('/templates/config')}
        />
      </SideNavSection>
    </SideNav>
  );
}
