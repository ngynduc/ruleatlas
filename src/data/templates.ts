import type { TemplateDefinition } from '../types';

export const ruleStatuses = [
  'draft',
  'testing',
  'enabled',
  'disabled',
  'deprecated',
] as const;

export const priorities = ['critical', 'high', 'medium', 'low'] as const;
export const severities = ['critical', 'high', 'medium', 'low', 'informational'] as const;
export const confidenceLevels = ['high', 'medium', 'low'] as const;
export const domains = ['endpoint', 'identity', 'cloud', 'network', 'email', 'saas', 'other'] as const;
export const categories = [
  'execution',
  'persistence',
  'privilege escalation',
  'defense evasion',
  'credential access',
  'discovery',
  'lateral movement',
  'collection',
  'command and control',
  'exfiltration',
  'impact',
  'general',
] as const;
export const coverageTypes = ['detective', 'preventive', 'investigative', 'response', 'gap'] as const;
export const ownerTypes = ['team', 'person', 'vendor', 'service'] as const;
export const platforms = [
  'Splunk',
  'Microsoft Sentinel',
  'Elastic',
  'Chronicle',
  'Defender',
  'Okta',
  'AWS',
  'Azure',
  'GCP',
  'Other',
] as const;

const rules: TemplateDefinition = {
  id: 'rules',
  name: 'Rule',
  pluralName: 'Rules',
  description: 'Catalog detection rules across draft, testing, and deployed states.',
  storageKey: 'rules',
  tableFields: [
    'rule_id',
    'name',
    'status',
    'owner',
    'platform',
    'severity',
    'mitre_tactic',
    'mitre_technique',
    'tags',
  ],
  filterFields: ['status', 'severity', 'category', 'coverage_type'],
  fields: [
    { key: 'rule_id', label: 'Rule ID', type: 'text', required: true, placeholder: 'EXEC-0001' },
    { key: 'uuid', label: 'UUID', type: 'text', required: true },
    { key: 'name', label: 'Rule Name', type: 'text', required: true },
    { key: 'description', label: 'Description', type: 'textarea' },
    { key: 'owner', label: 'Owner', type: 'text', required: true },
    { key: 'status', label: 'Status', type: 'select', required: true, options: ruleStatuses },
    { key: 'severity', label: 'Severity', type: 'select', required: true, options: severities },
    { key: 'confidence', label: 'Confidence', type: 'select', options: confidenceLevels },
    { key: 'domain', label: 'Domain', type: 'select', options: domains },
    { key: 'category', label: 'Detection Category', type: 'select', options: categories },
    { key: 'coverage_type', label: 'Coverage Type', type: 'select', options: coverageTypes },
    { key: 'platform', label: 'Platform', type: 'select', required: true, options: platforms },
    { key: 'product', label: 'Product', type: 'text' },
    { key: 'log_source', label: 'Log Source', type: 'text', required: true },
    { key: 'mitre_tactic', label: 'MITRE Tactic', type: 'text' },
    { key: 'mitre_technique', label: 'MITRE Technique', type: 'text' },
    { key: 'query', label: 'Current Query', type: 'code' },
    { key: 'tags', label: 'Tags', type: 'tags' },
  ],
};

const inventory: TemplateDefinition = {
  id: 'inventory',
  name: 'Inventory',
  pluralName: 'Inventory',
  description: 'Track assets, systems, and environments relevant to detection coverage.',
  storageKey: 'inventory',
  tableFields: ['asset_id', 'name', 'platform', 'owner', 'criticality', 'environment'],
  filterFields: ['platform', 'criticality', 'environment'],
  fields: [
    { key: 'asset_id', label: 'Asset ID', type: 'text', required: true },
    { key: 'name', label: 'Asset Name', type: 'text', required: true },
    { key: 'description', label: 'Description', type: 'textarea' },
    { key: 'platform', label: 'Platform', type: 'select', required: true, options: platforms },
    { key: 'owner', label: 'Owner / Team', type: 'text', required: true },
    { key: 'criticality', label: 'Criticality', type: 'select', required: true, options: priorities },
    { key: 'environment', label: 'Environment', type: 'select', options: ['production', 'staging', 'development', 'lab'] },
    { key: 'data_sources', label: 'Data Sources', type: 'tags' },
    { key: 'tags', label: 'Tags', type: 'tags' },
  ],
};

const dataSource: TemplateDefinition = {
  id: 'data-source',
  name: 'Data Source',
  pluralName: 'Data Sources',
  description: 'Document log sources needed to support detection and investigation.',
  storageKey: 'dataSources',
  tableFields: ['source_id', 'name', 'platform', 'owner', 'status', 'retention'],
  filterFields: ['platform', 'status', 'owner'],
  fields: [
    { key: 'source_id', label: 'Source ID', type: 'text', required: true },
    { key: 'name', label: 'Source Name', type: 'text', required: true },
    { key: 'description', label: 'Description', type: 'textarea' },
    { key: 'platform', label: 'Platform', type: 'select', required: true, options: platforms },
    { key: 'owner', label: 'Owner / Team', type: 'text', required: true },
    { key: 'status', label: 'Status', type: 'select', required: true, options: ['planned', 'available', 'partial', 'missing', 'retired'] },
    { key: 'retention', label: 'Retention', type: 'text', placeholder: '30 days, 1 year' },
    { key: 'schema_fields', label: 'Schema Fields', type: 'tags', placeholder: 'user.name, src.ip, process.name' },
    { key: 'collection_notes', label: 'Collection Notes', type: 'textarea' },
    { key: 'tags', label: 'Tags', type: 'tags' },
  ],
};

const detectionObjective: TemplateDefinition = {
  id: 'detection-objective',
  name: 'Detection Objective',
  pluralName: 'Detection Objectives',
  description: 'Capture what the team needs to detect and why it matters.',
  storageKey: 'detectionObjectives',
  tableFields: ['objective_id', 'name', 'priority', 'owner', 'status', 'mapped_techniques'],
  filterFields: ['priority', 'status', 'owner'],
  fields: [
    { key: 'objective_id', label: 'Objective ID', type: 'text', required: true },
    { key: 'name', label: 'Objective Name', type: 'text', required: true },
    { key: 'description', label: 'Objective', type: 'textarea', required: true },
    { key: 'priority', label: 'Priority', type: 'select', required: true, options: priorities },
    { key: 'status', label: 'Status', type: 'select', required: true, options: ['proposed', 'approved', 'in_progress', 'covered', 'deferred'] },
    { key: 'owner', label: 'Owner / Team', type: 'text', required: true },
    { key: 'mapped_techniques', label: 'Mapped Techniques', type: 'tags', placeholder: 'T1110, T1059' },
    { key: 'success_criteria', label: 'Success Criteria', type: 'textarea' },
    { key: 'notes', label: 'Notes', type: 'textarea' },
  ],
};

const mitreMapping: TemplateDefinition = {
  id: 'mitre-mapping',
  name: 'MITRE Mapping',
  pluralName: 'MITRE Mappings',
  description: 'Map objectives, rules, and data sources to ATT&CK tactics and techniques.',
  storageKey: 'mitreMappings',
  tableFields: ['mapping_id', 'technique_id', 'technique_name', 'tactic', 'coverage_type', 'priority'],
  filterFields: ['tactic', 'coverage_type', 'priority'],
  fields: [
    { key: 'mapping_id', label: 'Mapping ID', type: 'text', required: true },
    { key: 'tactic', label: 'Tactic', type: 'text', required: true, placeholder: 'Credential Access' },
    { key: 'technique_id', label: 'Technique ID', type: 'text', required: true, placeholder: 'T1110' },
    { key: 'technique_name', label: 'Technique Name', type: 'text', required: true },
    { key: 'subtechnique_id', label: 'Sub-technique ID', type: 'text', placeholder: 'T1110.003' },
    { key: 'coverage_type', label: 'Coverage Type', type: 'select', required: true, options: coverageTypes },
    { key: 'priority', label: 'Priority', type: 'select', options: priorities },
    { key: 'rule_ids', label: 'Rule IDs', type: 'tags' },
    { key: 'data_sources', label: 'Data Sources', type: 'tags' },
    { key: 'gaps', label: 'Known Gaps', type: 'textarea' },
  ],
};

const owner: TemplateDefinition = {
  id: 'owner',
  name: 'Owner / Team',
  pluralName: 'Owners',
  description: 'Track accountable owners for rules, data sources, objectives, and assets.',
  storageKey: 'owners',
  tableFields: ['owner_id', 'name', 'type', 'email', 'slack_channel', 'active'],
  filterFields: ['type', 'active'],
  fields: [
    { key: 'owner_id', label: 'Owner ID', type: 'text', required: true },
    { key: 'name', label: 'Name', type: 'text', required: true },
    { key: 'type', label: 'Type', type: 'select', required: true, options: ownerTypes },
    { key: 'email', label: 'Email', type: 'text' },
    { key: 'slack_channel', label: 'Slack Channel', type: 'text', placeholder: '#detection-engineering' },
    { key: 'active', label: 'Active', type: 'boolean' },
    { key: 'responsibilities', label: 'Responsibilities', type: 'tags' },
    { key: 'notes', label: 'Notes', type: 'textarea' },
  ],
};

export const templates = [
  rules,
  inventory,
  dataSource,
  detectionObjective,
  mitreMapping,
  owner,
] as const satisfies readonly TemplateDefinition[];

export const defaultTemplateId = rules.id;

export function getTemplate(templateId: string): TemplateDefinition {
  return templates.find((template) => template.id === templateId) ?? rules;
}
