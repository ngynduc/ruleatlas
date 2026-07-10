import {
  Button,
  Heading,
  HStack,
  Layout,
  LayoutContent,
  LayoutHeader,
  StackItem,
  Text,
  VStack,
} from '@astryxdesign/core';
import { useRef } from 'react';
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
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const summary = templates.map((template) => ({
    name: template.pluralName,
    count: store[template.storageKey]?.length ?? 0,
  }));

  return (
    <Layout
      height="fill"
      header={
        <LayoutHeader hasDivider label="Import export header">
          <HStack align="center" gap={4} paddingInline={4} paddingBlock={3} wrap="wrap">
            <StackItem size="fill">
              <VStack gap={1}>
                <Heading level={1}>Import / Export</Heading>
                <Text as="p" color="secondary" type="supporting">
                  Move all RuleAtlas local data as JSON.
                </Text>
              </VStack>
            </StackItem>
            <HStack align="center" className="header-actions" gap={2} wrap="wrap">
              <Button
                label="Preview JSON"
                variant="secondary"
                onClick={() => onPreview({ title: 'All RuleAtlas templates', value: store })}
              />
              <Button label="Export all JSON" variant="primary" onClick={onExport} />
              <Button label="Import JSON" variant="secondary" onClick={() => fileInputRef.current?.click()} />
              <input
                ref={fileInputRef}
                className="hidden-input"
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
            </HStack>
          </HStack>
        </LayoutHeader>
      }
    >
      <LayoutContent label="Import export summary">
        <section className="summary-grid" aria-label="Template counts">
          {summary.map((item) => (
            <article className="summary-cell" key={item.name}>
              <Text as="p" color="secondary" type="supporting">
                {item.name}
              </Text>
              <Text as="p" color="accent" type="display-3">
                {item.count}
              </Text>
            </article>
          ))}
        </section>
      </LayoutContent>
    </Layout>
  );
}
