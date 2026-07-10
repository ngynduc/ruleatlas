import { useEffect, useState } from 'react';
import {
  Banner,
  Button,
  Heading,
  HStack,
  Layout,
  LayoutContent,
  LayoutHeader,
  StackItem,
  Text,
  TextInput,
  VStack,
} from '@astryxdesign/core';
import { loadRepoConfig, saveRepoConfig } from '../lib/storage';
import type { RuleRepoConfigResult } from '../lib/storage';

interface ConfigPageProps {
  onSaved: (config: RuleRepoConfigResult) => void;
}

export function ConfigPage({ onSaved }: ConfigPageProps) {
  const [repoPath, setRepoPath] = useState('');
  const [contentRoot, setContentRoot] = useState('contents');
  const [resolvedConfig, setResolvedConfig] = useState<RuleRepoConfigResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    void loadRepoConfig()
      .then((config) => {
        if (!mounted) {
          return;
        }

        setRepoPath(config.path);
        setContentRoot(config.contentRoot);
        setResolvedConfig(config);
        setError(null);
      })
      .catch((loadError: unknown) => {
        if (!mounted) {
          return;
        }
        setError(loadError instanceof Error ? loadError.message : 'Unable to load rule repo config.');
      })
      .finally(() => {
        if (mounted) {
          setIsLoading(false);
        }
      });

    return () => {
      mounted = false;
    };
  }, []);

  const saveConfig = async () => {
    setIsSaving(true);
    setMessage(null);
    setError(null);

    try {
      const config = await saveRepoConfig({
        path: repoPath.trim(),
        contentRoot: contentRoot.trim() || '.',
      });

      setRepoPath(config.path);
      setContentRoot(config.contentRoot);
      setResolvedConfig(config);
      setMessage(`Saved rule repo config to ${config.configPath}`);
      onSaved(config);
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Unable to save rule repo config.');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <Layout
      height="fill"
      header={
        <LayoutHeader hasDivider label="Config header">
          <HStack align="center" gap={4} paddingInline={4} paddingBlock={3} wrap="wrap">
            <StackItem size="fill">
              <VStack gap={1}>
                <Heading level={1}>Config</Heading>
                <Text as="p" color="secondary" type="supporting">
                  Detection rule repository sync target.
                </Text>
              </VStack>
            </StackItem>
          </HStack>
        </LayoutHeader>
      }
    >
      <LayoutContent label="Rule repo config">
        <form
          className="config-form"
          onSubmit={(event) => {
            event.preventDefault();
            void saveConfig();
          }}
        >
          <VStack gap={4}>
            {isLoading ? <Banner status="warning" title="Loading rule repo config..." /> : null}
            {message ? <Banner status="success" title={message} /> : null}
            {error ? <Banner status="error" title={error} /> : null}

            <section className="config-section" aria-label="Rule repo path">
              <VStack gap={4}>
                <TextInput
                  isRequired
                  description="Absolute paths and paths relative to this project root are supported."
                  label="Detection rule repo path"
                  placeholder="../detection-rules"
                  value={repoPath}
                  onChange={setRepoPath}
                />
                <TextInput
                  description="Use . when rule files live at the repository root."
                  label="Content root"
                  placeholder="contents"
                  value={contentRoot}
                  onChange={setContentRoot}
                />
              </VStack>
            </section>

            {resolvedConfig ? (
              <section className="config-section" aria-label="Resolved paths">
                <VStack gap={2}>
                  <Text as="p" color="secondary" type="supporting">
                    Resolved repo
                  </Text>
                  <Text as="p" color="primary" type="body">
                    {resolvedConfig.targetRepo}
                  </Text>
                  <Text as="p" color="secondary" type="supporting">
                    Resolved content root
                  </Text>
                  <Text as="p" color="primary" type="body">
                    {resolvedConfig.contentRootPath}
                  </Text>
                  <Text as="p" color="secondary" type="supporting">
                    Config file
                  </Text>
                  <Text as="p" color="primary" type="body">
                    {resolvedConfig.configPath}
                  </Text>
                </VStack>
              </section>
            ) : null}

            <HStack align="center" className="header-actions" gap={2} wrap="wrap">
              <Button
                isDisabled={isLoading || !repoPath.trim()}
                isLoading={isSaving}
                label="Save config"
                type="submit"
                variant="primary"
              />
            </HStack>
          </VStack>
        </form>
      </LayoutContent>
    </Layout>
  );
}
