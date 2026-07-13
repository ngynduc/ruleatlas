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
  StatusDot,
  Switch,
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
  const [githubRemote, setGithubRemote] = useState('origin');
  const [githubBaseBranch, setGithubBaseBranch] = useState('main');
  const [attackDataPath, setAttackDataPath] = useState('../../DetectionEngineering/attack_data');
  const [attackDataMaxDatasets, setAttackDataMaxDatasets] = useState('5');
  const [splunkHecUrl, setSplunkHecUrl] = useState('');
  const [splunkApiUrl, setSplunkApiUrl] = useState('');
  const [splunkIndex, setSplunkIndex] = useState('attack_data');
  const [splunkVerifyTls, setSplunkVerifyTls] = useState(true);
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
        setGithubRemote(config.githubRemote);
        setGithubBaseBranch(config.githubBaseBranch);
        setAttackDataPath(config.attackDataPath);
        setAttackDataMaxDatasets(String(config.attackDataMaxDatasets));
        setSplunkHecUrl(config.splunkHecUrl);
        setSplunkApiUrl(config.splunkApiUrl);
        setSplunkIndex(config.splunkIndex);
        setSplunkVerifyTls(config.splunkVerifyTls);
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
        githubRemote: githubRemote.trim() || 'origin',
        githubBaseBranch: githubBaseBranch.trim() || 'main',
        attackDataPath: attackDataPath.trim(),
        attackDataMaxDatasets: Number(attackDataMaxDatasets) || 5,
        splunkHecUrl: splunkHecUrl.trim(),
        splunkApiUrl: splunkApiUrl.trim(),
        splunkIndex: splunkIndex.trim() || 'attack_data',
        splunkVerifyTls,
      });

      setRepoPath(config.path);
      setContentRoot(config.contentRoot);
      setGithubRemote(config.githubRemote);
      setGithubBaseBranch(config.githubBaseBranch);
      setAttackDataPath(config.attackDataPath);
      setAttackDataMaxDatasets(String(config.attackDataMaxDatasets));
      setSplunkHecUrl(config.splunkHecUrl);
      setSplunkApiUrl(config.splunkApiUrl);
      setSplunkIndex(config.splunkIndex);
      setSplunkVerifyTls(config.splunkVerifyTls);
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

            <section className="config-section" aria-label="GitHub settings">
              <VStack gap={4}>
                <Text as="p" color="primary" type="large">GitHub publishing</Text>
                <Text color="secondary" type="supporting">
                  Tokens are never stored here. Set GITHUB_TOKEN / GH_TOKEN, or authenticate the local gh CLI.
                </Text>
                <HStack align="center" gap={4} wrap="wrap">
                  <StackItem size="fill">
                    <TextInput
                      isRequired
                      label="Git remote"
                      placeholder="origin"
                      value={githubRemote}
                      onChange={setGithubRemote}
                    />
                  </StackItem>
                  <StackItem size="fill">
                    <TextInput
                      isRequired
                      label="Default base branch"
                      placeholder="main"
                      value={githubBaseBranch}
                      onChange={setGithubBaseBranch}
                    />
                  </StackItem>
                </HStack>
              </VStack>
            </section>

            <section className="config-section" aria-label="Attack data settings">
              <VStack gap={4}>
                <Text as="p" color="primary" type="large">Splunk attack-data</Text>
                <TextInput
                  isRequired
                  description="Local clone of splunk/attack_data. Relative paths resolve from the RuleAtlas project."
                  label="Attack-data repository path"
                  placeholder="../../DetectionEngineering/attack_data"
                  value={attackDataPath}
                  onChange={setAttackDataPath}
                />
                <TextInput
                  isRequired
                  description="Caps the number of data files pulled and ingested for one rule run (1–20)."
                  label="Maximum datasets per test"
                  placeholder="5"
                  value={attackDataMaxDatasets}
                  onChange={setAttackDataMaxDatasets}
                />
              </VStack>
            </section>

            <section className="config-section" aria-label="Splunk settings">
              <VStack gap={4}>
                <Text as="p" color="primary" type="large">Splunk test target</Text>
                <Text color="secondary" type="supporting">
                  Set SPLUNK_HEC_TOKEN and SPLUNK_API_TOKEN in the Vite server environment. Credential values are not written to config or returned to the browser.
                </Text>
                <TextInput
                  isRequired
                  description="Base URL or complete collector URL, for example https://splunk.local:8088."
                  label="HEC URL"
                  placeholder="https://splunk.local:8088"
                  value={splunkHecUrl}
                  onChange={setSplunkHecUrl}
                />
                <TextInput
                  isRequired
                  description="Splunk management API base URL, normally port 8089."
                  label="Search API URL"
                  placeholder="https://splunk.local:8089"
                  value={splunkApiUrl}
                  onChange={setSplunkApiUrl}
                />
                <TextInput
                  isRequired
                  label="Test index"
                  placeholder="attack_data"
                  value={splunkIndex}
                  onChange={setSplunkIndex}
                />
                <Switch
                  label="Verify Splunk TLS certificates"
                  value={splunkVerifyTls}
                  onChange={setSplunkVerifyTls}
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
                  <Text as="p" color="secondary" type="supporting">
                    Resolved attack-data repo
                  </Text>
                  <Text as="p" color="primary" type="body">
                    {resolvedConfig.resolvedAttackDataPath}
                  </Text>
                  <HStack align="center" gap={2} wrap="wrap">
                    <StatusDot
                      label={resolvedConfig.githubAuthAvailable ? 'GitHub token available' : 'GitHub token not detected'}
                      variant={resolvedConfig.githubAuthAvailable ? 'success' : 'neutral'}
                    />
                    <Text type="supporting">GitHub token {resolvedConfig.githubAuthAvailable ? 'available' : 'not detected'}</Text>
                  </HStack>
                  <HStack align="center" gap={2} wrap="wrap">
                    <StatusDot
                      label={resolvedConfig.splunkHecTokenAvailable ? 'Splunk HEC token available' : 'Splunk HEC token missing'}
                      variant={resolvedConfig.splunkHecTokenAvailable ? 'success' : 'warning'}
                    />
                    <Text type="supporting">HEC token {resolvedConfig.splunkHecTokenAvailable ? 'available' : 'missing'}</Text>
                  </HStack>
                  <HStack align="center" gap={2} wrap="wrap">
                    <StatusDot
                      label={resolvedConfig.splunkApiTokenAvailable ? 'Splunk API token available' : 'Splunk API token missing'}
                      variant={resolvedConfig.splunkApiTokenAvailable ? 'success' : 'warning'}
                    />
                    <Text type="supporting">Search token {resolvedConfig.splunkApiTokenAvailable ? 'available' : 'missing'}</Text>
                  </HStack>
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
