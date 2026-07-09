import { StrictMode, useEffect, useRef, useState } from 'react';
import { AppShell } from './components/AppShell';
import { ImportExportPage } from './components/ImportExportPage';
import { JsonModal } from './components/JsonModal';
import { TemplateWorkspace } from './components/TemplateWorkspace';
import { getTemplate } from './data/templates';
import {
  exportStore,
  getTemplateRecords,
  importStorePayload,
  routeToTemplateId,
} from './lib/records';
import { loadRepoStore, loadStore, saveRepoStore, saveStore } from './lib/storage';
import type { JsonPreview, TemplateDefinition, TemplateStore } from './types';

type SyncState =
  | { status: 'loading'; message: string }
  | { status: 'saved'; message: string; targetRepo: string; savedFiles: string[] }
  | { status: 'local'; message: string }
  | { status: 'error'; message: string };

export function App() {
  const [store, setStore] = useState<TemplateStore>(() => loadStore());
  const [repoReady, setRepoReady] = useState(false);
  const [syncState, setSyncState] = useState<SyncState>({
    status: 'loading',
    message: 'Loading repo store...',
  });
  const [activeTemplateId, setActiveTemplateId] = useState(() => routeToTemplateId(window.location.pathname));
  const [preview, setPreview] = useState<JsonPreview | null>(null);
  const saveVersion = useRef(0);
  const firstRepoSave = useRef(true);
  const repoStoreFound = useRef(false);

  useEffect(() => {
    let mounted = true;

    void loadRepoStore()
      .then((result) => {
        if (!mounted) {
          return;
        }

        if (result?.store) {
          repoStoreFound.current = true;
          setStore(result.store);
          setSyncState({
            status: 'saved',
            message: `Loaded repo store from ${result.storePath}`,
            savedFiles: [],
            targetRepo: result.targetRepo,
          });
        } else if (result) {
          setSyncState({
            status: 'local',
            message: `No repo store yet at ${result.storePath}; browser data will sync on save.`,
          });
        } else {
          setSyncState({
            status: 'local',
            message: 'Repo sync endpoint unavailable; using browser storage.',
          });
        }
      })
      .catch((error: unknown) => {
        if (!mounted) {
          return;
        }
        setSyncState({
          status: 'error',
          message: error instanceof Error ? error.message : 'Unable to load repo store.',
        });
      })
      .finally(() => {
        if (mounted) {
          setRepoReady(true);
        }
      });

    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!repoReady) {
      return;
    }

    saveStore(store);
    if (firstRepoSave.current) {
      firstRepoSave.current = false;
      if (!repoStoreFound.current && !storeHasRecords(store)) {
        return;
      }
    }

    const currentSave = saveVersion.current + 1;
    saveVersion.current = currentSave;

    void saveRepoStore(store)
      .then((result) => {
        if (saveVersion.current !== currentSave) {
          return;
        }

        setSyncState({
          status: 'saved',
          message: `Saved ${result.savedFiles.length} file(s) to ${result.targetRepo}`,
          savedFiles: result.savedFiles,
          targetRepo: result.targetRepo,
        });
      })
      .catch((error: unknown) => {
        if (saveVersion.current !== currentSave) {
          return;
        }

        setSyncState({
          status: 'error',
          message: error instanceof Error ? error.message : 'Saved in browser only; repo sync failed.',
        });
      });
  }, [repoReady, store]);

  useEffect(() => {
    const handlePopState = () => setActiveTemplateId(routeToTemplateId(window.location.pathname));
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const navigate = (path: string) => {
    window.history.pushState(null, '', path);
    setActiveTemplateId(routeToTemplateId(path));
  };

  const importStoreFile = async (file: File) => {
    const text = await file.text();
    setStore(importStorePayload(JSON.parse(text)));
  };

  const exportAll = () => {
    downloadJson('ruleatlas-templates.json', exportStore(store));
  };

  const exportTemplate = (template: TemplateDefinition) => {
    downloadJson(`ruleatlas-${template.id}.json`, getTemplateRecords(store, template.id));
  };

  const template = getTemplate(activeTemplateId);
  const records = getTemplateRecords(store, activeTemplateId);

  return (
    <div className="app-shell">
      <AppShell activeTemplateId={activeTemplateId} onNavigate={navigate} />
      <div className="content-shell">
        <div className={`repo-sync-status repo-sync-${syncState.status}`}>
          {syncState.message}
        </div>
        {activeTemplateId === 'import-export' ? (
          <ImportExportPage
            store={store}
            onExport={exportAll}
            onImport={(file) => void importStoreFile(file)}
            onPreview={setPreview}
          />
        ) : (
          <TemplateWorkspace
            records={records}
            store={store}
            template={template}
            onExportTemplate={exportTemplate}
            onPreview={setPreview}
            onStoreChange={setStore}
          />
        )}
      </div>

      {preview ? (
        <JsonModal
          title={preview.title}
          value={preview.value}
          onClose={() => setPreview(null)}
          onCopy={copyText}
        />
      ) : null}
    </div>
  );
}

export function Root() {
  return (
    <StrictMode>
      <App />
    </StrictMode>
  );
}

function downloadJson(fileName: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}

async function copyText(value: string) {
  if (navigator.clipboard) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const textArea = document.createElement('textarea');
  textArea.value = value;
  document.body.appendChild(textArea);
  textArea.select();
  document.execCommand('copy');
  textArea.remove();
}

function storeHasRecords(store: TemplateStore): boolean {
  return Object.values(store).some((records) => records.length > 0);
}
