# RuleAtlas

Local-first template manager for detection engineering rule metadata.

## Local Rule Repo

RuleAtlas syncs browser edits to a local checkout of the rules repo while the Vite dev server is running. The rules repo content folder defaults to `contents`.

From the app, open **Config** and save the local detection rule repo path. This writes `ruleatlas.config.json` and switches the running dev server to that repo.

Create a local config:

```bash
cp ruleatlas.config.example.json ruleatlas.config.json
```

Edit `ruleatlas.config.json`:

```json
{
  "ruleRepo": {
    "path": "../detection-rules",
    "contentRoot": "contents"
  },
  "github": {
    "remote": "origin",
    "baseBranch": "main"
  },
  "attackData": {
    "path": "../../DetectionEngineering/attack_data",
    "maxDatasets": 5
  },
  "splunk": {
    "hecUrl": "https://splunk.local:8088",
    "apiUrl": "https://splunk.local:8089",
    "index": "attack_data",
    "verifyTls": true
  }
}
```

`path` is the local location of the rules repo checkout. Relative paths resolve from this project root.

Environment variables can override the file:

```bash
RULEATLAS_RULE_REPO=/path/to/detection-rules \
RULEATLAS_RULE_REPO_CONTENT_ROOT=contents \
npm run dev -- --host 127.0.0.1
```

## GitHub Pull Requests

Open **Repository** to review the current branch and changed files, fetch or fast-forward pull, create a feature branch, and publish a pull request. Publishing stages the configured rules repository, creates a commit when necessary, pushes the branch, and creates or reuses an open GitHub PR.

Authenticate with either option:

```bash
export GITHUB_TOKEN=github_pat_xxx
```

```bash
gh auth login
```

The token is read by the local Vite server. It is not stored in `ruleatlas.config.json` or returned to the browser.

## Splunk Attack-data Rule Tests

RuleAtlas scans the local [Splunk attack_data](https://github.com/splunk/attack_data) manifests. For rules with a MITRE technique, it selects exact or parent/sub-technique matches and uses rule tags/log source to rank them. If a rule has no MITRE technique, tags and log source provide the fallback match. The configured dataset cap prevents accidental multi-gigabyte pulls.

Install Git LFS and clone attack-data with smudge disabled:

```bash
git lfs install --skip-smudge
git clone https://github.com/splunk/attack_data ../../DetectionEngineering/attack_data
```

Configure Splunk credentials in the Vite server environment:

```bash
export SPLUNK_HEC_TOKEN=your-hec-token
export SPLUNK_API_TOKEN=your-splunk-api-token
export SPLUNK_HEC_URL=https://splunk.local:8088
export SPLUNK_API_URL=https://splunk.local:8089
export SPLUNK_INDEX=attack_data
npm run dev -- --host 127.0.0.1
```

Open **Rule testing** from the Utilities navigation, choose a saved Splunk rule, and optionally choose concrete datasets from the configured `attack_data` repository. RuleAtlas stores the rule snapshot, test name, notes, dataset choices, preview, and latest result in browser storage.

When a test runs, RuleAtlas:

1. Uses the explicitly selected datasets, or falls back to MITRE/tag/log-source mapping when the selection is empty.
2. Pulls only the selected Git LFS files and shows the exact selective fetch target and outcome.
3. Sends those files to Splunk HEC with a unique run host and records each HEC response.
4. Runs the rule query through the Splunk search export API.
5. Stores the live fetch/ingest/search activity, pass/fail result, and selected manifests on the Rule testing page.

The replay status treats HEC acceptance and detection matches as separate checkpoints. A successful HEC response confirms that Splunk accepted the collector request; the following search attempts show whether the replayed events became searchable and matched the rule.

Preview the selection before running to inspect the explicit files or mapping fallback without pulling LFS data or contacting Splunk. Set `splunk.verifyTls` to `false` only for a trusted local lab with a self-signed certificate.

Run locally:

```bash
npm install
npm run dev -- --host 127.0.0.1
```

RuleAtlas operational APIs are intentionally loopback-only and reject cross-origin browser requests because they can write files, run Git, and use server-side GitHub/Splunk credentials. Use SSH port forwarding when accessing a remote development host; do not expose the Vite server directly to a LAN or the internet.

Run checks:

```bash
npm test
npm run build
```
