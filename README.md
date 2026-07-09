# RuleAtlas

Local-first template manager for detection engineering rule metadata.

## Local Rule Repo

RuleAtlas syncs browser edits to a local checkout of the rules repo while the Vite dev server is running. The rules repo content folder defaults to `contents`.

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
  }
}
```

`path` is the local location of the rules repo checkout. Relative paths resolve from this project root.

Environment variables can override the file:

```bash
RULEATLAS_RULE_REPO=/path/to/detection-rules \
RULEATLAS_RULE_REPO_CONTENT_ROOT=contents \
npm run dev -- --host 0.0.0.0
```

Run locally:

```bash
npm install
npm run dev -- --host 0.0.0.0
```
