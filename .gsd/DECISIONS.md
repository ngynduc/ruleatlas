# Decisions

## 2026-07-13 — Separate replay and historical Splunk tests

`POST /api/rule-tests/runs` accepts an additive `mode` field: `attack_data` (the compatibility default) or `historical`.

- `attack_data` performs dataset discovery, selective Git LFS materialization, HEC ingestion, test-index override, run-host scoping, and retry searches over `-5m` to `now`.
- `historical` skips the attack-data repository and HEC, preserves the original SPL/index constraints, and runs one search using caller-supplied `earliestTime` and `latestTime` values (defaults: `-24h` and `now`).
- Historical mode requires only the Splunk API URL/token. Replay mode continues to require both API and HEC configuration.
- Existing callers that omit `mode` retain replay behavior. The endpoint remains same-origin and loopback-only through the existing operational API protections.
