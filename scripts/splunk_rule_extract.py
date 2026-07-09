#!/usr/bin/env python3
"""
Extract useful fields from a Splunk saved-search/rule JSON export and convert it
into a clean rule-template YAML/JSON object.

Usage:
  python splunk_rule_extract.py test_rule.json -o rule.yaml
  python splunk_rule_extract.py exports/*.json --format json -o rules.json

Notes:
  - Drops null/empty values recursively.
  - Keeps string "0" values because Splunk uses them for meaningful settings.
  - Supports common Splunk shapes: {"result": {...}}, {"results": [...]},
    {"entry": [{"name": ..., "content": {...}, "acl": {...}}]}, or a raw dict.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


TRUE_VALUES = {"1", "true", "yes", "y", "on"}
FALSE_VALUES = {"0", "false", "no", "n", "off"}


BOOLEAN_FIELDS = {
    "disabled",
    "is_scheduled",
    "realtime_schedule",
    "run_on_startup",
    "alert.digest_mode",
    "alert.suppress",
    "alert.track",
    "dispatch.lookups",
    "dispatch.allow_partial_results",
    "action.webhook",
    "action.email",
    "action.rss",
    "action.script",
    "action.populate_lookup",
    "action.summary_index",
}


INT_FIELDS = {
    "alert.severity",
    "alert_threshold",
    "max_concurrent",
    "dispatch.max_count",
    "dispatch.max_time",
    "dispatch.reduce_freq",
}

DEFAULT_TEMPLATE_VERSION = "1.0.0"

MITRE_FIELD_GROUPS = {
    "tactics": ("mitre.tactics", "mitre_tactics", "mitre_tactic"),
    "techniques": ("mitre.techniques", "mitre_techniques", "mitre_technique"),
    "sub-techniques": (
        "mitre.sub-techniques",
        "mitre.sub_techniques",
        "mitre_sub_techniques",
        "mitre_sub_technique",
    ),
}


def is_empty(value: Any) -> bool:
    """Return True for values we do not want in the final template."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == "" or value.strip().lower() == "null"
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def clean(value: Any) -> Any:
    """Recursively remove empty values from dict/list structures."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            cleaned = clean(item)
            if not is_empty(cleaned):
                out[key] = cleaned
        return out
    if isinstance(value, list):
        out = [clean(item) for item in value]
        return [item for item in out if not is_empty(item)]
    return value


def parse_bool(value: Any) -> bool | Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in TRUE_VALUES:
            return True
        if lowered in FALSE_VALUES:
            return False
    return value


def parse_int(value: Any) -> int | Any:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return value
    return value


def get(src: dict[str, Any], key: str, default: Any = None) -> Any:
    value = src.get(key, default)
    if key in BOOLEAN_FIELDS:
        return parse_bool(value)
    if key in INT_FIELDS:
        return parse_int(value)
    return value


def split_csv(value: Any) -> list[str]:
    if is_empty(value):
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def flatten_splunk_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Flatten Splunk REST 'entry' format into the same shape as a raw result."""
    if "content" not in entry:
        return entry

    flattened = dict(entry.get("content") or {})

    if entry.get("name") and not flattened.get("title"):
        flattened["title"] = entry["name"]
    if entry.get("updated") and not flattened.get("updated"):
        flattened["updated"] = entry["updated"]
    if entry.get("id") and not flattened.get("id"):
        flattened["id"] = entry["id"]

    acl = entry.get("acl") or {}
    for key, value in acl.items():
        flattened[f"eai:acl.{key}"] = value

    return flattened


def iter_rules(payload: Any) -> Iterable[dict[str, Any]]:
    """Yield one or many rule dicts from common Splunk JSON export shapes."""
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield flatten_splunk_entry(item)
        return

    if not isinstance(payload, dict):
        raise TypeError("Expected JSON object or list of objects")

    if isinstance(payload.get("result"), dict):
        yield payload["result"]
        return

    if isinstance(payload.get("results"), list):
        for item in payload["results"]:
            if isinstance(item, dict):
                yield flatten_splunk_entry(item)
        return

    if isinstance(payload.get("entry"), list):
        for item in payload["entry"]:
            if isinstance(item, dict):
                yield flatten_splunk_entry(item)
        return

    # Fallback: treat the whole object as a rule.
    yield flatten_splunk_entry(payload)


def extract_actions(src: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []

    for action_name in split_csv(src.get("actions")):
        action: dict[str, Any] = {"type": action_name}

        prefix = f"action.{action_name}.param."
        params = {
            key.replace(prefix, ""): value
            for key, value in src.items()
            if key.startswith(prefix) and not is_empty(value)
        }
        if params:
            action["params"] = params

        enabled_key = f"action.{action_name}"
        if enabled_key in src:
            action["enabled"] = parse_bool(src[enabled_key])

        actions.append(clean(action))

    return actions


def extract_rule(src: dict[str, Any], include_raw: bool = False) -> dict[str, Any]:
    """Map Splunk fields to the RuleAtlas rule template."""
    disabled = get(src, "disabled")

    rule = {
        "title": get(src, "title"),
        "author": get(src, "author") or get(src, "eai:acl.owner"),
        "enabled": None if is_empty(disabled) else not bool(disabled),
        "status": "enabled" if disabled is False else "disabled" if disabled is True else None,
        "severity": get(src, "alert.severity"),
        "query": {
            "language": "spl",
            "search": get(src, "search")
        },
        "schedule": {
            "enabled": get(src, "is_scheduled"),
            "cron": get(src, "cron_schedule"),
            "earliest_time": get(src, "dispatch.earliest_time"),
            "latest_time": get(src, "dispatch.latest_time"),
            "realtime": get(src, "realtime_schedule"),
        },
        "alert": {
            "type": get(src, "alert_type"),
            "comparator": get(src, "alert_comparator"),
            "threshold": get(src, "alert_threshold"),
            "condition": get(src, "alert_condition"),
            "expires": get(src, "alert.expires"),
            "digest_mode": get(src, "alert.digest_mode"),
            "track": get(src, "alert.track"),
            "suppression": {
                "enabled": get(src, "alert.suppress"),
                "period": get(src, "alert.suppress.period"),
                "fields": split_csv(src.get("alert.suppress.fields")),
                "group_name": get(src, "alert.suppress.group_name"),
            },
        },
        "actions": extract_actions(src),
        "splunk": {
            "app": get(src, "eai:acl.app"),
            "owner": get(src, "eai:acl.owner"),
            "sharing": get(src, "eai:acl.sharing"),
            "server": get(src, "splunk_server"),
            "dispatch": {
                "ttl": get(src, "dispatch.ttl"),
                "max_count": get(src, "dispatch.max_count"),
                "max_time": get(src, "dispatch.max_time"),
                "lookups": get(src, "dispatch.lookups"),
                "allow_partial_results": get(src, "dispatch.allow_partial_results"),
            },
        },
        "metadata": {
            "id": get(src, "id"),
            "updated": get(src, "updated"),
            "last_updated_by": get(src, "eai:acl.owner") or get(src, "author"),
            "version": get(src, "version") or DEFAULT_TEMPLATE_VERSION,
        },
        "tags": split_csv(src.get("tags")),
        "mitre": {
            template_key: split_csv(
                next(
                    (
                        src.get(source_key)
                        for source_key in source_keys
                        if not is_empty(src.get(source_key))
                    ),
                    None,
                )
            )
            for template_key, source_keys in MITRE_FIELD_GROUPS.items()
        },
    }

    rule = clean(rule)
    rule.setdefault("tags", [])
    rule.setdefault(
        "mitre",
        {"tactics": [], "techniques": [], "sub-techniques": []},
    )
    for key in MITRE_FIELD_GROUPS:
        rule["mitre"].setdefault(key, [])

    if include_raw:
        rule["raw_splunk"] = clean(src)

    return rule


def dump_yaml(data: Any) -> str:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "YAML output requires PyYAML. Install it with: pip install pyyaml\n"
            "Or rerun with: --format json"
        ) from exc

    class LiteralStringDumper(yaml.SafeDumper):
        pass

    def str_presenter(dumper: yaml.SafeDumper, value: str):
        # Use clean block scalars for multiline SPL queries.
        style = "|" if "\n" in value else None
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)

    LiteralStringDumper.add_representer(str, str_presenter)

    return yaml.dump(
        data,
        Dumper=LiteralStringDumper,
        sort_keys=False,
        allow_unicode=True,
        width=120,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract clean detection-rule templates from Splunk saved-search JSON exports."
    )
    parser.add_argument("inputs", nargs="+", help="Input Splunk JSON export file(s).")
    parser.add_argument("-o", "--out", help="Output file. Defaults to stdout.")
    parser.add_argument(
        "--format",
        choices=("yaml", "json"),
        default="yaml",
        help="Output format. Default: yaml",
    )
    parser.add_argument(
        "--include-raw",
        action="store_true",
        help="Include cleaned raw Splunk fields under raw_splunk.",
    )
    args = parser.parse_args()

    extracted: list[dict[str, Any]] = []
    for input_path in args.inputs:
        payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
        for rule in iter_rules(payload):
            extracted.append(extract_rule(rule, include_raw=args.include_raw))

    output_data: Any = extracted[0] if len(extracted) == 1 else extracted

    if args.format == "json":
        rendered = json.dumps(output_data, indent=2, ensure_ascii=False) + "\n"
    else:
        rendered = dump_yaml(output_data)

    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
