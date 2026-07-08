#!/usr/bin/env python3
"""
Update a Splunk saved search from an extracted RuleAtlas YAML rule.

The script reads data/test_rule.extracted.yaml by default, resolves the saved
search from metadata.id or title/splunk owner/app values, fetches the current
Splunk object, and posts only changed saved-search fields. The metadata section
is used only to find the object and is never sent back to Splunk. If a .env
file exists in the current directory, it is loaded without overriding exported
environment variables.

Examples:
  python scripts/splunk_rule_update.py --insecure

  SPLUNK_BASE_URL=https://127.0.0.1:8089 \
  SPLUNK_TOKEN='...' \
  python scripts/splunk_rule_update.py data/test_rule.extracted.yaml --apply
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


DEFAULT_INPUT = Path("data/test_rule.extracted.yaml")
DEFAULT_ENV_FILE = Path(".env")
DEFAULT_MANAGEMENT_PORT = 8089
MISSING = object()

TRUE_VALUES = {"1", "true", "yes", "y", "on", "enabled"}
FALSE_VALUES = {"0", "false", "no", "n", "off", "disabled"}

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

CSV_FIELDS = {
    "actions",
    "alert.suppress.fields",
}

SUPPORTED_UPDATE_FIELDS = {
    "actions",
    "alert.digest_mode",
    "alert.expires",
    "alert.severity",
    "alert.suppress",
    "alert.suppress.fields",
    "alert.suppress.group_name",
    "alert.suppress.period",
    "alert.track",
    "alert_comparator",
    "alert_condition",
    "alert_threshold",
    "alert_type",
    "cron_schedule",
    "description",
    "disabled",
    "dispatchAs",
    "displayview",
    "is_scheduled",
    "is_visible",
    "max_concurrent",
    "realtime_schedule",
    "request.ui_dispatch_app",
    "request.ui_dispatch_view",
    "restart_on_searchpeer_add",
    "run_n_times",
    "run_on_startup",
    "schedule_priority",
    "schedule_window",
    "search",
    "vsid",
    "workload_pool",
}

SENSITIVE_KEY_PARTS = ("password", "passwd", "secret", "token", "apikey", "api_key")

FIELD_MAPPINGS = (
    (("description",), "description", "string"),
    (("severity",), "alert.severity", "int"),
    (("query", "search"), "search", "string"),
    (("schedule", "cron"), "cron_schedule", "string"),
    (("schedule", "earliest_time"), "dispatch.earliest_time", "string"),
    (("schedule", "latest_time"), "dispatch.latest_time", "string"),
    (("schedule", "realtime"), "realtime_schedule", "bool"),
    (("alert", "type"), "alert_type", "string"),
    (("alert", "comparator"), "alert_comparator", "string"),
    (("alert", "threshold"), "alert_threshold", "int"),
    (("alert", "condition"), "alert_condition", "string"),
    (("alert", "expires"), "alert.expires", "string"),
    (("alert", "digest_mode"), "alert.digest_mode", "bool"),
    (("alert", "track"), "alert.track", "bool"),
    (("alert", "suppression", "enabled"), "alert.suppress", "bool"),
    (("alert", "suppression", "period"), "alert.suppress.period", "string"),
    (("alert", "suppression", "fields"), "alert.suppress.fields", "csv"),
    (("alert", "suppression", "group_name"), "alert.suppress.group_name", "string"),
    (("splunk", "dispatch", "ttl"), "dispatch.ttl", "string"),
    (("splunk", "dispatch", "max_count"), "dispatch.max_count", "int"),
    (("splunk", "dispatch", "max_time"), "dispatch.max_time", "int"),
    (("splunk", "dispatch", "lookups"), "dispatch.lookups", "bool"),
    (
        ("splunk", "dispatch", "allow_partial_results"),
        "dispatch.allow_partial_results",
        "bool",
    ),
)


class RuleUpdateError(RuntimeError):
    """Raised for validation, API, or rule mapping failures."""


def load_env_file(path: Path = DEFAULT_ENV_FILE) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.removeprefix("export ").strip()
        if not key:
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        os.environ.setdefault(key, value)


def configured_base_url() -> str | None:
    base_url = os.getenv("SPLUNK_BASE_URL")
    if base_url and base_url.strip():
        return base_url.strip().rstrip("/")

    host = os.getenv("SPLUNK_HOST")
    if not host or not host.strip():
        return None

    raw_host = host.strip().rstrip("/")
    parsed = urlparse(raw_host if "://" in raw_host else f"https://{raw_host}")
    if not parsed.hostname:
        return raw_host

    return f"https://{parsed.hostname}:{DEFAULT_MANAGEMENT_PORT}"


def parse_args() -> argparse.Namespace:
    load_env_file()

    parser = argparse.ArgumentParser(
        description=(
            "Read an extracted RuleAtlas YAML rule and update changed Splunk "
            "saved-search fields except metadata."
        )
    )
    parser.add_argument(
        "rule_file",
        nargs="?",
        default=str(DEFAULT_INPUT),
        help=f"Extracted YAML rule file. Default: {DEFAULT_INPUT}",
    )
    parser.add_argument(
        "--base-url",
        default=configured_base_url(),
        help="Splunk management URL, for example https://127.0.0.1:8089.",
    )
    parser.add_argument(
        "--username",
        default=os.getenv("SPLUNK_USERNAME"),
        help="Splunk username. Prefer SPLUNK_USERNAME over shell history.",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("SPLUNK_PASSWORD"),
        help="Splunk password. Prefer SPLUNK_PASSWORD over shell history.",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("SPLUNK_TOKEN"),
        help="Splunk bearer/session token. Prefer SPLUNK_TOKEN over shell history.",
    )
    parser.add_argument(
        "--token-type",
        default=os.getenv("SPLUNK_TOKEN_TYPE", "Bearer"),
        choices=("Bearer", "Splunk"),
        help="Authorization token scheme. Use Splunk for session keys.",
    )
    parser.add_argument(
        "--owner",
        help="Saved-search owner namespace override. Defaults to YAML splunk.owner.",
    )
    parser.add_argument(
        "--app",
        help="Saved-search app namespace override. Defaults to YAML splunk.app.",
    )
    parser.add_argument(
        "--name",
        help=(
            "Saved-search name override. Defaults to metadata.id path or YAML title. "
            "Use this when the YAML title has changed."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Post changed fields to Splunk. Without this flag the script is read-only.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for local/self-signed Splunk labs.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("SPLUNK_TIMEOUT", "30")),
        help="API timeout in seconds. Default: 30.",
    )
    return parser.parse_args()


def load_rules(path: Path) -> list[dict[str, Any]]:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuleUpdateError(
            "YAML input requires PyYAML. Install it with: pip install pyyaml"
        ) from exc

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return payload
    raise RuleUpdateError(f"{path} must contain a YAML object or a list of objects")


def get_path(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = data
    for part in path:
        if not isinstance(value, dict) or part not in value:
            return MISSING
        value = value[part]
    return value


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in TRUE_VALUES:
        return True
    if lowered in FALSE_VALUES:
        return False
    raise RuleUpdateError(f"{name} must be a boolean value")


def to_splunk_bool(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int) and value in (0, 1):
        return str(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in TRUE_VALUES:
            return "1"
        if lowered in FALSE_VALUES:
            return "0"
    raise RuleUpdateError(f"Expected a boolean-compatible value, got {value!r}")


def to_splunk_disabled(enabled: Any) -> str:
    return "0" if to_splunk_bool(enabled) == "1" else "1"


def status_to_disabled(status: Any) -> str:
    if not isinstance(status, str):
        raise RuleUpdateError(f"Expected status to be a string, got {status!r}")
    lowered = status.strip().lower()
    if lowered == "enabled":
        return "0"
    if lowered == "disabled":
        return "1"
    raise RuleUpdateError("Only status values 'enabled' and 'disabled' map to Splunk")


def to_splunk_int(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        raise RuleUpdateError(f"Expected an integer-compatible value, got {value!r}")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "":
            return ""
        try:
            return str(int(stripped))
        except ValueError as exc:
            raise RuleUpdateError(f"Expected an integer-compatible value, got {value!r}") from exc
    raise RuleUpdateError(f"Expected an integer-compatible value, got {value!r}")


def to_splunk_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return to_splunk_bool(value)
    return str(value)


def split_csv(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def to_splunk_csv(value: Any) -> str:
    return ",".join(split_csv(value))


def convert_value(value: Any, value_type: str) -> str:
    if value_type == "bool":
        return to_splunk_bool(value)
    if value_type == "int":
        return to_splunk_int(value)
    if value_type == "csv":
        return to_splunk_csv(value)
    return to_splunk_string(value)


def build_desired_fields(rule: dict[str, Any]) -> dict[str, str]:
    desired: dict[str, str] = {}
    disabled_candidates: list[tuple[str, str]] = []

    enabled = get_path(rule, ("enabled",))
    status = get_path(rule, ("status",))
    if enabled is not MISSING:
        disabled_candidates.append(("enabled", to_splunk_disabled(enabled)))
    if status is not MISSING:
        disabled_candidates.append(("status", status_to_disabled(status)))
    schedule_enabled = get_path(rule, ("schedule", "enabled"))
    if schedule_enabled is not MISSING:
        disabled_candidates.append(
            ("schedule.enabled", to_splunk_disabled(schedule_enabled))
        )
    if disabled_candidates:
        disabled_values = {value for _, value in disabled_candidates}
        if len(disabled_values) > 1:
            fields = ", ".join(name for name, _ in disabled_candidates)
            raise RuleUpdateError(f"YAML enablement fields disagree: {fields}")
        desired["disabled"] = disabled_candidates[0][1]

    for path, splunk_key, value_type in FIELD_MAPPINGS:
        value = get_path(rule, path)
        if value is not MISSING:
            desired[splunk_key] = convert_value(value, value_type)

    actions = get_path(rule, ("actions",))
    if actions is not MISSING:
        desired.update(build_action_fields(actions))

    validate_update_fields(desired)
    return desired


def validate_update_fields(fields: dict[str, str]) -> None:
    unsupported = sorted(key for key in fields if not is_supported_update_field(key))
    if unsupported:
        joined = ", ".join(unsupported)
        raise RuleUpdateError(f"Unsupported Splunk saved-search update field(s): {joined}")


def is_supported_update_field(key: str) -> bool:
    if key in SUPPORTED_UPDATE_FIELDS:
        return True
    if key.startswith("dispatch."):
        return True
    if key.startswith("args."):
        return True
    if key.startswith("action.") and key.count(".") >= 1:
        return True
    if key.startswith("auto_summarize."):
        return True
    if key.startswith("durable."):
        return True
    return False


def build_action_fields(actions: Any) -> dict[str, str]:
    if actions is None:
        actions = []
    if not isinstance(actions, list):
        raise RuleUpdateError("actions must be a YAML list")

    desired: dict[str, str] = {}
    action_names: list[str] = []

    for index, action in enumerate(actions, start=1):
        if not isinstance(action, dict):
            raise RuleUpdateError(f"actions[{index}] must be an object")

        action_type = action.get("type")
        if not action_type or not str(action_type).strip():
            raise RuleUpdateError(f"actions[{index}] must include a type")

        action_name = str(action_type).strip()
        action_names.append(action_name)

        if "enabled" in action:
            desired[f"action.{action_name}"] = to_splunk_bool(action["enabled"])

        params = action.get("params", MISSING)
        if params is not MISSING:
            if params is None:
                continue
            if not isinstance(params, dict):
                raise RuleUpdateError(f"actions[{index}].params must be an object")
            for param_name, param_value in params.items():
                if not str(param_name).strip():
                    raise RuleUpdateError(f"actions[{index}].params contains an empty key")
                desired[f"action.{action_name}.param.{param_name}"] = to_splunk_string(param_value)

    desired["actions"] = ",".join(action_names)
    return desired


def build_auth_headers(args: argparse.Namespace) -> dict[str, str]:
    if args.token:
        return {"Authorization": f"{args.token_type} {args.token}"}

    if not args.username or not args.password:
        raise RuleUpdateError(
            "Provide SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD for API access"
        )

    raw = f"{args.username}:{args.password}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def resolve_endpoint(
    rule: dict[str, Any],
    base_url: str | None,
    owner_override: str | None,
    app_override: str | None,
    name_override: str | None,
) -> str:
    metadata_id = get_path(rule, ("metadata", "id"))
    parsed_id = urlparse(metadata_id) if isinstance(metadata_id, str) else None

    if base_url:
        base = base_url.rstrip("/")
    elif parsed_id and parsed_id.scheme and parsed_id.netloc:
        base = f"{parsed_id.scheme}://{parsed_id.netloc}"
    else:
        raise RuleUpdateError("Provide --base-url or include a full metadata.id URL")

    if parsed_id and parsed_id.path.startswith("/servicesNS/") and not any(
        (owner_override, app_override, name_override)
    ):
        return f"{base}{parsed_id.path}"

    owner = owner_override or get_path(rule, ("splunk", "owner"))
    app = app_override or get_path(rule, ("splunk", "app"))
    name = name_override or get_path(rule, ("title",))

    if owner is MISSING or not str(owner).strip():
        owner = "nobody"
    if app is MISSING or not str(app).strip():
        app = "search"
    if name is MISSING or not str(name).strip():
        raise RuleUpdateError("Saved-search name is required; set YAML title or pass --name")

    return (
        f"{base}/servicesNS/{quote(str(owner).strip(), safe='')}/"
        f"{quote(str(app).strip(), safe='')}/saved/searches/"
        f"{quote(str(name).strip(), safe='')}"
    )


def with_output_mode(url: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["output_mode"] = "json"
    return urlunparse(parsed._replace(query=urlencode(query)))


def request_json(
    method: str,
    url: str,
    headers: dict[str, str],
    timeout: float,
    tls_context: ssl.SSLContext,
    fields: dict[str, str] | None = None,
) -> dict[str, Any]:
    data = urlencode(fields or {}).encode("utf-8") if fields is not None else None
    request = Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if fields is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    for key, value in headers.items():
        request.add_header(key, value)

    try:
        with urlopen(request, timeout=timeout, context=tls_context) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuleUpdateError(f"Splunk API returned HTTP {exc.code}: {body}") from exc
    except URLError as exc:
        raise RuleUpdateError(f"Could not reach Splunk API: {exc.reason}") from exc

    if not body.strip():
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuleUpdateError(f"Splunk API returned non-JSON response: {body[:500]}") from exc


def flatten_saved_search(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("entry"), list) and payload["entry"]:
        entry = payload["entry"][0]
        flattened = dict(entry.get("content") or {})
        for key in ("name", "id", "updated"):
            if entry.get(key) and not flattened.get(key):
                flattened[key] = entry[key]
        for key, value in (entry.get("acl") or {}).items():
            flattened[f"eai:acl.{key}"] = value
        return flattened

    if isinstance(payload.get("result"), dict):
        return payload["result"]

    return payload


def is_boolean_field(key: str) -> bool:
    if key in BOOLEAN_FIELDS:
        return True
    return key.startswith("action.") and ".param." not in key and key.count(".") == 1


def normalize_for_compare(key: str, value: Any) -> str:
    if value is MISSING:
        value = ""
    if is_boolean_field(key):
        return to_splunk_bool(value) if value != "" else ""
    if key in INT_FIELDS:
        return to_splunk_int(value)
    if key in CSV_FIELDS:
        return to_splunk_csv(value)
    return to_splunk_string(value)


def compute_changes(current: dict[str, Any], desired: dict[str, str]) -> dict[str, str]:
    changes: dict[str, str] = {}
    for key, desired_value in desired.items():
        current_value = current.get(key, MISSING)
        if normalize_for_compare(key, current_value) != normalize_for_compare(key, desired_value):
            changes[key] = desired_value
    return changes


def preview_value(key: str, value: Any) -> str:
    if any(part in key.lower() for part in SENSITIVE_KEY_PARTS):
        return "<redacted>"
    rendered = normalize_for_compare(key, value)
    rendered = rendered.replace("\n", "\\n")
    if len(rendered) > 120:
        return f"{rendered[:117]}..."
    return rendered


def print_change_summary(current: dict[str, Any], changes: dict[str, str]) -> None:
    for key in sorted(changes):
        before = preview_value(key, current.get(key, MISSING))
        after = preview_value(key, changes[key])
        print(f"  - {key}: {before!r} -> {after!r}")


def run() -> int:
    args = parse_args()
    rule_path = Path(args.rule_file)
    rules = load_rules(rule_path)
    headers = build_auth_headers(args)
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", True) and not args.insecure
    tls_context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()

    total_changes = 0

    for index, rule in enumerate(rules, start=1):
        title = get_path(rule, ("title",))
        label = str(title) if title is not MISSING else f"rule #{index}"
        endpoint = resolve_endpoint(rule, args.base_url, args.owner, args.app, args.name)
        current_payload = request_json(
            "GET",
            with_output_mode(endpoint),
            headers,
            args.timeout,
            tls_context,
        )
        current = flatten_saved_search(current_payload)
        desired = build_desired_fields(rule)
        changes = compute_changes(current, desired)

        print(f"{label}: {len(changes)} changed field(s)")
        if not changes:
            continue

        total_changes += len(changes)
        print_change_summary(current, changes)

        if args.apply:
            request_json(
                "POST",
                with_output_mode(endpoint),
                headers,
                args.timeout,
                tls_context,
                changes,
            )
            print("  posted update to Splunk")
        else:
            print("  dry run only; rerun with --apply to post these changes")

    return 0


def main() -> None:
    try:
        raise SystemExit(run())
    except RuleUpdateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
