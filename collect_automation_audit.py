#!/usr/bin/env python3
# Copyright 2026 iDev Solutions
# SPDX-License-Identifier: Apache-2.0
"""Collect Jira Automation audit rows into the Analyzer's strict CSV contract.

The endpoint used here is an unsupported Atlassian internal API and may change.
The collector therefore validates every mapped record and fails closed instead
of silently emitting a misleading partial CSV.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


RETRYABLE = {429, 500, 502, 503, 504}
LIST_KEYS = ("auditItems", "items", "values", "results", "records", "auditLog", "auditLogs", "data")
UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)
SAFE_OUTPUT_PATTERN = re.compile(r"automation-audit-logs-[a-z0-9._-]+\.csv", re.IGNORECASE)
SAFE_DETAIL_OUTPUT_PATTERN = re.compile(
    r"automation-audit-details-[a-z0-9._-]+\.json", re.IGNORECASE,
)
KNOWN_STATUSES = {"SUCCESS", "NO_ACTIONS_PERFORMED", "SOME_ERRORS", "ABORTED", "NO_MATCH"}
DETAIL_MAX_CHUNK_RECORDS = 5_000
# The listing can mix execution rows with administrative history. These entries
# have no execution trace and must not be coerced into an Analyzer status.
NON_EXECUTION_CATEGORIES = {"CONFIG_CHANGE"}
IN_PROGRESS_CATEGORIES = {"IN_PROGRESS"}
ANALYZER_HEADERS = (
    "Start time",
    "Audit log ID",
    "Rule",
    "Rule ID",
    "Status",
    "Total time",
    "Associated items",
    "End time",
)
OVERVIEW_HEADERS = ANALYZER_HEADERS + (
    "Automation steps",
    "Step usage status",
)
OVERVIEW_MAX_CHUNK_RECORDS = 50_000
COLLECTOR_VERSION = "0.2.0"

FIELD_PATHS = {
    "audit_id": ("auditLogId", "auditItemId", "auditId", "id"),
    "rule_id": (
        "ruleIdUuid", "ruleUuid", "ruleUUID", "ruleId", "automationRuleId",
        "rule.uuid", "rule.ruleUuid", "rule.id", "automationRule.uuid",
    ),
    "rule_name": ("ruleName", "rule.name", "automationRule.name", "name"),
    "status": ("category", "status", "executionStatus", "outcome", "result.status"),
    "start": ("startTime", "startedAt", "createdAt", "created", "start", "timestamp"),
    "end": ("endTime", "endedAt", "completedAt", "finishedAt", "end"),
    "duration_ms": ("durationMs", "durationMillis", "executionTimeMs", "totalTimeMs"),
    "duration": ("duration", "executionTime", "totalTime"),
    "associated": (
        "associatedIds", "associatedItems", "items", "relatedItems", "context.associatedItems",
    ),
}


class MappingError(RuntimeError):
    pass


def get_json(url: str, auth: str | None = None, retries: int = 5) -> Any:
    headers = {
        "Accept": "application/json",
        "Cache-Control": "no-cache",
        "User-Agent": f"JiraAutomationAuditEvidenceCollector/{COLLECTOR_VERSION}",
    }
    if auth:
        headers["Authorization"] = auth

    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise RuntimeError(
                    f"HTTP {exc.code}. Check the account/token, global Automation permissions, "
                    "and remember that this endpoint is unsupported."
                ) from exc
            if exc.code not in RETRYABLE or attempt == retries:
                raise
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            wait = min(int(retry_after), 30) if retry_after and retry_after.isdigit() else min(2 ** attempt, 30)
            print(f"HTTP {exc.code}; retrying in {wait}s...")
            time.sleep(wait)
        except (TimeoutError, urllib.error.URLError, ConnectionError) as exc:
            if attempt == retries:
                raise RuntimeError(
                    f"Network request failed after {retries + 1} attempts: {type(exc).__name__}"
                ) from exc
            wait = min(2 ** attempt, 30)
            print(f"Network {type(exc).__name__}; retrying in {wait}s...")
            time.sleep(wait)
    raise AssertionError("retry loop did not return or raise")


def post_json_bytes(url: str, payload: dict[str, Any], auth: str, retries: int = 5) -> tuple[bytes, str]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {
        "Accept": "text/csv, application/json",
        "Authorization": auth,
        "Cache-Control": "no-cache",
        "Content-Type": "application/json",
        "User-Agent": f"JiraAutomationAuditEvidenceCollector/{COLLECTOR_VERSION}",
    }
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read(), response.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise RuntimeError(f"HTTP {exc.code} from the unsupported Automation export endpoint") from exc
            if exc.code not in RETRYABLE or attempt == retries:
                raise
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            wait = min(int(retry_after), 30) if retry_after and retry_after.isdigit() else min(2 ** attempt, 30)
            print(f"HTTP {exc.code}; retrying in {wait}s...")
            time.sleep(wait)
        except (TimeoutError, urllib.error.URLError, ConnectionError) as exc:
            if attempt == retries:
                raise RuntimeError(
                    f"Network request failed after {retries + 1} attempts: {type(exc).__name__}"
                ) from exc
            wait = min(2 ** attempt, 30)
            print(f"Network {type(exc).__name__}; retrying in {wait}s...")
            time.sleep(wait)
    raise AssertionError("retry loop did not return or raise")


def post_json(url: str, payload: dict[str, Any], auth: str, retries: int = 5) -> Any:
    body, content_type = post_json_bytes(url, payload, auth, retries)
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Automation listing returned a non-JSON response (content type: {content_type or 'unknown'})"
        ) from exc


def find_records(payload: Any) -> list[dict[str, Any]]:
    # Observed Automation listing contract: {"items": {"items": [...]}}.
    if (
        isinstance(payload, dict)
        and isinstance(payload.get("items"), dict)
        and isinstance(payload["items"].get("items"), list)
    ):
        candidates = payload["items"]["items"]
        if not all(isinstance(record, dict) for record in candidates):
            raise RuntimeError("The audit-record array contains a non-object entry")
        return candidates

    candidates: Any = payload
    if isinstance(payload, dict):
        candidates = None
        for key in LIST_KEYS:
            if isinstance(payload.get(key), list):
                candidates = payload[key]
                break
        if candidates is None:
            for outer in payload.values():
                if not isinstance(outer, dict):
                    continue
                for key in LIST_KEYS:
                    if isinstance(outer.get(key), list):
                        candidates = outer[key]
                        break
                if candidates is not None:
                    break
    if not isinstance(candidates, list):
        keys = sorted(payload.keys()) if isinstance(payload, dict) else []
        raise RuntimeError("Could not find the audit-record array. Top-level keys: " + ", ".join(keys))
    if not all(isinstance(record, dict) for record in candidates):
        raise RuntimeError("The audit-record array contains a non-object entry")
    return candidates


def value_at(record: dict[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def recursive_values(value: Any, keys: set[str]) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in keys:
                yield child
            yield from recursive_values(child, keys)
    elif isinstance(value, list):
        for child in value:
            yield from recursive_values(child, keys)


def candidate_values(record: dict[str, Any], paths: tuple[str, ...]) -> Iterable[Any]:
    yielded: list[Any] = []
    for path in paths:
        value = value_at(record, path)
        if value is not None and value not in yielded:
            yielded.append(value)
            yield value
    leaf_keys = {path.rsplit(".", 1)[-1] for path in paths}
    for value in recursive_values(record, leaf_keys):
        if value is not None and value not in yielded:
            yielded.append(value)
            yield value


def scalar_text(values: Iterable[Any]) -> str | None:
    for value in values:
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            text = str(value).strip()
            if text:
                return text
    return None


def uuid_text(values: Iterable[Any]) -> str | None:
    for value in values:
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            continue
        match = UUID_PATTERN.search(str(value))
        if match:
            return match.group(0).lower()
    return None


def parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000 if abs(float(value)) >= 100_000_000_000 else float(value)
        try:
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return parse_datetime(float(text))
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        for pattern in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                parsed = datetime.strptime(text, pattern)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def first_datetime(record: dict[str, Any], field: str) -> datetime | None:
    for value in candidate_values(record, FIELD_PATHS[field]):
        parsed = parse_datetime(value)
        if parsed:
            return parsed
    return None


def duration_ms(record: dict[str, Any]) -> int | None:
    for value in candidate_values(record, FIELD_PATHS["duration_ms"]):
        try:
            result = round(float(value))
        except (TypeError, ValueError):
            continue
        if result >= 0:
            return result
    for value in candidate_values(record, FIELD_PATHS["duration"]):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0, round(float(value)))
        match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s|m|h)\s*", str(value), re.IGNORECASE)
        if match:
            multiplier = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000}[match.group(2).lower()]
            return round(float(match.group(1)) * multiplier)
    return None


def associated_count(record: dict[str, Any]) -> int:
    for value in candidate_values(record, FIELD_PATHS["associated"]):
        if isinstance(value, list):
            return len(value)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        if isinstance(value, dict):
            return len(value)
    return 0


def normalize_status(record: dict[str, Any]) -> str:
    raw = scalar_text(candidate_values(record, FIELD_PATHS["status"]))
    if raw is None:
        raise MappingError("status was not found")
    normalized = re.sub(r"[^A-Z0-9]+", "_", raw.upper()).strip("_")
    aliases = {
        "NO_ACTIONS": "NO_ACTIONS_PERFORMED",
        "NO_ACTION": "NO_ACTIONS_PERFORMED",
        "PARTIAL_SUCCESS": "SOME_ERRORS",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in KNOWN_STATUSES:
        raise MappingError(f"unsupported status shape: {normalized[:80]}")
    return normalized


def is_non_execution_record(record: dict[str, Any]) -> bool:
    raw = value_at(record, "category")
    if not isinstance(raw, str):
        return False
    normalized = re.sub(r"[^A-Z0-9]+", "_", raw.upper()).strip("_")
    return normalized in NON_EXECUTION_CATEGORIES


def is_in_progress_record(record: dict[str, Any]) -> bool:
    raw = value_at(record, "category")
    if not isinstance(raw, str):
        return False
    normalized = re.sub(r"[^A-Z0-9]+", "_", raw.upper()).strip("_")
    return normalized in IN_PROGRESS_CATEGORIES


def format_local(value: datetime, target_timezone: ZoneInfo) -> str:
    local = value.astimezone(target_timezone)
    hour = local.hour % 12 or 12
    meridiem = "AM" if local.hour < 12 else "PM"
    return f"{local.month}/{local.day}/{str(local.year)[2:]}, {hour}:{local.minute:02d} {meridiem}"


def normalize_record(record: dict[str, Any], target_timezone: ZoneInfo) -> dict[str, str]:
    audit_id = scalar_text(candidate_values(record, FIELD_PATHS["audit_id"]))
    if not audit_id:
        raise MappingError("audit ID was not found")
    rule_id = uuid_text(candidate_values(record, FIELD_PATHS["rule_id"]))
    if not rule_id:
        raise MappingError("rule UUID was not found")
    start = first_datetime(record, "start")
    if not start:
        raise MappingError("start timestamp was not found or understood")
    elapsed = duration_ms(record)
    end = first_datetime(record, "end")
    if end is None and elapsed is not None:
        end = start + timedelta(milliseconds=elapsed)
    if end is None:
        raise MappingError("end timestamp and usable duration were both absent")
    if elapsed is None:
        elapsed = max(0, round((end - start).total_seconds() * 1000))
    item_count = associated_count(record)
    usage = value_at(record, "automationStepUsage")
    usage_steps = ""
    usage_status = ""
    if isinstance(usage, dict):
        raw_steps = usage.get("totalSteps")
        if isinstance(raw_steps, int) and not isinstance(raw_steps, bool) and raw_steps >= 0:
            usage_steps = str(raw_steps)
        raw_usage_status = usage.get("status")
        if isinstance(raw_usage_status, str):
            normalized_usage_status = re.sub(
                r"[^A-Z0-9]+", "_", raw_usage_status.upper(),
            ).strip("_")
            if 0 < len(normalized_usage_status) <= 80:
                usage_status = normalized_usage_status
    result = {
        "Start time": format_local(start, target_timezone),
        "Audit log ID": audit_id,
        "Rule": scalar_text(candidate_values(record, FIELD_PATHS["rule_name"])) or "",
        "Rule ID": rule_id,
        "Status": normalize_status(record),
        "Total time": f"{elapsed}ms",
        # Preserve only cardinality. Tenant item identifiers are unnecessary for analysis.
        "Associated items": ",".join(f"item-{index + 1}" for index in range(item_count)),
        "End time": format_local(end, target_timezone),
    }
    if usage_steps or usage_status:
        result["Automation steps"] = usage_steps
        result["Step usage status"] = usage_status
    return result


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def component_reference(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result = {
        key: value.get(key)
        for key in ("id", "type", "parentId", "componentType")
        if isinstance(value.get(key), (str, int)) and not isinstance(value.get(key), bool)
    }
    return result or None


def sanitize_change(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    child = component_reference(value.get("childComponent"))
    if child:
        result["childComponent"] = child
    if isinstance(value.get("stateChange"), str):
        result["stateChange"] = value["stateChange"]
    payload = value.get("payload")
    if isinstance(payload, dict):
        sanitized_payload = {
            key: payload.get(key)
            for key in ("type", "key")
            if isinstance(payload.get(key), str)
        }
        parameters = payload.get("appendParameters")
        if isinstance(parameters, list):
            sanitized_payload["parameterCount"] = len(parameters)
        if sanitized_payload:
            result["payload"] = sanitized_payload
    return result or None


def sanitize_component_log(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MappingError("component log was not an object")
    component = component_reference(value.get("component"))
    if not component:
        raise MappingError("component log did not contain a usable component reference")
    result: dict[str, Any] = {"component": component}
    for key in ("nameKey", "totalDuration", "totalExecutions", "startTime", "iteration", "resurrected"):
        field = value.get(key)
        if isinstance(field, (str, int, float, bool)) and field is not None:
            result[key] = field
    associated = value.get("associatedItems")
    result["associatedItemCount"] = len(associated) if isinstance(associated, list) else 0
    raw_changes = value.get("changes")
    changes = [
        sanitized for change in raw_changes if (sanitized := sanitize_change(change))
    ] if isinstance(raw_changes, list) else []
    result["changes"] = changes
    execution_result = value.get("executionResult")
    if isinstance(execution_result, dict):
        result["executionResult"] = {
            key: execution_result.get(key)
            for key in ("errorType", "auditEventErrorType", "state", "continuation")
            if isinstance(execution_result.get(key), str)
        }
    return result


def sanitize_rule_node(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MappingError("rule component was not an object")
    result = {
        key: value.get(key)
        for key in ("id", "parentId", "conditionParentId", "component", "type", "schemaVersion")
        if isinstance(value.get(key), (str, int)) and not isinstance(value.get(key), bool)
    }
    conditions = value.get("conditions")
    children = value.get("children")
    result["conditions"] = [sanitize_rule_node(item) for item in conditions] if isinstance(conditions, list) else []
    result["children"] = [sanitize_rule_node(item) for item in children] if isinstance(children, list) else []
    return result


def scope_kind(resource: Any) -> str:
    text = str(resource).lower()
    if ":project/" in text:
        return "PROJECT"
    if ":space/" in text:
        return "SPACE"
    if ":site/" in text or "::site/" in text:
        return "SITE"
    return "OTHER"


def sanitize_rule(rule: Any, expected_uuid: str) -> dict[str, Any]:
    if not isinstance(rule, dict):
        raise MappingError("rule detail was not an object")
    rule_uuid = uuid_text(candidate_values(rule, ("idUuid", "uuid", "ruleIdUuid")))
    if rule_uuid != expected_uuid:
        raise MappingError("rule detail UUID did not match its audit record")
    trigger = rule.get("trigger")
    components = rule.get("components")
    if not isinstance(trigger, dict) or not isinstance(components, list):
        raise MappingError("rule detail did not contain trigger/components topology")
    resources = value_at(rule, "ruleScope.resources")
    resource_kinds = sorted({scope_kind(item) for item in resources}) if isinstance(resources, list) else []
    return {
        "ruleIdUuid": rule_uuid,
        "state": rule.get("state") if isinstance(rule.get("state"), str) else None,
        "billingType": rule.get("billingType") if isinstance(rule.get("billingType"), str) else None,
        "canOtherRuleTrigger": rule.get("canOtherRuleTrigger")
        if isinstance(rule.get("canOtherRuleTrigger"), bool) else None,
        "scope": {"resourceCount": len(resources) if isinstance(resources, list) else 0, "kinds": resource_kinds},
        "trigger": sanitize_rule_node(trigger),
        "components": [sanitize_rule_node(component) for component in components],
    }


def sanitize_execution(
    detail: Any,
    expected_audit_id: str,
    expected_rule_uuid: str,
    reported_steps: int | None = None,
    step_usage_status: str | None = None,
) -> dict[str, Any]:
    if not isinstance(detail, dict):
        raise MappingError("audit detail was not an object")
    audit_id = scalar_text(candidate_values(detail, FIELD_PATHS["audit_id"]))
    rule_uuid = uuid_text(candidate_values(detail, FIELD_PATHS["rule_id"]))
    if audit_id != expected_audit_id:
        raise MappingError("audit detail ID did not match the listing record")
    if rule_uuid != expected_rule_uuid:
        raise MappingError("audit detail rule UUID did not match the listing record")
    start = first_datetime(detail, "start")
    end = first_datetime(detail, "end")
    elapsed = duration_ms(detail)
    if start is None or (end is None and elapsed is None):
        raise MappingError("audit detail did not contain usable timing fields")
    if end is None:
        end = start + timedelta(milliseconds=elapsed or 0)
    if elapsed is None:
        elapsed = max(0, round((end - start).total_seconds() * 1000))
    logs = value_at(detail, "content.componentLogs")
    if not isinstance(logs, list):
        raise MappingError("audit detail did not contain content.componentLogs")
    result = {
        "auditLogId": audit_id,
        "ruleIdUuid": rule_uuid,
        "status": normalize_status(detail),
        "startTime": utc_text(start),
        "endTime": utc_text(end),
        "durationMs": elapsed,
        "associatedItemCount": associated_count(detail),
        "componentLogs": [sanitize_component_log(log) for log in logs],
    }
    if reported_steps is not None:
        result["reportedSteps"] = reported_steps
    if step_usage_status:
        result["stepUsageStatus"] = step_usage_status
    return result


def flattened_paths(value: Any, prefix: str = "") -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.add(path)
            result.update(flattened_paths(child, path))
    elif isinstance(value, list) and value:
        result.update(flattened_paths(value[0], f"{prefix}[]"))
    return result


def safe_site(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".atlassian.net"):
        raise argparse.ArgumentTypeError("site must be an https://*.atlassian.net origin")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise argparse.ArgumentTypeError("site must not contain a path, query, credentials, or fragment")
    return f"https://{parsed.hostname}"


def safe_output(value: str) -> Path:
    output = Path(value).expanduser().resolve()
    if not SAFE_OUTPUT_PATTERN.fullmatch(output.name):
        raise argparse.ArgumentTypeError(
            "output filename must match automation-audit-logs-*.csv so Git ignores tenant data"
        )
    if not output.parent.is_dir():
        raise argparse.ArgumentTypeError("output parent directory does not exist")
    return output


def safe_detail_output(value: str) -> Path:
    output = Path(value).expanduser().resolve()
    if not SAFE_DETAIL_OUTPUT_PATTERN.fullmatch(output.name):
        raise argparse.ArgumentTypeError(
            "detail output filename must match automation-audit-details-*.json"
        )
    if not output.parent.is_dir():
        raise argparse.ArgumentTypeError("output parent directory does not exist")
    return output


def safe_rule_uuid(value: str) -> str:
    normalized = value.strip().lower()
    if not UUID_PATTERN.fullmatch(normalized):
        raise argparse.ArgumentTypeError("rule ID must be a UUID from the Automation rule URL/API")
    return normalized


def iso_utc(value: str) -> str:
    normalized = value.strip()
    parsed = parse_datetime(normalized)
    if parsed is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("time must be an ISO-8601 timestamp with timezone, preferably ending in Z")
    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def validate_native_export(body: bytes, content_type: str) -> str:
    if not body:
        raise RuntimeError("Automation export returned an empty response")
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"Automation export was not UTF-8 CSV (content type: {content_type or 'unknown'})") from exc
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        keys = sorted(payload.keys()) if isinstance(payload, dict) else []
        raise RuntimeError(
            "Automation export returned JSON instead of CSV. Response keys: " + ", ".join(keys)
        )
    try:
        header = next(csv.reader(text.splitlines()))
    except (StopIteration, csv.Error) as exc:
        raise RuntimeError("Automation export did not contain a readable CSV header") from exc
    if header and header[0].startswith("\ufeff"):
        header[0] = header[0].lstrip("\ufeff")
    if len(header) != len(ANALYZER_HEADERS) or set(header) != set(ANALYZER_HEADERS):
        raise RuntimeError(
            "Native export CSV headers do not match the Analyzer contract. Headers received: "
            + ", ".join(header)
        )
    return text


def write_csv_atomic(
    output: Path,
    rows: list[dict[str, str]],
    headers: tuple[str, ...] = ANALYZER_HEADERS,
) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8-sig", newline="", delete=False,
            dir=output.parent, prefix=f".{output.name}.", suffix=".tmp",
        ) as handle:
            temporary = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def write_text_atomic(output: Path, text: str) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8-sig", newline="", delete=False,
            dir=output.parent, prefix=f".{output.name}.", suffix=".tmp",
        ) as handle:
            temporary = Path(handle.name)
            handle.write(text.lstrip("\ufeff"))
        os.replace(temporary, output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def write_json_atomic(output: Path, value: Any) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="", delete=False,
            dir=output.parent, prefix=f".{output.name}.", suffix=".tmp",
        ) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def detail_part_path(output: Path, part_number: int, total_parts: int) -> Path:
    if total_parts == 1:
        return output
    return output.with_name(
        f"{output.stem}-part-{part_number:04d}-of-{total_parts:04d}{output.suffix}"
    )


def csv_part_path(output: Path, part_number: int, total_parts: int) -> Path:
    if total_parts == 1:
        return output
    return output.with_name(
        f"{output.stem}-part-{part_number:04d}-of-{total_parts:04d}{output.suffix}"
    )


def detail_listing_targets(rule_base: str, rule_ids: list[str]) -> list[tuple[str | None, str]]:
    if not rule_ids:
        return [(None, f"{rule_base}/auditlog")]
    return [
        (rule_uuid, f"{rule_base}/rule/{urllib.parse.quote(rule_uuid, safe='')}/auditlog")
        for rule_uuid in rule_ids
    ]


def detail_collection_id(
    site_fingerprint: str,
    from_time: str,
    to_time: str,
    listed: list[tuple[str, str, int | None, str | None]],
    selected_rule_ids: list[str] | None = None,
) -> str:
    digest = hashlib.sha256()
    digest.update(f"{site_fingerprint}\n{from_time}\n{to_time}\n".encode("utf-8"))
    if selected_rule_ids:
        digest.update(f"RULE_IDS\t{','.join(selected_rule_ids)}\n".encode("utf-8"))
    for audit_id, rule_uuid, reported_steps, step_usage_status in listed:
        digest.update(
            f"{audit_id}\t{rule_uuid}\t{reported_steps}\t{step_usage_status or ''}\n".encode("utf-8")
        )
    return digest.hexdigest()


def reusable_detail_part(
    path: Path,
    collection_id: str,
    part_number: int,
    total_parts: int,
    expected_audit_ids: list[str],
) -> bool:
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    coverage = payload.get("coverage") if isinstance(payload, dict) else None
    executions = payload.get("executions") if isinstance(payload, dict) else None
    if (not isinstance(coverage, dict) or not isinstance(executions, list)
            or payload.get("schemaVersion") != "automation-audit-detail/0.2"):
        return False
    if (
        coverage.get("collectionId") != collection_id
        or coverage.get("partNumber") != part_number
        or coverage.get("totalParts") != total_parts
    ):
        return False
    actual_ids = [item.get("auditLogId") for item in executions if isinstance(item, dict)]
    return actual_ids == expected_audit_ids


def promote_legacy_detail_seed(
    source_path: Path,
    target_path: Path,
    collection_id: str,
    total_parts: int,
    collection_executions: int,
    expected_audit_ids: list[str],
    pages: int,
    skipped_non_execution: int,
    skipped_in_progress: int,
    collection_truncated: bool,
) -> bool:
    if source_path == target_path or not source_path.is_file() or target_path.exists():
        return False
    try:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    executions = payload.get("executions") if isinstance(payload, dict) else None
    if (not isinstance(payload, dict)
            or payload.get("schemaVersion") != "automation-audit-detail/0.2"
            or not isinstance(executions, list)):
        return False
    actual_ids = [item.get("auditLogId") for item in executions if isinstance(item, dict)]
    if actual_ids != expected_audit_ids:
        return False
    rules = payload.get("rules") if isinstance(payload.get("rules"), list) else []
    payload["coverage"] = {
        "pages": pages,
        "collectionId": collection_id,
        "partNumber": 1,
        "totalParts": total_parts,
        "collectionExecutions": collection_executions,
        "listedExecutions": len(executions),
        "detailedExecutions": len(executions),
        "uniqueRules": len(rules),
        "skippedNonExecutionRecords": skipped_non_execution,
        "skippedInProgressRecords": skipped_in_progress,
        "truncatedByMaxRecords": collection_truncated,
    }
    write_json_atomic(target_path, payload)
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {COLLECTOR_VERSION}")
    parser.add_argument("--site", required=True, type=safe_site, help="https://example.atlassian.net")
    parser.add_argument("--timezone", required=True, help="IANA timezone used in the generated local timestamps")
    parser.add_argument(
        "--output",
        help=("Output path. CSV modes require automation-audit-logs-*.csv; "
              "detail mode requires automation-audit-details-*.json"),
    )
    parser.add_argument(
        "--limit", type=int, default=50,
        help="Records requested per POST page (the observed internal API maximum is 50)",
    )
    parser.add_argument(
        "--max-records", type=int,
        help="Optional maximum completed executions to collect; omit for the complete selected period",
    )
    parser.add_argument(
        "--chunk-size", type=int, default=1_000,
        help="Detailed executions per JSON part (default 1000, maximum 5000)",
    )
    parser.add_argument(
        "--overview-chunk-size", type=int, default=10_000,
        help="Rows per simple overview CSV part (default 10000, maximum 50000)",
    )
    parser.add_argument(
        "--rule-id", action="append", type=safe_rule_uuid, default=[],
        help=("Detail mode only: collect one rule UUID through the server-side rule filter. "
              "Repeat the option for more rules."),
    )
    parser.add_argument("--from-time", required=True, type=iso_utc, help="Start, ISO-8601 with timezone")
    parser.add_argument("--to-time", required=True, type=iso_utc, help="End, ISO-8601 with timezone")
    parser.add_argument(
        "--mode", choices=("list", "export", "detail"), default="list",
        help=("list maps paginated POST JSON records; export probes Atlassian's native export response; "
              "detail also fetches execution traces and sanitized rule topology"),
    )
    parser.add_argument(
        "--schema-only", action="store_true",
        help="Fetch one page and print field paths only; do not write tenant values",
    )
    args = parser.parse_args()
    if not 1 <= args.limit <= 50:
        parser.error("--limit must be between 1 and 50")
    if args.max_records is not None and args.max_records < 1:
        parser.error("--max-records must be positive")
    if not 1 <= args.chunk_size <= DETAIL_MAX_CHUNK_RECORDS:
        parser.error(f"--chunk-size must be between 1 and {DETAIL_MAX_CHUNK_RECORDS}")
    if not 1 <= args.overview_chunk_size <= OVERVIEW_MAX_CHUNK_RECORDS:
        parser.error(
            f"--overview-chunk-size must be between 1 and {OVERVIEW_MAX_CHUNK_RECORDS}"
        )
    if args.rule_id and args.mode != "detail":
        parser.error("--rule-id is available only with --mode detail")
    args.rule_id = list(dict.fromkeys(args.rule_id))
    if parse_datetime(args.from_time) >= parse_datetime(args.to_time):
        parser.error("--from-time must be earlier than --to-time")
    try:
        if args.mode == "detail":
            args.output = safe_detail_output(args.output or "automation-audit-details-api.json")
        else:
            args.output = safe_output(args.output or "automation-audit-logs-api.csv")
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    try:
        args.zone = ZoneInfo(args.timezone)
    except ZoneInfoNotFoundError:
        parser.error("--timezone must be a valid IANA timezone, for example America/Sao_Paulo")
    return args


def main() -> None:
    args = parse_args()
    email = os.environ.get("ATLASSIAN_EMAIL")
    token = os.environ.get("ATLASSIAN_API_TOKEN")
    if not email or not token:
        raise SystemExit("Set ATLASSIAN_EMAIL and ATLASSIAN_API_TOKEN first")

    tenant = get_json(f"{args.site}/_edge/tenant_info")
    if not isinstance(tenant, dict) or not isinstance(tenant.get("cloudId"), str):
        raise SystemExit("The tenant-info response did not contain a cloudId")
    cloud_id = tenant["cloudId"]
    basic = base64.b64encode(f"{email}:{token}".encode()).decode()
    auth = f"Basic {basic}"
    try:
        get_json(f"{args.site}/rest/api/3/myself", auth=auth, retries=0)
    except RuntimeError:
        raise SystemExit(
            "Authentication failed against Jira's supported /rest/api/3/myself endpoint. "
            "Confirm that ATLASSIAN_EMAIL belongs to the token owner. If this is a scoped or "
            "service-account token, it may require api.atlassian.com and cannot authenticate "
            "this site-local internal endpoint; use a classic personal API token for this lab collector."
        ) from None
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"Jira authentication preflight failed with HTTP {exc.code}.") from None
    endpoint = (
        f"{args.site}/gateway/api/automation/internal-api/jira/"
        f"{urllib.parse.quote(cloud_id, safe='')}/pro/rest/GLOBAL/auditlog"
    )
    rule_base = endpoint.rsplit("/auditlog", 1)[0]

    if args.mode == "export" and not args.schema_only:
        export_payload = {
            "fromTime": args.from_time,
            "toTime": args.to_time,
            "actionTypes": [],
            "triggerTypes": [],
            "orchestrationTypes": [],
        }
        try:
            export_body, content_type = post_json_bytes(f"{endpoint}/export", export_payload, auth)
            export_csv = validate_native_export(export_body, content_type)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from None
        write_text_atomic(args.output, export_csv)
        print(f"Done: native Automation audit export -> {args.output}")
        print(f"Use timezone {args.timezone} when supplying analysis cutoff context in the Analyzer.")
        print("Treat the CSV as administrative Jira data. The filename is ignored by this repository's Git rules.")
        return

    if args.mode == "detail" and not args.schema_only:
        listed: list[tuple[str, str, int | None, str | None]] = []
        seen_listing_ids: set[str] = set()
        page = 0
        skipped_non_execution = 0
        skipped_in_progress = 0
        listing_targets = detail_listing_targets(rule_base, args.rule_id)
        maximum_reached = False
        for target_rule_uuid, listing_endpoint in listing_targets:
            offset = 0
            target_page = 0
            while True:
                page += 1
                target_page += 1
                list_payload = {
                    "fromTime": args.from_time,
                    "toTime": args.to_time,
                    "offset": offset,
                    "limit": args.limit,
                    "actionTypes": [],
                    "triggerTypes": [],
                    "orchestrationTypes": [],
                }
                try:
                    payload = post_json(listing_endpoint, list_payload, auth)
                    records = find_records(payload)
                except RuntimeError as exc:
                    raise SystemExit(str(exc)) from None
                for record in records:
                    if is_non_execution_record(record):
                        skipped_non_execution += 1
                        continue
                    if is_in_progress_record(record):
                        skipped_in_progress += 1
                        continue
                    try:
                        row = normalize_record(record, args.zone)
                    except MappingError as exc:
                        paths = ", ".join(sorted(flattened_paths(record)))
                        raise SystemExit(
                            f"Listing record could not be mapped safely: {exc}. "
                            f"Available field paths: {paths}"
                        ) from None
                    if target_rule_uuid and row["Rule ID"] != target_rule_uuid:
                        raise SystemExit(
                            "The rule-filtered endpoint returned a different rule UUID; "
                            "detail collection stopped without guessing."
                        )
                    audit_id = row["Audit log ID"]
                    if audit_id in seen_listing_ids:
                        continue
                    seen_listing_ids.add(audit_id)
                    raw_reported_steps = row.get("Automation steps", "")
                    reported_steps = int(raw_reported_steps) if raw_reported_steps.isdigit() else None
                    step_usage_status = row.get("Step usage status") or None
                    listed.append((audit_id, row["Rule ID"], reported_steps, step_usage_status))
                    if args.max_records and len(listed) >= args.max_records:
                        maximum_reached = True
                        break
                target_label = target_rule_uuid or "all rules"
                print(
                    f"Listing {target_label} page {target_page}: received {len(records)}, "
                    f"selected {len(listed)}, administrative skipped {skipped_non_execution}, "
                    f"in-progress skipped {skipped_in_progress}"
                )
                if maximum_reached or len(records) < args.limit:
                    break
                offset += args.limit
            if maximum_reached:
                break

        if not listed:
            raise SystemExit("No audit records returned; no detail JSON was written")

        host = urllib.parse.urlsplit(args.site).hostname or ""
        site_fingerprint = hashlib.sha256(host.encode("utf-8")).hexdigest()
        collection_id = detail_collection_id(
            site_fingerprint, args.from_time, args.to_time, listed, args.rule_id,
        )
        total_parts = (len(listed) + args.chunk_size - 1) // args.chunk_size
        collection_truncated = bool(args.max_records and len(listed) >= args.max_records)
        rules_cache: dict[str, dict[str, Any]] = {}
        written_paths: list[Path] = []
        reused_parts = 0
        if total_parts > 1 and not args.rule_id:
            first_entries = listed[:args.chunk_size]
            first_part_path = detail_part_path(args.output, 1, total_parts)
            if promote_legacy_detail_seed(
                args.output,
                first_part_path,
                collection_id,
                total_parts,
                len(listed),
                [audit_id for audit_id, _rule_uuid, _steps, _status in first_entries],
                page,
                skipped_non_execution,
                skipped_in_progress,
                collection_truncated,
            ):
                print(f"Part 1/{total_parts}: promoted existing compatible sample -> {first_part_path}")
        for part_index in range(total_parts):
            part_number = part_index + 1
            part_entries = listed[part_index * args.chunk_size:(part_index + 1) * args.chunk_size]
            part_path = detail_part_path(args.output, part_number, total_parts)
            expected_ids = [
                audit_id for audit_id, _rule_uuid, _steps, _status in part_entries
            ]
            if reusable_detail_part(
                part_path, collection_id, part_number, total_parts, expected_ids,
            ):
                reused_parts += 1
                written_paths.append(part_path)
                print(f"Part {part_number}/{total_parts}: reused existing verified file {part_path}")
                continue

            executions: list[dict[str, Any]] = []
            part_rule_ids = sorted({
                rule_uuid for _audit_id, rule_uuid, _steps, _status in part_entries
            })
            for part_record_index, (
                audit_id, rule_uuid, reported_steps, step_usage_status,
            ) in enumerate(part_entries, start=1):
                global_index = part_index * args.chunk_size + part_record_index
                try:
                    detail = get_json(
                        f"{endpoint}/item/{urllib.parse.quote(audit_id, safe='')}", auth=auth,
                    )
                    executions.append(sanitize_execution(
                        detail, audit_id, rule_uuid, reported_steps, step_usage_status,
                    ))
                    if rule_uuid not in rules_cache:
                        rule = get_json(
                            f"{rule_base}/rule/{urllib.parse.quote(rule_uuid, safe='')}", auth=auth,
                        )
                        rules_cache[rule_uuid] = sanitize_rule(rule, rule_uuid)
                except (RuntimeError, MappingError, urllib.error.HTTPError) as exc:
                    raise SystemExit(
                        f"Detail collection stopped at record {global_index}/{len(listed)} "
                        f"(part {part_number}/{total_parts}): {exc}. "
                        "Previously completed part files remain reusable; run the same command again."
                    ) from None
                print(
                    f"Detail {global_index}/{len(listed)} · part {part_number}/{total_parts}: collected"
                )

            bundle = {
                "schemaVersion": "automation-audit-detail/0.2",
                "generatedAt": utc_text(datetime.now(timezone.utc)),
                "source": {
                    "family": "jira-automation-internal-api",
                    "siteFingerprint": site_fingerprint,
                    "authentication": "basic-api-token",
                },
                "period": {
                    "fromTime": args.from_time,
                    "toTime": args.to_time,
                    "displayTimezone": args.timezone,
                },
                "coverage": {
                    "pages": page,
                    "collectionId": collection_id,
                    "partNumber": part_number,
                    "totalParts": total_parts,
                    "collectionExecutions": len(listed),
                    "listedExecutions": len(part_entries),
                    "detailedExecutions": len(executions),
                    "uniqueRules": len(part_rule_ids),
                    "skippedNonExecutionRecords": skipped_non_execution,
                    "skippedInProgressRecords": skipped_in_progress,
                    "truncatedByMaxRecords": collection_truncated,
                    "selectionMode": "RULE_IDS" if args.rule_id else "ALL_RULES",
                    "selectedRuleIds": args.rule_id,
                },
                "rules": [rules_cache[key] for key in part_rule_ids],
                "executions": executions,
            }
            write_json_atomic(part_path, bundle)
            written_paths.append(part_path)
            print(f"Part {part_number}/{total_parts}: wrote {len(executions)} executions -> {part_path}")

        if collection_truncated:
            print(
                f"Done: bounded collection of {len(listed)} executions in {total_parts} file(s); "
                f"{reused_parts} existing part(s) reused."
            )
            print(
                f"Collection truncated by --max-records {args.max_records}; "
                "additional executions may exist in the selected period."
            )
        else:
            print(
                f"Done: complete period with {len(listed)} detailed executions in "
                f"{total_parts} file(s); {reused_parts} existing part(s) reused."
            )
        if total_parts > 1:
            print(f"Import all {total_parts} generated part files together in the Analyzer.")
        print("Associated item values, rule values, user data, URLs, cookies, and tokens were not written.")
        return

    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    offset = 0
    page = 0
    skipped_non_execution = 0
    skipped_in_progress = 0
    while True:
        page += 1
        list_payload = {
            "fromTime": args.from_time,
            "toTime": args.to_time,
            "offset": offset,
            "limit": args.limit,
            "actionTypes": [],
            "triggerTypes": [],
            "orchestrationTypes": [],
        }
        try:
            payload = post_json(endpoint, list_payload, auth)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from None
        records = find_records(payload)
        if not records:
            break
        if args.schema_only:
            print("\n".join(sorted(flattened_paths(records[0]))))
            return

        kept = 0
        mapping_errors: list[str] = []
        for record in records:
            if is_non_execution_record(record):
                skipped_non_execution += 1
                continue
            if is_in_progress_record(record):
                skipped_in_progress += 1
                continue
            try:
                row = normalize_record(record, args.zone)
            except MappingError as exc:
                if len(mapping_errors) < 5:
                    paths = ", ".join(sorted(flattened_paths(record)))
                    mapping_errors.append(f"{exc}; available field paths: {paths}")
                continue
            audit_id = row["Audit log ID"]
            if audit_id in seen:
                continue
            seen.add(audit_id)
            rows.append(row)
            kept += 1
            if args.max_records and len(rows) >= args.max_records:
                break

        if mapping_errors:
            details = "\n\n".join(mapping_errors)
            raise SystemExit(
                "The unsupported API returned records that could not be mapped safely. "
                "No CSV was written. Field names are shown below; record values are omitted.\n\n" + details
            )
        print(
            f"Page {page}: received {len(records)}, kept {kept}, total {len(rows)}, "
            f"administrative skipped {skipped_non_execution}, in-progress skipped {skipped_in_progress}"
        )
        if args.max_records and len(rows) >= args.max_records:
            break
        if len(records) < args.limit:
            break
        offset += args.limit

    if not rows:
        raise SystemExit("No audit records returned; no CSV was written")
    total_parts = (len(rows) + args.overview_chunk_size - 1) // args.overview_chunk_size
    written_paths: list[Path] = []
    for part_index in range(total_parts):
        part_rows = rows[
            part_index * args.overview_chunk_size:(part_index + 1) * args.overview_chunk_size
        ]
        part_path = csv_part_path(args.output, part_index + 1, total_parts)
        write_csv_atomic(part_path, part_rows, OVERVIEW_HEADERS)
        written_paths.append(part_path)
        print(
            f"Overview part {part_index + 1}/{total_parts}: "
            f"wrote {len(part_rows)} executions -> {part_path}"
        )
    print(f"Done: {len(rows)} simple overview records in {total_parts} file(s)")
    if total_parts > 1:
        print(f"Import all {total_parts} generated CSV part files together in the Analyzer.")
    if args.max_records and len(rows) >= args.max_records:
        print(
            f"Collection truncated by --max-records {args.max_records}; "
            "additional executions may exist in the selected period."
        )
    print(f"Use timezone {args.timezone} when supplying analysis cutoff context in the Analyzer.")
    print("Treat the CSV as administrative Jira data. The filename is ignored by this repository's Git rules.")


if __name__ == "__main__":
    main()
