#!/usr/bin/env python3
"""Reads new Vault audit entries and writes each finding to the journal at priority alert.

The check keeps the inode and the offset of the audit log. After a rotation it reads the rest of the rotated file
before the new file. No entry between two runs therefore escapes the check.
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime

POLICY_PATH = re.compile(r"^sys/policies/acl/")
ROLE_PATH = re.compile(r"^auth/[^/]+/(role|users|groups|certs)/")
WRITE_OPERATIONS = {"create", "update", "delete"}
# vault kv patch issues the operation patch on the data path of a KV v2 secret.
KV_WRITE_OPERATIONS = WRITE_OPERATIONS | {"patch"}
KV_V2_PREFIXES = "data|metadata|delete|undelete|destroy"
BREAK_GLASS_POLICY = "operator-break-glass-root"
FRACTIONAL_SECONDS_PATTERN = re.compile(r"(\.\d{6})\d+")
FINDING_CATEGORIES = (
    "audit_device_change",
    "break_glass_root_use",
    "denied_policy_or_role_write",
    "generate_root_request",
    "kv_write_alert_path",
    "root_token_use",
    "transit_key_admin",
    "transit_unseal_failed",
    "transit_unseal_unexpected_source",
)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


def read_from(path, offset):
    with open(path, encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        lines = handle.readlines()
        return lines, handle.tell()


def new_lines(log_path, state):
    """Returns the lines written since the last run and the state for the next run."""
    try:
        stat = os.stat(log_path)
    except FileNotFoundError:
        return [], state
    lines = []
    offset = state.get("offset", 0)
    if state.get("inode") != stat.st_ino:
        rotated = f"{log_path}.1"
        if (
            state.get("inode") is not None
            and os.path.exists(rotated)
            and os.stat(rotated).st_ino == state["inode"]
        ):
            lines, _ = read_from(rotated, offset)
        offset = 0
    elif stat.st_size < offset:
        offset = 0
    tail, offset = read_from(log_path, offset)
    return lines + tail, {"inode": stat.st_ino, "offset": offset}


def in_cidrs(address, cidrs):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(cidr) for cidr in cidrs)


def classified_findings(entry, config):
    """Yields (category, message) tuples for each rule the response entry violates."""
    request = entry.get("request", {})
    path = request.get("path", "")
    operation = request.get("operation", "")
    remote = request.get("remote_address", "")
    error = entry.get("error", "") or ""
    policies = entry.get("auth", {}).get("policies", []) or []
    accessor = entry.get("auth", {}).get("accessor", "")
    mount = config["transit_mount"]
    unseal_path = re.compile(rf"^{re.escape(mount)}/(encrypt|decrypt)/[^/]+$")

    where = f"path={path} operation={operation} remote={remote} accessor={accessor}"
    if path.startswith(f"{mount}/") and not unseal_path.match(path):
        yield (
            "transit_key_admin",
            f"transit key administration on the unseal mount: {where}",
        )
    if path.startswith(f"{mount}/") and error:
        yield (
            "transit_unseal_failed",
            f"transit unseal request failed ({error}): {where}",
        )
    if (
        unseal_path.match(path)
        and config["transit_source_cidrs"]
        and not in_cidrs(remote, config["transit_source_cidrs"])
    ):
        yield (
            "transit_unseal_unexpected_source",
            f"transit unseal request from an unexpected source: {where}",
        )
    if path.startswith("sys/audit") and operation in WRITE_OPERATIONS:
        yield ("audit_device_change", f"audit device change: {where}")
    if path == "sys/generate-root" or path.startswith("sys/generate-root/"):
        yield ("generate_root_request", f"generate-root request: {where}")
    if "root" in policies:
        yield ("root_token_use", f"root token use: {where}")
    if BREAK_GLASS_POLICY in policies:
        yield ("break_glass_root_use", f"break-glass-root policy use: {where}")
    if (
        "permission denied" in error
        and (POLICY_PATH.match(path) or ROLE_PATH.match(path))
        and operation in WRITE_OPERATIONS
    ):
        yield (
            "denied_policy_or_role_write",
            f"denied policy or role write: {where}",
        )
    if matches_kv_write_alert(path, operation, config["kv_write_alert_paths"]):
        yield ("kv_write_alert_path", f"KV write to an alert path: {where}")


def findings(entry, config):
    """Yields one message per rule which the response entry violates."""
    for _, message in classified_findings(entry, config):
        yield message


def matches_kv_write_alert(path, operation, kv_write_alert_paths):
    if operation not in KV_WRITE_OPERATIONS:
        return False
    return any(
        re.match(
            rf"^{re.escape(alert['mount'])}/({KV_V2_PREFIXES})/{re.escape(alert['path'])}$",
            path,
        )
        for alert in kv_write_alert_paths
    )


def alert(message):
    subprocess.run(
        ["logger", "--priority", "auth.alert", "--tag", "vault-audit-alert", message],
        check=True,
    )


def parse_entry_timestamp(entry, fallback):
    """Parses the RFC3339 audit entry timestamp into integer Unix seconds."""
    raw = entry.get("time")
    if not isinstance(raw, str) or not raw:
        return fallback
    normalized = FRACTIONAL_SECONDS_PATTERN.sub(r"\1", raw.replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


def write_textfile_metrics(textfile_dir, counts, last_seen, run_timestamp):
    """Atomically writes Prometheus textfile metrics for node_exporter collection."""
    os.makedirs(textfile_dir, exist_ok=True)
    lines = [
        "# HELP vault_audit_findings_total Cumulative Vault audit alert findings by category.",
        "# TYPE vault_audit_findings_total counter",
    ]
    for category in FINDING_CATEGORIES:
        lines.append(
            f'vault_audit_findings_total{{category="{category}"}} {counts.get(category, 0)}'
        )
    lines.extend(
        [
            "# HELP vault_audit_finding_last_seen_timestamp_seconds Unix timestamp of the latest finding per category, or 0 if never seen.",
            "# TYPE vault_audit_finding_last_seen_timestamp_seconds gauge",
        ]
    )
    for category in FINDING_CATEGORIES:
        lines.append(
            f'vault_audit_finding_last_seen_timestamp_seconds{{category="{category}"}} {last_seen.get(category, 0)}'
        )
    lines.extend(
        [
            "# HELP vault_audit_check_last_run_timestamp_seconds Unix timestamp when vault_audit_check last completed.",
            "# TYPE vault_audit_check_last_run_timestamp_seconds gauge",
            f"vault_audit_check_last_run_timestamp_seconds {run_timestamp}",
        ]
    )
    tmp_path = os.path.join(textfile_dir, f".vault_audit.prom.{os.getpid()}.tmp")
    prom_path = os.path.join(textfile_dir, "vault_audit.prom")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.chmod(tmp_path, 0o644)
    os.replace(tmp_path, prom_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = load_json(args.config, None)
    if config is None:
        sys.exit(f"missing configuration {args.config}")

    state_path = config["state_file"]
    prior_state = load_json(state_path, {})
    counts = dict(prior_state.get("counts", {}))
    last_seen = dict(prior_state.get("last_seen", {}))
    run_timestamp = int(time.time())

    lines, state = new_lines(config["log_path"], prior_state)
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("type") != "response":
            continue
        entry_ts = parse_entry_timestamp(entry, run_timestamp)
        for category, message in classified_findings(entry, config):
            alert(message)
            counts[category] = int(counts.get(category, 0)) + 1
            last_seen[category] = max(int(last_seen.get(category, 0)), entry_ts)

    state["counts"] = counts
    state["last_seen"] = last_seen

    textfile_dir = config.get("textfile_dir")
    if textfile_dir:
        write_textfile_metrics(textfile_dir, counts, last_seen, run_timestamp)

    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


if __name__ == "__main__":
    main()
