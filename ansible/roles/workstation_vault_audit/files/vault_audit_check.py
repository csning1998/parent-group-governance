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

POLICY_PATH = re.compile(r"^sys/policies/acl/")
ROLE_PATH = re.compile(r"^auth/[^/]+/(role|users|groups|certs)/")
WRITE_OPERATIONS = {"create", "update", "delete"}


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


def findings(entry, config):
    """Yields one message per rule which the response entry violates."""
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
        yield f"transit key administration on the unseal mount: {where}"
    if path.startswith(f"{mount}/") and error:
        yield f"transit unseal request failed ({error}): {where}"
    if (
        unseal_path.match(path)
        and config["transit_source_cidrs"]
        and not in_cidrs(remote, config["transit_source_cidrs"])
    ):
        yield f"transit unseal request from an unexpected source: {where}"
    if path.startswith("sys/audit") and operation in WRITE_OPERATIONS:
        yield f"audit device change: {where}"
    if "root" in policies:
        yield f"root token use: {where}"
    if (
        "permission denied" in error
        and (POLICY_PATH.match(path) or ROLE_PATH.match(path))
        and operation in WRITE_OPERATIONS
    ):
        yield f"denied policy or role write: {where}"


def alert(message):
    subprocess.run(
        ["logger", "--priority", "auth.alert", "--tag", "vault-audit-alert", message],
        check=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = load_json(args.config, None)
    if config is None:
        sys.exit(f"missing configuration {args.config}")

    state_path = config["state_file"]
    lines, state = new_lines(config["log_path"], load_json(state_path, {}))
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("type") != "response":
            continue
        for message in findings(entry, config):
            alert(message)

    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


if __name__ == "__main__":
    main()
