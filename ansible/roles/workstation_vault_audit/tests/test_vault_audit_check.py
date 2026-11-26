"""Tests the Vault audit check against synthetic audit log entries."""

import importlib.util
import json
import os
import pathlib
import stat
import sys
from datetime import UTC, datetime

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "files" / "vault_audit_check.py"


def load_check_module():
    spec = importlib.util.spec_from_file_location("vault_audit_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load_check_module()

CONFIG = {
    "transit_mount": "transit-unseal",
    "transit_source_cidrs": ["172.16.127.0/24"],
    "kv_write_alert_paths": [
        {"mount": "secret", "path": "parent-group-governance/network/allocation"}
    ],
}
UNSEAL_PATH = "transit-unseal/decrypt/example-platform-vault-downstream"
ALLOCATION_DATA_PATH = "secret/data/parent-group-governance/network/allocation"


def build_response(
    path, operation="update", remote="172.16.127.10", error="", policies=None, time=None
):
    entry = {
        "type": "response",
        "error": error,
        "auth": {"policies": policies or ["default"], "accessor": "accessor-1"},
        "request": {"path": path, "operation": operation, "remote_address": remote},
    }
    if time is not None:
        entry["time"] = time
    return entry


@pytest.mark.parametrize(
    ("entry", "config", "expected"),
    [
        pytest.param(
            build_response(UNSEAL_PATH), CONFIG, [], id="unseal from allowed source"
        ),
        pytest.param(
            build_response(
                "transit-unseal/keys/example-platform-vault-downstream", operation="read"
            ),
            CONFIG,
            ["transit key administration"],
            id="key read on unseal mount",
        ),
        pytest.param(
            build_response(
                "transit-unseal/keys/k", operation="delete", error="permission denied"
            ),
            CONFIG,
            ["transit key administration", "transit unseal request failed"],
            id="failed key delete",
        ),
        pytest.param(
            build_response(UNSEAL_PATH, error="decryption failed"),
            CONFIG,
            ["transit unseal request failed"],
            id="failed unseal",
        ),
        pytest.param(
            build_response(UNSEAL_PATH, remote="10.0.0.5"),
            CONFIG,
            ["transit unseal request from an unexpected source"],
            id="foreign source",
        ),
        pytest.param(
            build_response(UNSEAL_PATH, remote="not-an-address"),
            CONFIG,
            ["transit unseal request from an unexpected source"],
            id="unparsable source",
        ),
        pytest.param(
            build_response(UNSEAL_PATH, remote="10.0.0.5"),
            {**CONFIG, "transit_source_cidrs": []},
            [],
            id="empty source list skips the source rule",
        ),
        pytest.param(
            build_response("sys/audit/file", operation="create"),
            CONFIG,
            ["audit device change"],
            id="audit device write",
        ),
        pytest.param(
            build_response("sys/audit", operation="read"),
            CONFIG,
            [],
            id="audit device read",
        ),
        pytest.param(
            build_response("secret/data/x", policies=["root"]),
            CONFIG,
            ["root token use"],
            id="root token",
        ),
        pytest.param(
            build_response(
                "sys/policies/acl/example-platform-x",
                operation="create",
                error="1 error occurred: permission denied",
            ),
            CONFIG,
            ["denied policy or role write"],
            id="denied policy write",
        ),
        pytest.param(
            build_response(
                "auth/approle/role/example-platform-x", error="permission denied"
            ),
            CONFIG,
            ["denied policy or role write"],
            id="denied role write",
        ),
        pytest.param(
            build_response(
                "sys/policies/acl/example-platform-x",
                operation="read",
                error="permission denied",
            ),
            CONFIG,
            [],
            id="denied policy read",
        ),
        pytest.param(
            build_response(ALLOCATION_DATA_PATH, operation="patch"),
            CONFIG,
            ["KV write to an alert path"],
            id="alert path patch",
        ),
        pytest.param(
            build_response(ALLOCATION_DATA_PATH, operation="create"),
            CONFIG,
            ["KV write to an alert path"],
            id="alert path put",
        ),
        pytest.param(
            build_response(
                "secret/metadata/parent-group-governance/network/allocation",
                operation="delete",
            ),
            CONFIG,
            ["KV write to an alert path"],
            id="alert path metadata delete",
        ),
        pytest.param(
            build_response(
                "secret/destroy/parent-group-governance/network/allocation",
                error="permission denied",
            ),
            CONFIG,
            ["KV write to an alert path"],
            id="denied alert path destroy",
        ),
        pytest.param(
            build_response(ALLOCATION_DATA_PATH, operation="read"),
            CONFIG,
            [],
            id="alert path read",
        ),
        pytest.param(
            build_response(f"{ALLOCATION_DATA_PATH}-draft", operation="create"),
            CONFIG,
            [],
            id="sibling path write",
        ),
        pytest.param(
            build_response("sys/generate-root/attempt", operation="update"),
            CONFIG,
            ["generate-root request"],
            id="generate-root attempt",
        ),
        pytest.param(
            build_response("sys/generate-root/update", operation="update"),
            CONFIG,
            ["generate-root request"],
            id="generate-root update",
        ),
        pytest.param(
            build_response("secret/data/x", policies=["operator-break-glass-root"]),
            CONFIG,
            ["break-glass-root policy use"],
            id="break-glass-root policy",
        ),
        pytest.param(
            build_response(
                "sys/generate-root/attempt",
                operation="update",
                policies=["operator-break-glass-root"],
            ),
            CONFIG,
            ["generate-root request", "break-glass-root policy use"],
            id="generate-root with break-glass-root policy",
        ),
    ],
)
def test_findings(entry, config, expected):
    messages = list(check.findings(entry, config))
    assert len(messages) == len(expected), messages
    for message, prefix in zip(messages, expected, strict=True):
        assert message.startswith(prefix), message
        assert f"path={entry['request']['path']}" in message
        assert "accessor=accessor-1" in message


def write_lines(path, lines, mode="a"):
    with open(path, mode, encoding="utf-8") as handle:
        handle.writelines(f"{line}\n" for line in lines)


def test_new_lines_returns_nothing_without_log(tmp_path):
    state = {"inode": 7, "offset": 3}
    assert check.new_lines(str(tmp_path / "audit.log"), state) == ([], state)


def test_new_lines_reads_only_appended_entries(tmp_path):
    log = tmp_path / "audit.log"
    write_lines(log, ["a", "b"])
    lines, state = check.new_lines(str(log), {})
    assert lines == ["a\n", "b\n"]
    assert state == {"inode": os.stat(log).st_ino, "offset": log.stat().st_size}

    write_lines(log, ["c"])
    lines, state = check.new_lines(str(log), state)
    assert lines == ["c\n"]
    assert state["offset"] == log.stat().st_size


def test_new_lines_restarts_after_truncation(tmp_path):
    log = tmp_path / "audit.log"
    write_lines(log, ["a", "b", "c"])
    _, state = check.new_lines(str(log), {})
    write_lines(log, ["d"], mode="w")
    lines, _ = check.new_lines(str(log), state)
    assert lines == ["d\n"]


def test_new_lines_finishes_the_rotated_file_first(tmp_path):
    log = tmp_path / "audit.log"
    write_lines(log, ["a"])
    _, state = check.new_lines(str(log), {})
    write_lines(log, ["b"])
    os.rename(log, tmp_path / "audit.log.1")
    write_lines(log, ["c"])

    lines, state = check.new_lines(str(log), state)
    assert lines == ["b\n", "c\n"]
    assert state == {"inode": os.stat(log).st_ino, "offset": log.stat().st_size}


def test_new_lines_skips_a_rotated_file_of_another_inode(tmp_path):
    log = tmp_path / "audit.log"
    write_lines(tmp_path / "audit.log.1", ["stale"])
    write_lines(log, ["fresh"])
    lines, _ = check.new_lines(str(log), {"inode": -1, "offset": 4})
    assert lines == ["fresh\n"]


@pytest.fixture
def captured_alerts(monkeypatch):
    calls = []
    monkeypatch.setattr(
        check.subprocess, "run", lambda args, check: calls.append((args, check))
    )
    return calls


def run_main(monkeypatch, config_path):
    monkeypatch.setattr(
        sys, "argv", ["vault_audit_check.py", "--config", str(config_path)]
    )
    check.main()


def test_main_exits_without_configuration(monkeypatch, tmp_path):
    with pytest.raises(SystemExit, match="missing configuration"):
        run_main(monkeypatch, tmp_path / "absent.json")


def test_main_alerts_once_per_finding_and_persists_state(
    monkeypatch, tmp_path, captured_alerts
):
    log = tmp_path / "audit.log"
    write_lines(
        log,
        [
            json.dumps(build_response("secret/data/x", policies=["root"])),
            json.dumps(
                {
                    **build_response("sys/audit/file", operation="create"),
                    "type": "request",
                }
            ),
            "not json",
            json.dumps(build_response(UNSEAL_PATH)),
        ],
    )
    state_file = tmp_path / "state" / "check-state.json"
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({**CONFIG, "log_path": str(log), "state_file": str(state_file)}),
        encoding="utf-8",
    )

    run_main(monkeypatch, config_path)
    assert len(captured_alerts) == 1
    args, raise_on_failure = captured_alerts[0]
    assert args[:5] == [
        "logger",
        "--priority",
        "auth.alert",
        "--tag",
        "vault-audit-alert",
    ]
    assert args[5].startswith("root token use")
    assert raise_on_failure is True
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["inode"] == os.stat(log).st_ino
    assert state["offset"] == log.stat().st_size
    assert state["counts"] == {"root_token_use": 1}
    assert isinstance(state["last_seen"]["root_token_use"], int)
    assert state["last_seen"]["root_token_use"] > 0

    run_main(monkeypatch, config_path)
    assert len(captured_alerts) == 1


def test_main_writes_prometheus_textfile_metrics_atomically(
    monkeypatch, tmp_path, captured_alerts
):
    log = tmp_path / "audit.log"
    t1 = "2026-11-25T10:00:00.123456789Z"
    ts1 = int(datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC).timestamp())
    write_lines(
        log,
        [
            json.dumps(
                build_response(
                    "sys/generate-root/attempt",
                    operation="update",
                    policies=["operator-break-glass-root"],
                    time=t1,
                )
            ),
            json.dumps(build_response(UNSEAL_PATH, time="2026-11-25T10:00:05Z")),
        ],
    )
    textfile_dir = tmp_path / "textfile"
    textfile_dir.mkdir()
    state_file = tmp_path / "state" / "check-state.json"
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                **CONFIG,
                "log_path": str(log),
                "state_file": str(state_file),
                "textfile_dir": str(textfile_dir),
            }
        ),
        encoding="utf-8",
    )

    run_main(monkeypatch, config_path)
    assert len(captured_alerts) == 2

    prom_path = textfile_dir / "vault_audit.prom"
    assert prom_path.exists()
    assert stat.S_IMODE(prom_path.stat().st_mode) == 0o640
    assert [p.name for p in textfile_dir.iterdir()] == ["vault_audit.prom"]

    body = prom_path.read_text(encoding="utf-8")
    expected_categories = (
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
    for cat in expected_categories:
        assert f'vault_audit_findings_total{{category="{cat}"}}' in body
        assert (
            f'vault_audit_finding_last_seen_timestamp_seconds{{category="{cat}"}}'
            in body
        )
    assert 'vault_audit_findings_total{category="generate_root_request"} 1' in body
    assert 'vault_audit_findings_total{category="break_glass_root_use"} 1' in body
    assert (
        f'vault_audit_finding_last_seen_timestamp_seconds{{category="generate_root_request"}} {ts1}'
        in body
    )
    assert (
        f'vault_audit_finding_last_seen_timestamp_seconds{{category="break_glass_root_use"}} {ts1}'
        in body
    )
    assert 'vault_audit_findings_total{category="root_token_use"} 0' in body
    assert (
        'vault_audit_finding_last_seen_timestamp_seconds{category="root_token_use"} 0'
        in body
    )
    assert "vault_audit_check_last_run_timestamp_seconds " in body

    t2 = "2026-11-25T10:05:00Z"
    ts2 = int(datetime(2026, 11, 25, 10, 5, 0, tzinfo=UTC).timestamp())
    write_lines(
        log,
        [json.dumps(build_response("sys/generate-root/update", operation="update", time=t2))],
    )
    run_main(monkeypatch, config_path)
    body2 = prom_path.read_text(encoding="utf-8")
    assert 'vault_audit_findings_total{category="generate_root_request"} 2' in body2
    assert (
        f'vault_audit_finding_last_seen_timestamp_seconds{{category="generate_root_request"}} {ts2}'
        in body2
    )
    assert 'vault_audit_findings_total{category="break_glass_root_use"} 1' in body2
    assert (
        f'vault_audit_finding_last_seen_timestamp_seconds{{category="break_glass_root_use"}} {ts1}'
        in body2
    )


def test_main_persists_state_before_textfile_write_failure(
    monkeypatch, tmp_path, captured_alerts
):
    log = tmp_path / "audit.log"
    write_lines(
        log,
        [json.dumps(build_response("secret/data/x", policies=["root"]))],
    )
    textfile_dir = tmp_path / "textfile"
    textfile_dir.mkdir()
    state_file = tmp_path / "state" / "check-state.json"
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                **CONFIG,
                "log_path": str(log),
                "state_file": str(state_file),
                "textfile_dir": str(textfile_dir),
            }
        ),
        encoding="utf-8",
    )

    def fail_write(*_args, **_kwargs):
        raise PermissionError("textfile dir not writable")

    monkeypatch.setattr(check, "write_textfile_metrics", fail_write)

    with pytest.raises(PermissionError, match="textfile dir not writable"):
        run_main(monkeypatch, config_path)

    assert len(captured_alerts) == 1
    assert state_file.exists()
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["offset"] == log.stat().st_size
    assert state["counts"] == {"root_token_use": 1}
