"""Tests the Vault audit check against synthetic audit log entries."""

import importlib.util
import json
import os
import pathlib
import sys

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
}
UNSEAL_PATH = "transit-unseal/decrypt/meta-platform-vault-downstream"


def build_response(
    path, operation="update", remote="172.16.127.10", error="", policies=None
):
    return {
        "type": "response",
        "error": error,
        "auth": {"policies": policies or ["default"], "accessor": "accessor-1"},
        "request": {"path": path, "operation": operation, "remote_address": remote},
    }


@pytest.mark.parametrize(
    ("entry", "config", "expected"),
    [
        pytest.param(
            build_response(UNSEAL_PATH), CONFIG, [], id="unseal from allowed source"
        ),
        pytest.param(
            build_response(
                "transit-unseal/keys/meta-platform-vault-downstream", operation="read"
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
                "sys/policies/acl/meta-platform-x",
                operation="create",
                error="1 error occurred: permission denied",
            ),
            CONFIG,
            ["denied policy or role write"],
            id="denied policy write",
        ),
        pytest.param(
            build_response(
                "auth/approle/role/meta-platform-x", error="permission denied"
            ),
            CONFIG,
            ["denied policy or role write"],
            id="denied role write",
        ),
        pytest.param(
            build_response(
                "sys/policies/acl/meta-platform-x",
                operation="read",
                error="permission denied",
            ),
            CONFIG,
            [],
            id="denied policy read",
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
    assert json.loads(state_file.read_text(encoding="utf-8")) == {
        "inode": os.stat(log).st_ino,
        "offset": log.stat().st_size,
    }

    run_main(monkeypatch, config_path)
    assert len(captured_alerts) == 1
