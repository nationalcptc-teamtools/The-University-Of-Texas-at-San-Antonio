from __future__ import annotations

import io
import hashlib
import json
from dataclasses import replace
import subprocess

import pytest

from testing.cptc11_lab.kali_portcast_relay import (
    KALI_PORTCAST_RELAY_APPLY_ARGV,
    KALI_PORTCAST_RELAY_ROLLBACK_ARGV,
    RELAY_ABSENT_MARKER_PATH,
    RELAY_BACKUP_PATH,
    RELAY_FRAGMENT,
    RELAY_FRAGMENT_SHA256,
    RELAY_FRAGMENT_PATH,
    apply_relay,
    main,
    parse_relay_apply_marker,
    parse_relay_rollback_marker,
    relay_plan,
    verify_relay,
)
from testing.cptc11_lab.transport import (
    CPTC11_KALI_OPENSSH_PINSET,
    CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,
    KALI_OPENSSH_INVENTORY_ARGV,
    KALI_PORTCAST_RELAY_POLICY_ARGV,
    PreflightRejected,
    TransportError,
)


class FakeSession:
    def __init__(
        self, *, manifest=CPTC11_KALI_OPENSSH_PINSET, manifests=None,
        apply_marker=None, apply_error=False,
    ):
        self.manifest = manifest
        self.manifests = list(manifests or ())
        self.apply_marker = apply_marker or b"HARBINGER_PORTCAST_RELAY_APPLIED_V1\n"
        self.apply_error = apply_error
        self.commands: list[tuple[tuple[str, ...], str]] = []
        self.inventory_calls = 0

    def inspect_openssh_runtime(self):
        self.inventory_calls += 1
        self.commands.append((KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory"))
        if self.manifests:
            self.manifest = self.manifests.pop(0)
        return self.manifest

    def _execute_kali(self, argv, label):
        self.commands.append((argv, label))
        if argv == KALI_PORTCAST_RELAY_APPLY_ARGV:
            if self.apply_error:
                raise TransportError("synthetic internal rollback reload failure")
            return self.apply_marker
        if argv == KALI_PORTCAST_RELAY_ROLLBACK_ARGV:
            return b"HARBINGER_PORTCAST_RELAY_ROLLED_BACK_V1\n"
        if argv == KALI_PORTCAST_RELAY_POLICY_ARGV:
            return b"HARBINGER_PORTCAST_RELAY_POLICY_V1\n"
        raise AssertionError("unexpected synthetic command")


def test_plan_is_exact_and_side_effect_free():
    plan = relay_plan()
    assert plan == {
        "schema": "harbinger-kali-portcast-relay-plan-v1",
        "source_address": "10.0.254.253",
        "destination": "10.0.1.30:8096",
        "fragment_path": RELAY_FRAGMENT_PATH,
        "fragment": RELAY_FRAGMENT,
        "backup_path": RELAY_BACKUP_PATH,
        "absent_marker_path": RELAY_ABSENT_MARKER_PATH,
        "validation_command": "/usr/sbin/sshd -t",
        "effective_policy_command": "/usr/sbin/sshd -T -C user=root,host=10.0.254.201,addr=10.0.254.253,laddr=10.0.254.201,lport=22",
        "reload_command": "/usr/bin/systemctl reload ssh.service",
    }

    output = io.StringIO()
    assert main(["plan"], stdout=output) == 0
    assert json.loads(output.getvalue()) == plan


def test_apply_script_is_fixed_rolls_back_and_has_no_scanner_or_target_input():
    assert KALI_PORTCAST_RELAY_APPLY_ARGV[:2] == ("/bin/bash", "-ceu")
    script = KALI_PORTCAST_RELAY_APPLY_ARGV[2]
    assert all(line in script for line in RELAY_FRAGMENT.splitlines())
    assert RELAY_FRAGMENT_PATH in script
    assert RELAY_BACKUP_PATH in script
    assert RELAY_ABSENT_MARKER_PATH in script
    assert "trap cleanup EXIT" in script
    assert "rollback" in script
    assert "/usr/sbin/sshd -t" in script
    assert "/usr/bin/systemctl reload ssh.service" in script
    assert "10.0.254.253" in script
    assert "10.0.1.30:8096" in script
    assert not any(token in script.lower() for token in ("curl", "wget", "nmap", "/dev/tcp"))
    assert RELAY_FRAGMENT_SHA256 == hashlib.sha256(RELAY_FRAGMENT.encode("ascii")).hexdigest()
    assert "/etc/ssh/sshd_config.d/20-systemd-userdb.conf" in script
    assert "/usr/lib/systemd/system/ssh.service" in script
    assert "DropInPaths" in script


def test_apply_transaction_remains_active_through_every_post_move_step():
    script = KALI_PORTCAST_RELAY_APPLY_ARGV[2]
    ordered = (
        '/usr/bin/mv -- "$candidate" "$fragment"',
        "changed=1",
        "/usr/bin/sync -f /etc/ssh/sshd_config.d",
        "assert_runtime_files",
        "/usr/sbin/sshd -t",
        "verify_policy /etc/ssh/sshd_config",
        "/usr/bin/systemctl reload ssh.service",
        "verify_policy /etc/ssh/sshd_config",
        "HARBINGER_PORTCAST_RELAY_APPLIED_V1",
        "changed=0",
    )
    cursor = 0
    positions = []
    for value in ordered:
        cursor = script.index(value, cursor)
        positions.append(cursor)
        cursor += len(value)
    assert positions == sorted(positions)
    assert "if test \"$status\" -ne 0 && test \"$changed\" -eq 1" in script


def test_rollback_is_fixed_and_restores_only_the_dedicated_fragment():
    assert KALI_PORTCAST_RELAY_ROLLBACK_ARGV[:2] == ("/bin/bash", "-ceu")
    script = KALI_PORTCAST_RELAY_ROLLBACK_ARGV[2]
    assert RELAY_FRAGMENT_PATH in script
    assert RELAY_ABSENT_MARKER_PATH in script
    assert RELAY_FRAGMENT_SHA256 in script
    assert '/usr/bin/rm -f -- "$fragment"' in script
    assert "/usr/sbin/sshd -t" in script
    assert "/usr/bin/systemctl reload ssh.service" in script
    assert "assert_pre_runtime" in script
    assert "verify_pre_policy" in script
    assert RELAY_BACKUP_PATH in script
    assert not any(token in script.lower() for token in ("curl", "wget", "nmap", "/dev/tcp"))


def test_apply_script_shell_literal_renders_the_exact_fragment_bytes():
    script = KALI_PORTCAST_RELAY_APPLY_ARGV[2]
    line = next(line for line in script.splitlines() if line.startswith("printf '%s' $'"))
    command = line.removesuffix(' > "$candidate"')
    completed = subprocess.run(
        ["/bin/bash", "-ceu", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == RELAY_FRAGMENT.encode("ascii")
    assert completed.stderr == b""


def test_apply_is_identity_gated_then_rechecks_policy_and_is_repeatable():
    first = FakeSession(
        manifests=(
            CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,
            CPTC11_KALI_OPENSSH_PINSET,
        )
    )
    assert apply_relay(first) == "applied"
    assert first.commands == [
        (KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory"),
        (KALI_PORTCAST_RELAY_APPLY_ARGV, "openssh-relay-apply"),
        (KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory"),
        (KALI_PORTCAST_RELAY_POLICY_ARGV, "openssh-policy"),
    ]

    repeated = FakeSession(apply_marker=b"HARBINGER_PORTCAST_RELAY_UNCHANGED_V1\n")
    assert apply_relay(repeated) == "unchanged"
    assert repeated.commands == first.commands


def test_apply_rejects_identity_drift_before_mutation():
    changed = replace(CPTC11_KALI_OPENSSH_PINSET, machine_id_sha256="0" * 64)
    session = FakeSession(manifest=changed)
    with pytest.raises(PreflightRejected, match="identity"):
        apply_relay(session)
    assert session.commands == [(KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory")]


def test_apply_failure_from_reviewed_absent_state_invokes_fixed_rollback():
    session = FakeSession(
        manifests=(CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,),
        apply_marker=b"malformed\n",
    )
    with pytest.raises(PreflightRejected, match="exact success marker"):
        apply_relay(session)
    assert session.commands == [
        (KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory"),
        (KALI_PORTCAST_RELAY_APPLY_ARGV, "openssh-relay-apply"),
        (KALI_PORTCAST_RELAY_ROLLBACK_ARGV, "openssh-relay-rollback"),
    ]


def test_post_apply_identity_failure_from_absent_state_invokes_fixed_rollback():
    session = FakeSession(
        manifests=(
            CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,
            CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,
        )
    )
    with pytest.raises(PreflightRejected, match="identity"):
        apply_relay(session)
    assert session.commands == [
        (KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory"),
        (KALI_PORTCAST_RELAY_APPLY_ARGV, "openssh-relay-apply"),
        (KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory"),
        (KALI_PORTCAST_RELAY_ROLLBACK_ARGV, "openssh-relay-rollback"),
    ]


def test_internal_rollback_reload_failure_causes_parent_recovery_retry():
    session = FakeSession(
        manifests=(CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,),
        apply_error=True,
    )
    with pytest.raises(TransportError, match="internal rollback reload failure"):
        apply_relay(session)
    assert session.commands == [
        (KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory"),
        (KALI_PORTCAST_RELAY_APPLY_ARGV, "openssh-relay-apply"),
        (KALI_PORTCAST_RELAY_ROLLBACK_ARGV, "openssh-relay-rollback"),
    ]


def test_preexisting_unreviewed_fragment_is_refused_without_apply_or_rollback():
    changed_fragments = tuple(
        replace(pin, sha256="9" * 64)
        if pin.path == RELAY_FRAGMENT_PATH else pin
        for pin in CPTC11_KALI_OPENSSH_PINSET.sshd_fragments
    )
    session = FakeSession(
        manifest=replace(CPTC11_KALI_OPENSSH_PINSET, sshd_fragments=changed_fragments)
    )
    with pytest.raises(PreflightRejected, match="identity"):
        apply_relay(session)
    assert session.commands == [(KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory")]


def test_verify_is_metadata_only_and_requires_exact_marker():
    session = FakeSession()
    assert verify_relay(session) is True
    assert session.commands == [
        (KALI_OPENSSH_INVENTORY_ARGV, "openssh-inventory"),
        (KALI_PORTCAST_RELAY_POLICY_ARGV, "openssh-policy"),
    ]
    for raw in (b"", b"HARBINGER_PORTCAST_RELAY_APPLIED_V1", b"HARBINGER_PORTCAST_RELAY_APPLIED_V1\nextra\n"):
        with pytest.raises(PreflightRejected):
            parse_relay_apply_marker(raw)
    assert parse_relay_rollback_marker(
        b"HARBINGER_PORTCAST_RELAY_ROLLED_BACK_V1\n"
    ) == "rolled_back"
    with pytest.raises(PreflightRejected):
        parse_relay_rollback_marker(b"HARBINGER_PORTCAST_RELAY_ROLLED_BACK_V1")
