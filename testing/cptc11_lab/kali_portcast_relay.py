"""Install and verify one exact Kali SSH forwarding boundary.

This operator-only helper changes only its dedicated ``sshd_config.d`` file on
the pinned CPTC11 Kali VM. It has no target, command, path, or policy input.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, TextIO

from .transport import (
    CPTC11_KALI_OPENSSH_PINSET,
    CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,
    KALI_PORTCAST_RELAY_POLICY_ARGV,
    LabSession,
    PreflightRejected,
    RunDirectory,
    parse_portcast_relay_policy,
)


RELAY_FRAGMENT_PATH = "/etc/ssh/sshd_config.d/70-harbinger-portcast.conf"
RELAY_BACKUP_PATH = "/var/backups/harbinger/70-harbinger-portcast.conf.pre-harbinger"
RELAY_ABSENT_MARKER_PATH = RELAY_BACKUP_PATH + ".absent"
RELAY_FRAGMENT = """Match Address 10.0.254.253
    PermitOpen 10.0.1.30:8096
    PermitListen none
    AllowTcpForwarding local
    X11Forwarding no
    PermitTunnel no
    GatewayPorts no
Match all
"""
RELAY_FRAGMENT_SHA256 = "0bbce970017f0aba4c44de79acd8426f95c9b3b6a105a116f24a3902d6462a3d"
_SYSTEMD_USERDB_FRAGMENT = "/etc/ssh/sshd_config.d/20-systemd-userdb.conf"
_SYSTEMD_USERDB_FRAGMENT_SHA256 = "d9accafa92bfec25801224015ac1ffbf52bb1649a656779ada3cd502da7feba3"
_SSH_SERVICE_UNIT = "/usr/lib/systemd/system/ssh.service"
_SSH_SERVICE_UNIT_SHA256 = "1e3c11483cc51a6c7aa3ab92affa43a313cab65e9721a64ce7720404cf6de1c8"


KALI_PORTCAST_RELAY_APPLY_ARGV: tuple[str, ...] = (
    "/bin/bash",
    "-ceu",
    f"""set -o pipefail
export LC_ALL=C
umask 077
fragment={RELAY_FRAGMENT_PATH!r}
backup={RELAY_BACKUP_PATH!r}
absent={RELAY_ABSENT_MARKER_PATH!r}
backup_dir='/var/backups/harbinger'
candidate=''
validation=''
changed=0

assert_runtime_files() {{
  local path digest fragment_count=0 userdb_count=0 relay_count=0 unit_path dropin_paths
  for path in /etc/ssh/sshd_config.d/*.conf; do
    test -e "$path" || continue
    test -f "$path" -a -r "$path"
    digest=$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{{print $1}}')
    case "$path" in
      {_SYSTEMD_USERDB_FRAGMENT!r})
        test "$digest" = {_SYSTEMD_USERDB_FRAGMENT_SHA256!r}
        userdb_count=$((userdb_count + 1))
        ;;
      {RELAY_FRAGMENT_PATH!r})
        test "$digest" = {RELAY_FRAGMENT_SHA256!r}
        relay_count=$((relay_count + 1))
        ;;
      *) return 72 ;;
    esac
    fragment_count=$((fragment_count + 1))
  done
  test "$userdb_count" -eq 1
  test "$relay_count" -le 1
  test "$fragment_count" -eq $((userdb_count + relay_count))
  unit_path=$(/usr/bin/systemctl show --property=FragmentPath --value ssh.service)
  test "$unit_path" = {_SSH_SERVICE_UNIT!r}
  test "$(/usr/bin/sha256sum -- "$unit_path" | /usr/bin/awk '{{print $1}}')" = {_SSH_SERVICE_UNIT_SHA256!r}
  dropin_paths=$(/usr/bin/systemctl show --property=DropInPaths --value ssh.service)
  test -z "$dropin_paths"
}}

policy_value() {{
  local config="$1" key="$2" effective
  effective=$(/usr/sbin/sshd -T -f "$config" -C 'user=root,host=10.0.254.201,addr=10.0.254.253,laddr=10.0.254.201,lport=22')
  printf '%s\n' "$effective" | /usr/bin/awk -v key="$key" '
    $1 == key {{ count += 1; $1 = ""; sub(/^ /, ""); value = $0 }}
    END {{ if (count != 1) exit 1; print value }}
  '
}}

verify_policy() {{
  local config="$1"
  test "$(policy_value "$config" permitopen)" = '10.0.1.30:8096'
  test "$(policy_value "$config" permitlisten)" = 'none'
  test "$(policy_value "$config" allowtcpforwarding)" = 'local'
  test "$(policy_value "$config" x11forwarding)" = 'no'
  test "$(policy_value "$config" permittunnel)" = 'no'
  test "$(policy_value "$config" gatewayports)" = 'no'
}}

rollback() {{
  if test -f "$absent"; then
    /usr/bin/rm -f -- "$fragment"
  else
    return 1
  fi
  /usr/bin/sync -f /etc/ssh/sshd_config.d
  /usr/sbin/sshd -t
  verify_policy /etc/ssh/sshd_config || true
  /usr/bin/systemctl reload ssh.service
}}

cleanup() {{
  local status=$?
  trap - EXIT
  set +e
  test -z "$candidate" || /usr/bin/rm -f -- "$candidate"
  test -z "$validation" || /usr/bin/rm -f -- "$validation"
  if test "$status" -ne 0 && test "$changed" -eq 1; then
    rollback || status=78
  fi
  exit "$status"
}}
trap cleanup EXIT

test "$EUID" -eq 0
test "$(/bin/hostname)" = 'cptc11-export-t1-vdi-kali01'
test "$(/usr/bin/sha256sum -- /etc/machine-id | /usr/bin/awk '{{print $1}}')" = '243500f5ca4683df06f22561458dd7e63f7b10aa1ef5a6660cf42983285f3915'
test "$(/usr/bin/dpkg-query -W -f='${{Version}}' openssh-server)" = '1:10.2p1-5'
test "$(/usr/bin/sha256sum -- /usr/sbin/sshd | /usr/bin/awk '{{print $1}}')" = 'e0f0341fe7b33a0802fc023b58c0c39d7486c13b5e3cc18813bf8bc2d48265b2'
test "$(/usr/bin/sha256sum -- /etc/ssh/sshd_config | /usr/bin/awk '{{print $1}}')" = '1df28dc31327abbbdae794aa4ac46b25b2efff10658a1c46ee9e4f53e46def24'
assert_runtime_files
test -d /etc/ssh/sshd_config.d
test ! -L /etc/ssh/sshd_config.d
test ! -L "$fragment"
test ! -L "$backup_dir"
test ! -L "$backup"
test ! -L "$absent"

if test ! -e "$backup_dir"; then
  /usr/bin/mkdir -m 0700 -- "$backup_dir"
fi
test -d "$backup_dir"
test -O "$backup_dir"
/usr/bin/chmod 0700 -- "$backup_dir"

candidate=$(/usr/bin/mktemp -p /etc/ssh/sshd_config.d .70-harbinger-portcast.XXXXXXXX)
/usr/bin/chmod 0600 -- "$candidate"
printf '%s' ${RELAY_FRAGMENT!r} > "$candidate"
/usr/bin/sync -f "$candidate"

validation=$(/usr/bin/mktemp -p /run harbinger-sshd-validation.XXXXXXXX)
/usr/bin/chmod 0600 -- "$validation"
{{
  printf 'Include %s\n' "$candidate"
  while IFS= read -r line || test -n "$line"; do printf '%s\n' "$line"; done < /etc/ssh/sshd_config
}} > "$validation"
/usr/bin/sync -f "$validation"
/usr/sbin/sshd -t -f "$validation"
verify_policy "$validation"

candidate_sha=$(/usr/bin/sha256sum -- "$candidate" | /usr/bin/awk '{{print $1}}')
if test -f "$fragment" && test "$(/usr/bin/sha256sum -- "$fragment" | /usr/bin/awk '{{print $1}}')" = "$candidate_sha"; then
  /usr/sbin/sshd -t
  verify_policy /etc/ssh/sshd_config
  printf '%s\n' HARBINGER_PORTCAST_RELAY_UNCHANGED_V1
  exit 0
fi

if test -e "$fragment" || test -e "$backup" || test -e "$absent"; then
  exit 76
fi
: > "$absent"
/usr/bin/chmod 0600 -- "$absent"
/usr/bin/sync -f "$backup_dir"

/usr/bin/mv -- "$candidate" "$fragment"
candidate=''
changed=1
/usr/bin/sync -f /etc/ssh/sshd_config.d
assert_runtime_files
/usr/sbin/sshd -t
verify_policy /etc/ssh/sshd_config
/usr/bin/systemctl reload ssh.service
verify_policy /etc/ssh/sshd_config
printf '%s\n' HARBINGER_PORTCAST_RELAY_APPLIED_V1
changed=0
""",
)


KALI_PORTCAST_RELAY_ROLLBACK_ARGV: tuple[str, ...] = (
    "/bin/bash",
    "-ceu",
    f"""set -o pipefail
export LC_ALL=C
umask 077
fragment={RELAY_FRAGMENT_PATH!r}
backup={RELAY_BACKUP_PATH!r}
absent={RELAY_ABSENT_MARKER_PATH!r}
assert_pre_runtime() {{
  local path digest count=0 unit_path dropin_paths
  for path in /etc/ssh/sshd_config.d/*.conf; do
    test -e "$path" || continue
    test "$path" = {_SYSTEMD_USERDB_FRAGMENT!r}
    test -f "$path" -a -r "$path"
    digest=$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{{print $1}}')
    test "$digest" = {_SYSTEMD_USERDB_FRAGMENT_SHA256!r}
    count=$((count + 1))
  done
  test "$count" -eq 1
  unit_path=$(/usr/bin/systemctl show --property=FragmentPath --value ssh.service)
  test "$unit_path" = {_SSH_SERVICE_UNIT!r}
  test "$(/usr/bin/sha256sum -- "$unit_path" | /usr/bin/awk '{{print $1}}')" = {_SSH_SERVICE_UNIT_SHA256!r}
  dropin_paths=$(/usr/bin/systemctl show --property=DropInPaths --value ssh.service)
  test -z "$dropin_paths"
}}
policy_value() {{
  local key="$1" effective
  effective=$(/usr/sbin/sshd -T -C 'user=root,host=10.0.254.201,addr=10.0.254.253,laddr=10.0.254.201,lport=22')
  printf '%s\n' "$effective" | /usr/bin/awk -v key="$key" '
    $1 == key {{ count += 1; $1 = ""; sub(/^ /, ""); value = $0 }}
    END {{ if (count != 1) exit 1; print value }}
  '
}}
verify_pre_policy() {{
  test "$(policy_value permitopen)" = any
  test "$(policy_value permitlisten)" = any
  test "$(policy_value allowtcpforwarding)" = yes
  test "$(policy_value x11forwarding)" = yes
  test "$(policy_value permittunnel)" = no
  test "$(policy_value gatewayports)" = no
}}
test "$EUID" -eq 0
test "$(/bin/hostname)" = 'cptc11-export-t1-vdi-kali01'
test "$(/usr/bin/sha256sum -- /etc/machine-id | /usr/bin/awk '{{print $1}}')" = '243500f5ca4683df06f22561458dd7e63f7b10aa1ef5a6660cf42983285f3915'
test "$(/usr/bin/sha256sum -- /usr/sbin/sshd | /usr/bin/awk '{{print $1}}')" = 'e0f0341fe7b33a0802fc023b58c0c39d7486c13b5e3cc18813bf8bc2d48265b2'
test "$(/usr/bin/sha256sum -- /etc/ssh/sshd_config | /usr/bin/awk '{{print $1}}')" = '1df28dc31327abbbdae794aa4ac46b25b2efff10658a1c46ee9e4f53e46def24'
test ! -L "$fragment"
test ! -e "$backup"
if test -f "$fragment"; then
  test -f "$absent"
  test "$(/usr/bin/sha256sum -- "$fragment" | /usr/bin/awk '{{print $1}}')" = {RELAY_FRAGMENT_SHA256!r}
  /usr/bin/rm -f -- "$fragment"
  recovery_marker=HARBINGER_PORTCAST_RELAY_ROLLED_BACK_V1
elif test -f "$absent"; then
  recovery_marker=HARBINGER_PORTCAST_RELAY_ALREADY_ROLLED_BACK_V1
else
  printf '%s\n' HARBINGER_PORTCAST_RELAY_ROLLBACK_NOT_NEEDED_V1
  exit 0
fi
/usr/bin/sync -f /etc/ssh/sshd_config.d
assert_pre_runtime
/usr/sbin/sshd -t
/usr/bin/systemctl reload ssh.service
assert_pre_runtime
verify_pre_policy
test ! -e "$fragment"
if test -f "$absent"; then
  /usr/bin/rm -f -- "$absent"
  /usr/bin/sync -f /var/backups/harbinger
fi
printf '%s\n' "$recovery_marker"
""",
)


def relay_plan() -> dict[str, str]:
    """Return the complete proposed change without opening a connection."""

    return {
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


def parse_relay_apply_marker(raw: bytes) -> str:
    """Accept only an exact success marker from the fixed apply script."""

    if raw == b"HARBINGER_PORTCAST_RELAY_APPLIED_V1\n":
        return "applied"
    if raw == b"HARBINGER_PORTCAST_RELAY_UNCHANGED_V1\n":
        return "unchanged"
    raise PreflightRejected("Kali relay apply did not return an exact success marker")


def parse_relay_rollback_marker(raw: bytes) -> str:
    """Accept only a fixed recovery result from the rollback script."""

    markers = {
        b"HARBINGER_PORTCAST_RELAY_ROLLED_BACK_V1\n": "rolled_back",
        b"HARBINGER_PORTCAST_RELAY_ALREADY_ROLLED_BACK_V1\n": "already_rolled_back",
        b"HARBINGER_PORTCAST_RELAY_ROLLBACK_NOT_NEEDED_V1\n": "not_needed",
    }
    try:
        return markers[raw]
    except KeyError:
        raise PreflightRejected(
            "Kali relay rollback did not return an exact recovery marker"
        ) from None


def _require_identity(session: Any, *allowed: Any):
    manifest = session.inspect_openssh_runtime()
    if manifest not in allowed:
        raise PreflightRejected("Kali relay host identity differs from the reviewed pinset")
    return manifest


def verify_relay(session: Any) -> bool:
    """Verify exact host identity and effective policy without target traffic."""

    _require_identity(session, CPTC11_KALI_OPENSSH_PINSET)
    output = session._execute_kali(  # noqa: SLF001 - internal operator helper.
        KALI_PORTCAST_RELAY_POLICY_ARGV,
        "openssh-policy",
    )
    return parse_portcast_relay_policy(output)


def apply_relay(session: Any) -> str:
    """Apply the fixed fragment, then re-pin identity and effective policy."""

    before = _require_identity(
        session,
        CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,
        CPTC11_KALI_OPENSSH_PINSET,
    )
    try:
        output = session._execute_kali(  # noqa: SLF001 - internal operator helper.
            KALI_PORTCAST_RELAY_APPLY_ARGV,
            "openssh-relay-apply",
        )
        result = parse_relay_apply_marker(output)
        if not verify_relay(session):
            raise PreflightRejected("Kali relay policy verification failed")
        return result
    except BaseException:
        if before == CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET:
            parse_relay_rollback_marker(
                session._execute_kali(  # noqa: SLF001 - fixed recovery operation.
                    KALI_PORTCAST_RELAY_ROLLBACK_ARGV,
                    "openssh-relay-rollback",
                )
            )
        raise


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    session_factory: Any = LabSession,
) -> int:
    """Run the fixed plan, apply, or verify operation."""

    parser = argparse.ArgumentParser(prog="harbinger-kali-portcast-relay")
    parser.add_argument("command", choices=("plan", "apply", "verify"))
    parser.add_argument(
        "--run-root",
        type=Path,
        default=Path("~/.local/state/harbinger/cptc11").expanduser(),
    )
    args = parser.parse_args(argv)
    destination = stdout or sys.stdout
    if args.command == "plan":
        print(json.dumps(relay_plan(), sort_keys=True), file=destination)
        return 0

    run = RunDirectory.create(args.run_root)
    state = "failed"
    detail = ""
    try:
        with session_factory(run_directory=run) as session:
            detail = apply_relay(session) if args.command == "apply" else "verified" if verify_relay(session) else "failed"
        state = "passed"
        run.transcript.emit("relay.finish", phase=args.command, status=state)
        return_code = 0
    except BaseException as error:
        run.transcript.emit(
            "relay.finish",
            phase=args.command,
            status="failed",
            reason=type(error).__name__,
        )
        return_code = 1
    finally:
        run.close()
    print(
        json.dumps(
            {
                "command": args.command,
                "detail": detail,
                "run_directory": str(run.path),
                "status": state,
            },
            sort_keys=True,
        ),
        file=destination,
    )
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
