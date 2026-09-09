#!/usr/bin/env bash
# Select one BloodHound collector in an existing NetExec configuration.
# This script never runs nxc, sudo, or network commands.
set -euo pipefail

usage() {
    echo "Usage: $0 [--auto|--legacy|--ce] [--user USER] [config-file]" >&2
}

mode="auto"
target_user=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto|--legacy|--ce) mode="${1#--}"; shift ;;
        --user) [[ $# -ge 2 ]] || { usage; exit 2; }; target_user="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --*) usage; exit 2 ;;
        *) break ;;
    esac
done
[[ $# -le 1 ]] || { usage; exit 2; }

fail() { echo "nxc-fix: $1" >&2; exit 1; }

if [[ -z "$target_user" ]]; then
    if [[ $EUID -eq 0 ]]; then
        [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] || fail "Root use needs a non-root SUDO_USER or explicit --user"
        target_user="$SUDO_USER"
    else
        target_user="$(id -un)"
    fi
fi

account="$(getent passwd "$target_user" || true)"
[[ -n "$account" ]] || fail "Cannot resolve the intended user"
IFS=: read -r _ _ target_uid target_gid _ target_home _ <<<"$account"
[[ "$target_uid" =~ ^[0-9]+$ && "$target_gid" =~ ^[0-9]+$ && -d "$target_home" ]] || fail "Intended user has an unsafe account record"
if [[ $EUID -ne 0 && "$(id -u)" != "$target_uid" ]]; then
    fail "Only root may edit another user's configuration"
fi

config_path="${1:-${NXC_CONFIG:-$target_home/.nxc/nxc.conf}}"
[[ -f "$config_path" && ! -L "$config_path" ]] || fail "NetExec config is missing or is a symlink"
config_path="$(realpath -e -- "$config_path")" || fail "Cannot resolve NetExec config"
config_dir="$(dirname -- "$config_path")"
[[ ! -L "$config_dir" && -d "$config_dir" ]] || fail "NetExec config directory is unsafe"

config_stat="$(stat -Lc '%u %a %F' -- "$config_path")" || fail "Cannot inspect NetExec config"
dir_stat="$(stat -Lc '%u %a %F' -- "$config_dir")" || fail "Cannot inspect NetExec config directory"
read -r config_uid config_mode config_kind <<<"$config_stat"
read -r dir_uid dir_mode dir_kind <<<"$dir_stat"
[[ "$config_uid" == "$target_uid" && "$config_kind" == "regular file" ]] || fail "NetExec config owner or type is unsafe"
[[ "$dir_uid" == "$target_uid" && "$dir_kind" == "directory" ]] || fail "NetExec config directory owner or type is unsafe"
(( (8#$config_mode & 8#077) == 0 && (8#$dir_mode & 8#022) == 0 )) || fail "NetExec config permissions are unsafe"

active_nxc="${NXC_BIN:-$(command -v nxc 2>/dev/null || true)}"
[[ -n "$active_nxc" && -x "$active_nxc" ]] || fail "Cannot find an executable nxc path"
active_nxc="$(realpath -e -- "$active_nxc")" || fail "Cannot resolve nxc path"
active_dir="$(dirname -- "$active_nxc")"
active_dir_stat="$(stat -Lc '%u %a %F' -- "$active_dir")" || fail "Cannot inspect the NetExec environment"
read -r active_dir_uid active_dir_mode active_dir_kind <<<"$active_dir_stat"
[[ "$active_dir_kind" == "directory" && ( "$active_dir_uid" == "0" || "$active_dir_uid" == "$target_uid" ) ]] || fail "NetExec environment owner or type is unsafe"
(( (8#$active_dir_mode & 8#022) == 0 )) || fail "NetExec environment permissions are unsafe"
active_python=""
for candidate in "$active_dir/python" "$active_dir/python3"; do
    [[ -f "$candidate" && -x "$candidate" ]] && { active_python="$candidate"; break; }
done
[[ -n "$active_python" ]] || fail "Cannot find the Python executable next to nxc"

has_distribution() {
    "$active_python" -c 'import importlib.metadata as m,sys; m.version(sys.argv[1])' "$1" >/dev/null 2>&1
}
distribution_version() {
    "$active_python" -c 'import importlib.metadata as m,sys; print(m.version(sys.argv[1]))' "$1" 2>/dev/null
}
has_distribution "netexec" || fail "The selected nxc path is not paired with a NetExec Python distribution"
nxc_version="$(distribution_version netexec)" || fail "Cannot read the NetExec version"
[[ "$nxc_version" =~ ^[0-9A-Za-z.+:~-]{1,80}$ ]] || fail "NetExec reported an unsafe version value"
if [[ "$mode" == "auto" ]]; then
    if has_distribution "bloodhound-ce"; then
        mode="ce"
    elif has_distribution "bloodhound"; then
        mode="legacy"
    else
        fail "No supported BloodHound collector is installed beside nxc"
    fi
fi
if [[ "$mode" == "ce" ]] && ! has_distribution "bloodhound-ce"; then fail "bloodhound-ce is unavailable"; fi
if [[ "$mode" == "legacy" ]] && ! has_distribution "bloodhound"; then fail "legacy bloodhound is unavailable"; fi

result="$(python3 - "$config_path" "$config_dir" "$target_uid" "$target_gid" "$mode" <<'PY'
import configparser
import os
import re
import stat
import sys
import tempfile

path, directory, uid, gid, mode = sys.argv[1:]
uid, gid = int(uid), int(gid)
settings = {"legacy": ("True", "False"), "ce": ("False", "True")}
try:
    original = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(original.st_mode) or original.st_uid != uid:
        raise ValueError("unsafe configuration file")
    legacy, ce = settings[mode]
    with open(path, "rb") as handle:
        old = handle.read()
    text = old.decode("utf-8")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(text)

    def set_flag(source, section, key, value):
        lines = source.splitlines(keepends=True)
        section_start = None
        section_end = len(lines)
        section_pattern = re.compile(r"^\s*\[([^]]+)]")
        for index, line in enumerate(lines):
            match = section_pattern.match(line)
            if not match:
                continue
            if section_start is not None:
                section_end = index
                break
            if match.group(1) == section:
                section_start = index
        newline = "\r\n" if "\r\n" in source else "\n"
        if section_start is None:
            separator = "" if not source or source.endswith(("\n", "\r")) else newline
            if source and not source.endswith(newline * 2):
                separator += newline
            return source + separator + "[" + section + "]" + newline + key + " = " + value + newline
        option = re.compile(r"^(\s*" + re.escape(key) + r"\s*[=:]\s*)([^#;\r\n]*?)(\s*(?:[#;].*)?)(\r?\n)?$", re.IGNORECASE)
        for index in range(section_start + 1, section_end):
            match = option.match(lines[index])
            if match:
                lines[index] = match.group(1) + value + match.group(3) + (match.group(4) or "")
                return "".join(lines)
        insertion = key + " = " + value + newline
        if section_end and not lines[section_end - 1].endswith(("\n", "\r")):
            insertion = newline + insertion
        lines.insert(section_end, insertion)
        return "".join(lines)

    text = set_flag(text, "BloodHound", "bh_enabled", legacy)
    text = set_flag(text, "BloodHound-CE", "bhce_enabled", ce)
    rendered = text.encode("utf-8")
    if rendered == old:
        print("unchanged")
        raise SystemExit(0)
    backup = None
    for number in range(128):
        suffix = ".bak." + os.urandom(8).hex() + ("." + str(number) if number else "")
        candidate = path + suffix
        try:
            backup_fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            backup = candidate
            break
        except FileExistsError:
            continue
    if backup is None:
        raise ValueError("cannot reserve a unique backup")
    replaced = False
    try:
        with os.fdopen(backup_fd, "wb") as handle:
            os.fchown(handle.fileno(), uid, gid)
            handle.write(old)
            handle.flush(); os.fsync(handle.fileno())
        temporary = None
        fd, temporary = tempfile.mkstemp(prefix=".nxc.conf.", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                os.fchown(handle.fileno(), uid, gid)
                handle.write(rendered); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, path)
            replaced = True
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        finally:
            if temporary and os.path.exists(temporary): os.unlink(temporary)
    except Exception:
        if not replaced and backup and os.path.exists(backup): os.unlink(backup)
        raise
    print("changed")
except (OSError, UnicodeError, configparser.Error, ValueError):
    print("failed", file=sys.stderr)
    raise SystemExit(2)
PY
)" || fail "Configuration update failed"

echo "NetExec BloodHound mode: $mode"
echo "NetExec version: $nxc_version"
echo "Configuration update: $result"
