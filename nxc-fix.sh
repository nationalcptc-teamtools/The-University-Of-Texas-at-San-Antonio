#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 [--auto|--legacy|--ce] [config-file]" >&2
}

mode="auto"
case "${1:-}" in
    --auto|--legacy|--ce)
        mode="${1#--}"
        shift
        ;;
    -h|--help)
        usage
        exit 0
        ;;
esac

config_path="${1:-${NXC_CONFIG:-$HOME/.nxc/nxc.conf}}"
if [[ $# -gt 1 ]]; then
    usage
    exit 2
fi

if [[ ! -f "$config_path" ]]; then
    echo "NetExec config not found: $config_path" >&2
    exit 1
fi
if [[ -L "$config_path" ]]; then
    echo "Refusing a symlinked NetExec config: $config_path" >&2
    exit 1
fi

active_nxc="$(command -v nxc 2>/dev/null || true)"
active_python=""
if [[ -n "$active_nxc" ]]; then
    active_nxc="$(readlink -f -- "$active_nxc")"
    candidate_python="$(dirname -- "$active_nxc")/python"
    if [[ -x "$candidate_python" ]]; then
        active_python="$candidate_python"
    elif [[ -x "${candidate_python}3" ]]; then
        active_python="${candidate_python}3"
    fi
fi

has_distribution() {
    local distribution="$1"
    [[ -n "$active_python" ]] \
        && "$active_python" -c 'import importlib.metadata as m, sys; m.version(sys.argv[1])' \
            "$distribution" >/dev/null 2>&1
}

if [[ "$mode" == "auto" ]]; then
    if has_distribution "bloodhound-ce"; then
        mode="ce"
    elif has_distribution "bloodhound"; then
        mode="legacy"
    else
        echo "Could not identify a BloodHound collector in the active nxc environment." >&2
        exit 1
    fi
fi

if [[ "$mode" == "ce" ]] && ! has_distribution "bloodhound-ce"; then
    echo "The active nxc environment does not contain bloodhound-ce." >&2
    exit 1
fi
if [[ "$mode" == "legacy" ]] && ! has_distribution "bloodhound"; then
    echo "The active nxc environment does not contain the legacy bloodhound package." >&2
    exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_path="$(mktemp --tmpdir="$(dirname -- "$config_path")" "$(basename -- "$config_path").bak.${timestamp}.XXXXXX")"
cp -a -- "$config_path" "$backup_path"

python3 - "$config_path" "$mode" <<'PY'
import configparser
import os
import stat
import sys
import tempfile

path, mode = sys.argv[1:]
settings = {
    "legacy": ("True", "False"),
    "ce": ("False", "True"),
}

parser = configparser.ConfigParser(interpolation=None)
parser.optionxform = str
with open(path, encoding="utf-8") as handle:
    parser.read_file(handle)

for section in ("BloodHound", "BloodHound-CE"):
    if not parser.has_section(section):
        parser.add_section(section)

legacy_enabled, ce_enabled = settings[mode]
parser.set("BloodHound", "bh_enabled", legacy_enabled)
parser.set("BloodHound-CE", "bhce_enabled", ce_enabled)

original_mode = stat.S_IMODE(os.stat(path).st_mode)
directory = os.path.dirname(os.path.abspath(path))
fd, temporary = tempfile.mkstemp(prefix=".nxc.conf.", dir=directory, text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        parser.write(handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, original_mode)
    os.replace(temporary, path)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY

legacy_value="$(awk -F= '
    /^\[BloodHound\]$/ { active=1; next }
    /^\[/ { active=0 }
    active && $1 ~ /^[[:space:]]*bh_enabled[[:space:]]*$/ {
        gsub(/[[:space:]]/, "", $2); print $2
    }
' "$config_path")"
ce_value="$(awk -F= '
    /^\[BloodHound-CE\]$/ { active=1; next }
    /^\[/ { active=0 }
    active && $1 ~ /^[[:space:]]*bhce_enabled[[:space:]]*$/ {
        gsub(/[[:space:]]/, "", $2); print $2
    }
' "$config_path")"

case "$mode" in
    legacy)
        [[ "$legacy_value" == "True" && "$ce_value" == "False" ]]
        ;;
    ce)
        [[ "$legacy_value" == "False" && "$ce_value" == "True" ]]
        ;;
esac

echo "NetExec BloodHound mode: $mode"
echo "Active nxc: $active_nxc"
echo "bh_enabled=$legacy_value"
echo "bhce_enabled=$ce_value"
echo "Backup: $backup_path"
