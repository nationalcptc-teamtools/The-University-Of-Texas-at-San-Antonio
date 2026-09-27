#!/usr/bin/env bash
# Run the fixed local installer and reviewed NetExec configuration repair.
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ "${1:-}" == "nxc-fix" ]]; then
    shift
    exec "$root_dir/nxc-fix.sh" "$@"
fi
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    /usr/bin/python3 "$root_dir/team_env_setup.py" "$@"
    printf '\nAdditional command:\n  nxc-fix [--auto|--legacy|--ce] [--user USER] [config-file]\n'
    exit 0
fi
exec /usr/bin/python3 "$root_dir/team_env_setup.py" "$@"
