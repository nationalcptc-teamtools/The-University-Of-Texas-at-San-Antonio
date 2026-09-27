#!/usr/bin/env bash
set -euo pipefail

SHARE_NAME=cptc-test
SHARE_DIR=/srv/cptc-samba-test
STATE_DIR=/var/lib/cptc-samba-test
MARKER=$STATE_DIR/managed
SMB_CONF=/etc/samba/smb.conf

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

[[ $# -eq 0 ]] || die "Usage: sudo $0"
[[ $EUID -eq 0 ]] || die "Run this script with sudo."

if ! command -v smbd >/dev/null 2>&1 || ! command -v testparm >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 || die "apt-get is required to install Samba."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y samba
fi
[[ -f $SMB_CONF && ! -L $SMB_CONF ]] || die "Expected a regular Samba config at $SMB_CONF."
getent passwd nobody >/dev/null || die "The Samba guest account 'nobody' is missing."
guest_group=$(id -gn nobody)

# A marker outside the share distinguishes previous runs from unrelated data.
if [[ -e $STATE_DIR || -L $STATE_DIR ]]; then
  [[ -d $STATE_DIR && ! -L $STATE_DIR ]] || die "$STATE_DIR is not a regular directory."
  [[ $(stat -c '%u:%a' "$STATE_DIR") == 0:700 ]] || die "$STATE_DIR must be owned by root with mode 0700."
fi
if [[ -e $MARKER || -L $MARKER ]]; then
  if [[ ! -f $MARKER || -L $MARKER ]] || ! cmp -s "$MARKER" <(printf 'cptc-samba-test\n'); then
    die "Unexpected marker at $MARKER."
  fi
  [[ $(stat -c '%u:%a' "$MARKER") == 0:600 ]] || die "$MARKER must be owned by root with mode 0600."
fi
first_run=1
if [[ -e $SHARE_DIR || -L $SHARE_DIR ]]; then
  [[ -d $SHARE_DIR && ! -L $SHARE_DIR ]] || die "$SHARE_DIR is not a regular directory."
  [[ -f $MARKER && ! -L $MARKER ]] || die "$SHARE_DIR exists but is not managed by this script."
  first_run=0
fi
if (( ! first_run )); then
  [[ -d $SHARE_DIR/test && ! -L $SHARE_DIR/test ]] || die "$SHARE_DIR/test is not a regular directory."
  for file in "$SHARE_DIR/test.txt" "$SHARE_DIR/test/test.txt"; do
    [[ -f $file && ! -L $file ]] || die "$file is missing or not a regular file."
  done
fi

candidate=$(mktemp "${SMB_CONF}.cptc-test.XXXXXXXX")
staging_dir=
cleanup() {
  rm -f "$candidate"
  if [[ -n $staging_dir && -d $staging_dir && ! -L $staging_dir ]]; then
    rm -f -- "$staging_dir/test.txt" "$staging_dir/test/test.txt"
    rmdir -- "$staging_dir/test" "$staging_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT
python3 - "$SMB_CONF" "$candidate" <<'PY'
import pathlib
import re
import sys

source, destination = map(pathlib.Path, sys.argv[1:])
config = source.read_text()
if re.search(r'(?im)^\s*include\s*=', config):
    sys.exit('Samba include directives need manual review; no config changed.')
begin = '# BEGIN CPTC TEST SHARE'
end = '# END CPTC TEST SHARE'
share_block = '''# BEGIN CPTC TEST SHARE
[cptc-test]
    path = /srv/cptc-samba-test
    browseable = yes
    guest ok = yes
    guest only = yes
    read only = no
    force user = nobody
    create mask = 0700
    force create mode = 0600
    directory mask = 0700
    force directory mode = 0700
    follow symlinks = no
# END CPTC TEST SHARE
'''
block = re.compile(r'(?ms)^' + re.escape(begin) + r'\n.*?^' + re.escape(end) + r'\n?')
if begin in config or end in config:
    matches = list(block.finditer(config))
    if len(matches) != 1 or config.count(begin) != 1 or config.count(end) != 1:
        sys.exit('Malformed managed Samba share block; no config changed.')
    if matches[0].group().rstrip('\n') != share_block.rstrip('\n'):
        sys.exit('Managed Samba share block was edited; no config changed.')
    config = block.sub('', config, count=1)
elif re.search(r'(?im)^\s*\[cptc-test\]\s*$', config):
    sys.exit('An unrelated [cptc-test] share already exists; no config changed.')

sections = list(re.finditer(r'(?im)^\s*\[([^]\n]+)\]\s*$', config))
globals_ = [i for i, section in enumerate(sections) if section.group(1).strip().lower() == 'global']
if len(globals_) != 1:
    sys.exit('Expected one [global] section; no config changed.')
index = globals_[0]
start = sections[index].end()
stop = sections[index + 1].start() if index + 1 < len(sections) else len(config)
global_body = config[start:stop]
guest_values = re.findall(r'(?im)^\s*map\s+to\s+guest\s*=\s*([^#;\n]+)', global_body)
if any(value.strip().lower() != 'bad user' for value in guest_values):
    sys.exit('An existing map to guest setting differs from Bad User; no config changed.')
if not guest_values:
    config = config[:stop] + '    # CPTC test share guest mapping\n    map to guest = Bad User\n\n' + config[stop:]

config = config.rstrip('\n') + '\n\n' + share_block
destination.write_text(config)
PY

testparm -s "$candidate" >/dev/null || die "Samba rejected the proposed config; $SMB_CONF is unchanged."
if (( first_run )); then
  install -d -m 0700 "$STATE_DIR"
  if [[ ! -e $MARKER ]]; then
    printf 'cptc-samba-test\n' > "$MARKER"
    chmod 0600 "$MARKER"
  fi
  staging_dir=$(mktemp -d /srv/.cptc-samba-test.XXXXXXXX)
  install -d -m 0700 "$staging_dir/test"
  for file in "$staging_dir/test.txt" "$staging_dir/test/test.txt"; do
    printf 'Hello World\n' > "$file"
    chown "nobody:$guest_group" "$file"
    chmod 0600 "$file"
  done
  chown "nobody:$guest_group" "$staging_dir" "$staging_dir/test"
  chmod 0700 "$staging_dir" "$staging_dir/test"
  mv -nT "$staging_dir" "$SHARE_DIR"
  [[ ! -e $staging_dir ]] || die "$SHARE_DIR appeared during setup; staged data was not installed."
  staging_dir=
fi

if ! cmp -s "$SMB_CONF" "$candidate"; then
  backup=$(mktemp "${SMB_CONF}.cptc-test-backup.XXXXXXXX")
  cp -p "$SMB_CONF" "$backup"
  chmod --reference="$SMB_CONF" "$candidate"
  chown --reference="$SMB_CONF" "$candidate"
  mv "$candidate" "$SMB_CONF"
  printf 'Original Samba config saved at %s\n' "$backup"
  changed=1
else
  changed=0
fi

activate_smbd() {
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    if systemctl is-active --quiet smbd; then
      systemctl reload smbd
    else
      systemctl enable --now smbd
    fi
  else
    command -v service >/dev/null 2>&1 || return 1
    if service smbd status >/dev/null 2>&1; then
      service smbd reload
    else
      service smbd start
    fi
  fi
}
if ! activate_smbd; then
  if (( changed )); then
    cp -p "$backup" "$SMB_CONF" || die "Samba activation failed, and config rollback failed. Backup: $backup"
  fi
  die "Samba activation failed. The original config was restored when this run changed it."
fi

printf 'Writable guest share ready: //HOST_IP/%s\n' "$SHARE_NAME"
printf 'Files: %s/test.txt and %s/test/test.txt\n' "$SHARE_DIR" "$SHARE_DIR"
printf 'Allow TCP 445 from the client if the host firewall blocks it.\n'
