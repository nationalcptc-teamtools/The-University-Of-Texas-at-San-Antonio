#!/usr/bin/env bash
set -euo pipefail

SHARE_NAME=cptc-test
MOUNT_DIR=$HOME/cptc-samba-test

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

if [[ $EUID -eq 0 ]]; then
  privileged=()
else
  command -v sudo >/dev/null 2>&1 || die "Install sudo or run as root."
  privileged=(sudo)
fi

[[ $# -eq 1 ]] || die "Usage: $0 HOST_IPV4"
ip=$1
[[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "Provide the share host's IPv4 address."
IFS=. read -r -a octets <<< "$ip"
for octet in "${octets[@]}"; do
  (( 10#$octet <= 255 )) || die "Invalid IPv4 address: $ip"
done

if ! command -v mount.cifs >/dev/null 2>&1 && [[ ! -x /sbin/mount.cifs && ! -x /usr/sbin/mount.cifs ]]; then
  command -v apt-get >/dev/null 2>&1 || die "apt-get is required to install cifs-utils."
  "${privileged[@]}" apt-get update
  "${privileged[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y cifs-utils
fi

if [[ -e $MOUNT_DIR && ! -d $MOUNT_DIR ]] || [[ -L $MOUNT_DIR ]]; then
  die "$MOUNT_DIR is not a regular directory."
fi
mkdir -p "$MOUNT_DIR"
source="//$ip/$SHARE_NAME"
if mountpoint -q "$MOUNT_DIR"; then
  existing=$(findmnt -nro SOURCE --target "$MOUNT_DIR")
  [[ $existing == "$source" ]] || die "$MOUNT_DIR is already mounted from $existing."
  mounted_here=0
else
  [[ -z $(ls -A "$MOUNT_DIR") ]] || die "$MOUNT_DIR is not empty; refusing to hide its files."
  "${privileged[@]}" mount -t cifs "$source" "$MOUNT_DIR" -o "guest,rw,nosuid,nodev,exec,uid=$(id -u),gid=$(id -g)" || die "Could not mount $source. Check TCP 445 and guest access."
  mounted_here=1
fi

options=$(findmnt -nro OPTIONS --target "$MOUNT_DIR")
for required in rw nosuid nodev; do
  if [[ ,$options, != *,$required,* ]]; then
    if (( mounted_here )); then
      "${privileged[@]}" umount "$MOUNT_DIR" || true
    fi
    die "$MOUNT_DIR lacks the required $required mount option. Unmount it and retry."
  fi
done
if [[ ,$options, == *,noexec,* ]]; then
  if (( mounted_here )); then
    "${privileged[@]}" umount "$MOUNT_DIR" || true
  fi
  die "$MOUNT_DIR is mounted noexec. Unmount it and retry."
fi

for file in "$MOUNT_DIR/test.txt" "$MOUNT_DIR/test/test.txt"; do
  if [[ ! -f $file ]] || ! head -c 1 "$file" >/dev/null; then
    if (( mounted_here )); then
      "${privileged[@]}" umount "$MOUNT_DIR" || true
    fi
    die "Mounted share is missing a readable test file: $file"
  fi
done
if ! probe=$(mktemp "$MOUNT_DIR/.cptc-guest-write.XXXXXXXX"); then
  if (( mounted_here )); then
    "${privileged[@]}" umount "$MOUNT_DIR" || true
  fi
  die "Guest cannot create files in $MOUNT_DIR."
fi
trap 'rm -f "$probe"' EXIT
rm "$probe" || die "Guest created $probe but could not remove it."
trap - EXIT
printf 'Connected to %s at %s\n' "$source" "$MOUNT_DIR"
if [[ $EUID -eq 0 ]]; then
  printf 'To disconnect: umount %q\n' "$MOUNT_DIR"
else
  printf 'To disconnect: sudo umount %q\n' "$MOUNT_DIR"
fi
