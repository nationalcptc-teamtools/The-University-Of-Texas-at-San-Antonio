#!/bin/sh
set -eu
out=${1:?output path required}
mkdir -p "$(dirname "$out")"
cc -shared -fPIC -O2 -Wall -Wextra -Werror -o "$out" "$(dirname "$0")/nmap_connect_shim.c" -ldl
chmod 700 "$out"
