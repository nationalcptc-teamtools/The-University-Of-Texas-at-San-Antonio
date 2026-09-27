#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="${TOOLS_DIR:-$HOME/Tools}"
VENVS_DIR="$TOOLS_DIR/venvs"
BIN_DIR="$TOOLS_DIR/bin"    
WINPEAS_URL="${WINPEAS_URL:-https://github.com/peass-ng/PEASS-ng/releases/download/20250904-27f4363e/winPEASx64.exe}"
ADRECON_REPO="${ADRECON_REPO:-https://github.com/adrecon/ADRecon.git}"
SECLISTS_REPO="${SECLISTS_REPO:-https://github.com/danielmiessler/SecLists.git}"
ADPEAS_REPO="${ADPEAS_REPO:-https://github.com/61106960/adPEAS.git}"
APT_NETEXEC="${APT_NETEXEC:-netexec}"
APT_CERTIPY="${APT_CERTIPY:-certipy-ad}"
APT_IMPACKET="${APT_IMPACKET:-python3-impacket}"

export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

apt_pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

apt_pkg_available() {
  local cand
  cand="$(apt-cache policy "$1" 2>/dev/null | awk -F': ' '/Candidate:/ {print $2}')"
  [[ -n "$cand" && "$cand" != "(none)" ]]
}

ensure_apt_pkg() {
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends "$@"
}

ensure_dir() { mkdir -p "$1"; }

make_launcher() {
  local launcher="$1"; local target="$2"
  cat >"$launcher" <<EOF
#!/usr/bin/env bash
exec "$target" "\$@"
EOF
  chmod +x "$launcher"
}

ensure_python_venv() {
  if ! python3 -c 'import venv' 2>/dev/null; then
    echo "[*] Installing python3-venv..."
    ensure_apt_pkg python3-venv
  fi
}

create_or_update_venv() {
  local venv="$1"
  if [[ ! -d "$venv" ]]; then
    python3 -m venv "$venv"
  fi
  "$venv/bin/python" -m pip install --upgrade --quiet pip setuptools wheel
}

install_base_utils() {
  echo "[*] Installing base utilities..."
  ensure_apt_pkg git curl wget unzip ca-certificates python3
}

install_winpeas() {
  echo "[*] Fetching winPEAS..."
  ensure_dir "$TOOLS_DIR/winpeas"
  local out="$TOOLS_DIR/winpeas/winPEASx64.exe"
  curl -fsSL "$WINPEAS_URL" -o "$out"
  chmod +x "$out" || true
  echo "    -> $out"
}

clone_or_update() {
  local repo_url="$1"; local dest="$2"
  if [[ -d "$dest/.git" ]]; then
    echo "    Updating $(basename "$dest") ..."
    git -C "$dest" pull --ff-only
  else
    echo "    Cloning $(basename "$dest") ..."
    git clone --depth=1 "$repo_url" "$dest"
  fi
}

install_git_repos() {
  echo "[*] Cloning/updating repos into $TOOLS_DIR ..."
  ensure_dir "$TOOLS_DIR"
  clone_or_update "$ADRECON_REPO" "$TOOLS_DIR/ADRecon"
  clone_or_update "$SECLISTS_REPO" "$TOOLS_DIR/SecLists"
  clone_or_update "$ADPEAS_REPO" "$TOOLS_DIR/adPEAS"
}

install_netexec() {
  echo "[*] Installing NetExec (nxc)..."
  ensure_dir "$BIN_DIR"
  if apt_pkg_available "$APT_NETEXEC"; then
    ensure_apt_pkg "$APT_NETEXEC"
    echo "    Installed via apt: run 'nxc'"
  else
    echo "    apt package '$APT_NETEXEC' not found; building isolated venv..."
    ensure_python_venv
    local venv="$VENVS_DIR/netexec"
    ensure_dir "$VENVS_DIR"
    create_or_update_venv "$venv"
    "$venv/bin/python" -m pip install --quiet "git+https://github.com/Pennyw0rth/NetExec.git"
    make_launcher "$BIN_DIR/nxc" "$venv/bin/nxc"
    echo "    -> Venv: $venv"
    echo "    -> Launcher: $BIN_DIR/nxc"
    echo "       (run with full path, or add '$BIN_DIR' to your PATH manually if you want)"
  fi
}

install_certipy() {
  echo "[*] Installing Certipy-AD (certipy)..."
  ensure_dir "$BIN_DIR"
  if apt_pkg_available "$APT_CERTIPY"; then
    ensure_apt_pkg "$APT_CERTIPY"
    echo "    Installed via apt: run 'certipy'"
  else
    echo "    apt package '$APT_CERTIPY' not found; building isolated venv..."
    ensure_python_venv
    local venv="$VENVS_DIR/certipy"
    ensure_dir "$VENVS_DIR"
    create_or_update_venv "$venv"
    "$venv/bin/python" -m pip install --quiet certipy-ad
    make_launcher "$BIN_DIR/certipy" "$venv/bin/certipy"
    echo "    -> Venv: $venv"
    echo "    -> Launcher: $BIN_DIR/certipy"
    echo "       (run with full path, or add '$BIN_DIR' to your PATH manually if you want)"
  fi
}

install_impacket() {
  echo "[*] Installing Impacket (various tools)..."
  ensure_dir "$BIN_DIR"
  if apt_pkg_available "$APT_IMPACKET"; then
    ensure_apt_pkg "$APT_IMPACKET"
    echo "    Installed via apt package: $APT_IMPACKET (use system-installed impacket scripts)"
  else
    echo "    Apt package '$APT_IMPACKET' not found; building isolated venv for Impacket..."
    ensure_python_venv
    local venv="$VENVS_DIR/impacket"
    ensure_dir "$VENVS_DIR"
    create_or_update_venv "$venv"
    "$venv/bin/python" -m pip install --quiet impacket
    for f in "$venv/bin/"*; do
      if [[ -x "$f" && ! -d "$f" ]]; then
        local name=$(basename "$f")
      
        case "$name" in
          python*|pip*|wheel*|easy_install*)
            continue
            ;;
        esac
        make_launcher "$BIN_DIR/$name" "$f"
      fi
    done
    echo "    -> Venv: $venv"
    echo "    -> Launchers placed in: $BIN_DIR (e.g., $BIN_DIR/wmiexec.py)"
    echo "       (run with full path, or add '$BIN_DIR' to your PATH manually if you want)"
  fi
}

post_summary() {
  cat <<EOF

[✔] Finished

EOF
}

main() {
  install_base_utils
  install_winpeas
  install_git_repos
  install_netexec
  install_certipy
  install_impacket
  post_summary
}

main "$@"
