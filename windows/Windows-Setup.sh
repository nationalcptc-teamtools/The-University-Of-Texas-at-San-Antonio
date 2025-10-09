#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$HOME/Tools"
WINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/download/20250904-27f4363e/winPEASx64.exe"
ADRECON_REPO="https://github.com/adrecon/ADRecon.git"
SECLISTS_REPO="https://github.com/danielmiessler/SecLists.git"
ADPEAS_REPO="https://github.com/61106960/adPEAS.git"
APT_NETEXEC="netexec"         
APT_CERTIPY="certipy-ad"       
ETH_IFACE="eth0"              
export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

ask_yes_no() {
  local prompt="$1"
  local default="${2:-N}"   # default N
  local yn
  read -rp "$prompt [y/N]: " yn || true
  yn=${yn:-$default}
  [[ "$yn" =~ ^[Yy]$ ]]
}

ensure_apt_pkg() {
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends "$@"
}

apt_pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

apt_pkg_available() {
  
  local cand
  cand="$(apt-cache policy "$1" 2>/dev/null | awk -F': ' '/Candidate:/ {print $2}')"
  [[ -n "${cand:-}" && "$cand" != "(none)" ]]
}

apt_install_or_update_guarded() {
  local pkg="$1" pretty="$2"
  if ! apt_pkg_available "$pkg"; then
    echo "[!] $pretty ($pkg) is not available in your current apt sources. Skipping install."
    return 0
  fi

  if apt_pkg_installed "$pkg"; then
    if ask_yes_no "[?] $pretty ($pkg) is already installed via apt. Upgrade/refresh it?" "N"; then
      sudo apt-get update -y
      sudo apt-get install -y --only-upgrade "$pkg" || sudo apt-get install -y "$pkg"
      echo "[+] $pretty upgraded/refreshed."
    else
      echo "[=] Skipped $pretty upgrade."
    fi
  else
    if ask_yes_no "[?] Install $pretty ($pkg) via apt?" "Y"; then
      ensure_apt_pkg "$pkg"
      echo "[+] Installed $pretty."
    else
      echo "[=] Skipped $pretty install."
    fi
  fi
}

mkdir -p "$TOOLS_DIR"

configure_zsh_history_and_prompt() {
  
  local iface="${ETH_IFACE}"
  local block_start="# CPTC_HISTORY_PROMPT_START"
  local block_end="# CPTC_HISTORY_PROMPT_END"

  if ! grep -q "$block_start" "$HOME/.zshrc" 2>/dev/null; then
    cat >> "$HOME/.zshrc" <<ZSHCFG
$block_start
export HISTSIZE=100000
export SAVEHIST=100000

# Enable command substitution in prompt
setopt PROMPT_SUBST

# Function to fetch \$iface IP (IPv4) from iproute2
__cptc_ip_iface() {
  ip -o -4 addr show dev "$iface" 2>/dev/null | awk '{print \$4}' | cut -d/ -f1
}

# Prompt example: user@host[IP] cwd %
PROMPT='%n@%m[$(__cptc_ip_iface)] %~ %# '
$block_end
ZSHCFG
    echo "[+] Updated ~/.zshrc with large history + IP-in-prompt (iface: $iface)"
  else
    echo "[=] ~/.zshrc already has CPTC zsh config; leaving as-is"
  fi
}

download_winpeas() {
  local dst="$TOOLS_DIR/winPEASx64.exe"
  if [[ -f "$dst" ]]; then
    if ask_yes_no "[?] winPEASx64.exe already exists. Update (re-download)?" "N"; then
      curl -fsSL "$WINPEAS_URL" -o "$dst"
      echo "[+] winPEASx64.exe updated at $dst"
    else
      echo "[=] Skipped winPEAS update"
    fi
  else
    curl -fsSL "$WINPEAS_URL" -o "$dst"
    chmod +x "$dst" || true
    echo "[+] Downloaded winPEASx64.exe to $dst"
  fi
}

clone_or_update_repo() {
  local name="$1" repo="$2" target="$3" depth="${4:-}"
  if [[ -d "$target/.git" ]]; then
    if ask_yes_no "[?] $name exists. Pull latest changes?" "N"; then
      git -C "$target" pull --rebase --autostash
      echo "[+] Updated $name in $target"
    else
      echo "[=] Skipped updating $name"
    fi
  else
    if [[ -n "$depth" ]]; then
      git clone --depth "$depth" "$repo" "$target"
    else
      git clone "$repo" "$target"
    fi
    echo "[+] Cloned $name into $target"
  fi
}
main() {
  echo "[*] Ensuring base prerequisites…"
  ensure_apt_pkg git curl zsh tmux python3 python3-pip ca-certificates

  echo "[*] Applying zsh history + IP-in-prompt config…"
  configure_zsh_history_and_prompt

  echo "[*] Preparing Tools directory at $TOOLS_DIR"
  mkdir -p "$TOOLS_DIR"

  echo "[*] Handling winPEAS…"
  download_winpeas

  echo "[*] Handling ADRecon…"
  clone_or_update_repo "ADRecon" "$ADRECON_REPO" "$TOOLS_DIR/ADRecon"

  echo "[*] Handling SecLists (shallow clone to save time/space)…"
  clone_or_update_repo "SecLists" "$SECLISTS_REPO" "$TOOLS_DIR/SecLists" "1"

  echo "[*] Handling adPEAS…"
  clone_or_update_repo "adPEAS" "$ADPEAS_REPO" "$TOOLS_DIR/adPEAS"

  echo "[*] (Optional) Install/Update NetExec via apt if available…"
  apt_install_or_update_guarded "$APT_NETEXEC" "NetExec"

  echo "[*] (Optional) Install/Update Certipy-AD via apt if available…"
  apt_install_or_update_guarded "$APT_CERTIPY" "Certipy-AD"

  echo
  echo "[✔] Done. New zsh shells will pick up the prompt. Apply now with:"
  echo "    source ~/.zshrc"
  echo
  if ! apt_pkg_available "$APT_NETEXEC"; then
    echo "[i] Tip: 'netexec' package not found in your apt sources. Leaving it alone (by design)."
  fi
  if ! apt_pkg_available "$APT_CERTIPY"; then
    echo "[i] Tip: 'certipy-ad' package not found in your apt sources. Leaving it alone (by design)."
  fi
}

main "$@"
