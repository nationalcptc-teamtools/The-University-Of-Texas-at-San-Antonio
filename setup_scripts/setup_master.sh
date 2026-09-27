#!/usr/bin/env bash
# Combined Kali installer. Original category scripts remain in legacy/.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
usage() {
  printf 'Usage: bash setup_scripts/setup_master.sh LOCK REVIEW\n' >&2
  printf 'Or set CPTC_SETUP_LOCK and CPTC_SETUP_REVIEW, then run without arguments.\n' >&2
}
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
(( $# == 0 || $# == 2 )) || { usage; exit 2; }
lock=${1:-${CPTC_SETUP_LOCK:-}}
review=${2:-${CPTC_SETUP_REVIEW:-}}
[[ -n $lock && -n $review ]] || { usage; exit 2; }
[[ -f $lock && ! -L $lock ]] || die "Reviewed lock is missing or a symlink: $lock"
[[ -f $review && ! -L $review ]] || die "Review file is missing or a symlink: $review"
[[ $EUID -ne 0 ]] || die "Run as the intended Kali user; the installer uses sudo where needed."
[[ -f /etc/os-release ]] || die "Cannot identify this Linux distribution."
. /etc/os-release
[[ ${ID:-} == kali ]] || die "This installer is for Kali Linux."
command -v sudo >/dev/null 2>&1 || die "sudo is required."
sudo -v
export DEBIAN_FRONTEND=noninteractive
export TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"
printf '%s\n' 'The reviewed lock covers only the team environment package bundle.' \
  'The following legacy sections also install packages and download external tools.'

# ##### Reviewed Kali Team Environment #####
# This review covers only the team environment package bundle. The legacy
# sections below retain their own unpinned package and download commands.
# Run this before additional installers alter package sources or versions.
sudo /usr/bin/python3 "$script_dir/team-env-setup/team_env_setup.py" apply --apply --lock "$lock" --review "$review"
sudo /usr/bin/python3 "$script_dir/team-env-setup/team_env_setup.py" verify --lock "$lock" --review "$review"

# ##### Shared APT Update #####
# Keep each category's package installation separate.
sudo apt-get update

# ##### Base Linux Setup #####
printf '\n##### Base Linux Setup #####\n'
# Commands from legacy/setup.sh run in this shell.
#!/bin/bash

# setup-script.sh
#
# With <3 from the UTSA CPTC team
# Tested on:
# Kali 2023.4-vmware
# Linux kali 6.5.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.5.6-1kali1 (2023-10-09) x86_64 GNU/Linux


### !! INSTALL XTERM ON WINDOWS FIRST MANUALLY AND THEN IMPORT THE MOBA CONFIG. !!

#read -p "Please run this script using the bash command, inside the context of the bash shell. Enter \"/bin/bash\", then execute the script with \"bash setup-script.sh\""

# The basics
sudo apt install tmux -y

# tmux + zsh config changes
echo "export HISTSIZE=100000" >> ~/.zshrc
echo "export HISTFILESIZE=100000" >> ~/.zshrc
# Reload ~/.zshrc from an interactive zsh after setup.
export DEBIAN_FRONTEND=noninteractive

# Get user context
who=$(whoami)

# Setting default shell to bash
#chsh -s /bin/bash $who

# Before we install tools, let's change/update our repos
# APT metadata was updated once above.

# Install tools (apt)
sudo apt install -y \
	apt-transport-https \
	pacu \
	peass \
	awscli \
	sliver \
	python3 \
	python3-pip \
	libssl-dev \
	seclists \
	curl \
	gobuster \
	nbtscan \
	nikto \
	onesixtyone \
	enum4linux \
	smbmap \
	smtp-user-enum \
	sslscan \
	hashcat \
	sqlmap \
	john


# XRDP lol
#sudo apt install -y kali-desktop-xfce xorg xrdp
#sudo systemctl enable xrdp --now
#sudo systemctl start xrdp

# Make tools directory
mkdir -p ~/tools
chown -R $who:$who ~/tools

# Peass-NG Suite
mkdir -p ~/tools/privesc/
cp /usr/share/peass/linpeas/linpeas.sh ~/tools/privesc
cp /usr/share/peass/winpeas/winPEASany.exe ~/tools/privesc



echo "Ok, done :) refresh your ssh connection or enter bash to continue - Happy Hacking!"

# ##### Terminal Configuration #####
printf '\n##### Terminal Configuration #####\n'
# Commands from legacy/terminal_config.zsh run in this shell once.
if ! grep -Fq '# CPTC terminal config' "$HOME/.zshrc"; then
  cp -a "$HOME/.zshrc" "$HOME/.zshrc.bak" 2>/dev/null || true
  cat >> "$HOME/.zshrc" <<'CPTC_ZSH_CONFIG'

# CPTC terminal config
RPROMPT='[%D{%F %H:%M}]'

export ip_address=$(ip addr show tun0 2>/dev/null | grep -oP '\d+(\.\d+){3}' | head -1); [ -z "$ip_address" ] && ip_address=$(ip addr show eth0 2>/dev/null | grep -oP '\d+(\.\d+){3}' | head -1)

PROMPT="%F{%(#.blue.green)}┌──${debian_chroot:+($debian_chroot)─}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))─}(%B%F{%(#.red.blue)}%n㉿%m%b%F{%(#.blue.green)})-[%B%F{blue}${ip_address}%b%F{%(#.blue.green)}]-[%F{reset}%B%(6~.%-1~/…/%4~.%5~)%b%F{%(#.blue.green)}]
└─%B%(#.%F{red}#.%F{blue}$)%b%F{reset} "
CPTC_ZSH_CONFIG
fi
# Start a fresh Zsh session to load this configuration; do not source it in Bash.

# ##### Linux Tools #####
printf '\n##### Linux Tools #####\n'
# Commands from legacy/linux-tooling.sh run in this shell.
#!/bin/bash
sudo apt install git python3-venv -y

target_user=$(whoami)
mkdir -p ~/tools/ ~/tools/privesc

chown -R ${target_user}:${target_user} ~/tools/ ~/tools/privesc
chmod u+rwx ~/tools/ ~/tools/privesc

if [[ ! -d ~/tools/privesc/redteam-launcher/.git ]]; then
  sudo -u "${target_user}" git clone https://github.com/No4Sec/redteam-launcher.git ~/tools/privesc/redteam-launcher
fi

python3 -m venv ~/tools/privesc/redteam-launcher/.venv
~/tools/privesc/redteam-launcher/.venv/bin/python -m pip install colorama

if [[ ! -d ~/tools/privesc/beroot/.git ]]; then
  sudo -u "${target_user}" git clone https://github.com/AlessandroZ/BeRoot.git ~/tools/privesc/beroot
fi

# make privesc tar
tmpdir=$(mktemp -d)
mkdir -p "$tmpdir/privesc/redteam-launcher" "$tmpdir/privesc/beroot"
cp -a ~/tools/privesc/redteam-launcher/launcher.py "$tmpdir/privesc/redteam-launcher/"
cp -ra ~/tools/privesc/redteam-launcher/scripts "$tmpdir/privesc/redteam-launcher/"
cp -ra ~/tools/privesc/redteam-launcher/.venv "$tmpdir/privesc/redteam-launcher/"
cp -ra ~/tools/privesc/beroot/Linux/* "$tmpdir/privesc/beroot/"
tar -C "$tmpdir" -cvf ~/tools/privesc/linux_privesc.tar privesc
rm -rf "$tmpdir"

# ##### Windows and AD Tools #####
printf '\n##### Windows and AD Tools #####\n'
# Commands from legacy/Windows-Setup.sh run in this shell.
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
  # APT metadata was updated once above.
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

install_windows_ad() {
  install_base_utils
  install_winpeas
  install_git_repos
  install_netexec
  install_certipy
  install_impacket
  post_summary
}

install_windows_ad

# ##### Additional Windows and AD Tools #####
printf '\n##### Additional Windows and AD Tools #####\n'
# Commands from legacy/windows-tooling.sh run in this shell.
#!/bin/bash
sudo apt install -y 7zip
mkdir -p ~/tools/AD

# Get user context
who=$(whoami)
# Make tools directory
mkdir -p ~/tools
chown -R $who:$who ~/tools

# PowerView + Pywerview
#mkdir -p ~/tools/AD/
#wget -4 https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -O ~/tools/AD/PowerView.ps1
#mkdir -p ~/tools/AD/Pywerview/
#git clone https://github.com/aniqfakhrul/powerview.py.git ~/tools/AD/Pywerview/
#chmod +x ~/tools/AD/Pywerview/setup.py
#chmod +x ~/tools/AD/Pywerview/powerview.py
#pip3 install -r ~/tools/AD/Pywerview/requirements.txt
#sudo python3 ~/tools/AD/Pywerview/setup.py install
# Can't believe I had to do this... >_>
# Disabled: hardcoded Python 3.11 library path; review on the target Kali version.
# Disabled: hardcoded Python 3.11 library path; review on the target Kali version.

# Certipy / Certify
# Disabled: the reviewed package setup installs Certipy without a global pip write.
# Disabled: do not rename a distribution-owned executable.
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe -O ~/tools/AD/Certify.exe

# SharpHound collector
mkdir -p ~/tools/AD/SharpHound/
wget https://github.com/BloodHoundAD/SharpHound/releases/download/v2.3.0/SharpHound-v2.3.0.zip -O /var/tmp/SharpHound-v2.3.0.zip
7z x -y -o"$HOME/tools/AD/SharpHound/" /var/tmp/SharpHound-v2.3.0.zip

# Mimikatz
mkdir -p ~/tools/cred_harvesting
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ~/tools/cred_harvesting

# Rubeus
mkdir -p ~/tools/AD/Rubeus/
wget -4 https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe -O ~/tools/AD/Rubeus/Rubeus.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v4.7.2%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-4_7_2.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v4.5%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-4_5.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v3.5%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-3_5.exe

# ##### Web Tools #####
printf '\n##### Web Tools #####\n'
# Commands from legacy/web-tooling.sh run in this shell.
#!/bin/bash
TMP_DIR="$(mktemp -d)"
ZAP_DIR="${ZAP_DIR:-$HOME/tools/web/zap}"

# update system
# APT metadata was updated once above.

# install apt sourced tools
sudo apt install nikto sqlmap wpscan whatweb wafw00f sslscan ffuf whois hydra waymore katana pipx golang golang-go -y

# check java is installed
if ! command -v java >/dev/null 2>&1; then
  sudo apt install -y openjdk-11-jre-headless
fi
# pipx tools
pipx install --force git+https://github.com/xnl-h4ck3r/xnLinkFinder.git

# go tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest


# mk folders for tools that need a place to go
mkdir -p ~/tools/web/ ~/tools/web/zap ~/tools/web/burp
# Burp
curl -L -o "${TMP_DIR}/burp_latest.sh" "https://portswigger.net/burp/releases/download?product=community&version=2025.8.4&type=Linux"
chmod u+x "${TMP_DIR}/burp_latest.sh"
/bin/bash "${TMP_DIR}/burp_latest.sh"

# Burp Jython
curl -L -o ~/tools/web/burp/jython.jar "https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar"

# ZAP
curl -L -o "${TMP_DIR}/zap_installer.sh" "https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2_16_1_unix.sh"
chmod u+x "${TMP_DIR}/zap_installer.sh"
sudo "${TMP_DIR}/zap_installer.sh" -y -d "${ZAP_DIR}"

# Cleanup
rm -rf "${TMP_DIR}"

# ##### Cloud Tools #####
printf '\n##### Cloud Tools #####\n'
# Commands from legacy/cloud-tooling.sh run in this shell.
#!/bin/bash

# Get user context
who=$(whoami)
# Make tools directory
mkdir -p ~/tools
chown -R $who:$who ~/tools

# Cloud tools installation
mkdir -p ~/tools/cloud/
wget https://github.com/BishopFox/cloudfox/releases/download/v1.13.0/cloudfox-linux-amd64.zip -O /tmp/cloudfox-linux-amd64.zip
unzip -o /tmp/cloudfox-linux-amd64.zip -d ~/tools/cloud/

# ##### GCP Tools #####
printf '\n##### GCP Tools #####\n'
# Commands from legacy/gcp-tooling.sh run in this shell.
# This is for installing gcp tools
mkdir -p ~/gcp-tooling
pushd ~/gcp-tooling >/dev/null

# Install gcloud cli
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz
tar -xf google-cloud-cli-linux-x86_64.tar.gz
./google-cloud-sdk/install.sh -q

# Install the rest of the gcp tools
[[ -d gcpwn/.git ]] || git clone https://github.com/NetSPI/gcpwn.git
[[ -d GCP-IAM-Privilege-Escalation/.git ]] || git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation.git
[[ -d gcp-tooling/.git ]] || git clone https://github.com/TeneBrae93/gcp-tooling.git
popd >/dev/null

# ##### AWS Tools #####
printf '\n##### AWS Tools #####\n'
# Commands from legacy/aws-tooling.sh run in this shell.
#!/bin/bash
# PASS 1 as args for non kali
# run as sudo
#source zsh after running on kali
# APT metadata was updated once above.
if [[ $ID == kali ]]; then
    sudo apt install -y python3 python3-pip pipx unzip python3-awscrt python3-jmespath awscli pacu
    echo -e '\nexport PATH=/usr/local/bin/:$PATH\nautoload bashcompinit && bashcompinit\nautoload -Uz compinit && compinit\ncomplete -C "/usr/local/bin/aws_completer" aws' >> ~/.zshrc
    echo "run source ~/.zshrc"
fi
if [[ $ID != kali ]]; then
    sudo apt install -y python3 python3-pip pipx unzip python3-awscrt python3-jmespath
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    bash ./aws/install
    pipx install git+https://github.com/RhinoSecurityLabs/pacu.git
    pipx ensurepath
    echo -e '\n# AWS CLI v2 Config\nexport PATH=/usr/local/bin:$PATH\ncomplete -C "/usr/local/bin/aws_completer" aws' >> ~/.bashrc
    source ~/.bashrc
fi

# ##### BloodHound CE and RustHound CE #####
# Disabled legacy BloodHound.py collector:
# git clone https://github.com/dirkjanm/BloodHound.py.git
# The old Debian bookworm Docker repository commands remain in legacy/.
printf '\n##### BloodHound CE and RustHound CE #####\n'
sudo apt-get install -y docker.io docker-compose git curl make gcc clang libclang-dev libkrb5-dev libsasl2-modules-gssapi-mit pkg-config rustc cargo
sudo systemctl enable --now docker
mkdir -p "$HOME/BloodHoundCE"
if [[ ! -e "$HOME/BloodHoundCE/docker-compose.yml" ]]; then
  compose_temp=$(mktemp "$HOME/BloodHoundCE/.docker-compose.XXXXXXXX")
  trap 'rm -f -- "$compose_temp"' EXIT
  curl -fsSLo "$compose_temp" \
    https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/docker-compose.yml
  mv -- "$compose_temp" "$HOME/BloodHoundCE/docker-compose.yml"
  trap - EXIT
fi
sudo docker compose -f "$HOME/BloodHoundCE/docker-compose.yml" pull
if [[ -d "$HOME/BloodHoundCE/RustHound-CE/.git" ]]; then
  git -C "$HOME/BloodHoundCE/RustHound-CE" pull --ff-only
else
  git clone https://github.com/g0h4n/RustHound-CE.git "$HOME/BloodHoundCE/RustHound-CE"
fi
pushd "$HOME/BloodHoundCE/RustHound-CE" >/dev/null
make install
popd >/dev/null
printf 'BloodHound CE compose file: %s\n' "$HOME/BloodHoundCE/docker-compose.yml"
printf 'RustHound CE executable: %s\n' "$HOME/.cargo/bin/rusthound-ce"
printf 'Review the compose file and set unique credentials before starting BloodHound CE.\n'
printf 'Setup complete.\n'
