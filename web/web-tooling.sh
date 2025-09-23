#!/bin/bash
TMP_DIR="$(mktemp -d)"

# update system
sudo apt update 

# install apt sourced tools
sudo apt install nikto sqlmap wpscan whatweb wafw00f sslscan ffuf whois hydra waymore katana pipx golang golang-go -y

# check java is installed
if ! command -v java >/dev/null 2>&1; then
  sudo apt install -y openjdk-11-jre-headless
fi
# pipx tools
pipx install git+https://github.com/xnl-h4ck3r/xnLinkFinder.git

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