#!/usr/bin/env bash
# shell-rprompt-ip.bash
# Bash has no native RPROMPT, so this emulates a zsh-style right prompt: it
# prints each active interface's IPv4 as [label/ip], chained and right-aligned
# on the prompt line:
#   [eth/192.168.1.5][vpn/10.8.0.1]
# "label" collapses long/predictable iface names (enp0s3, wlp2s0, utun3) to a
# short type tag.
#
# Usage:  echo 'source /path/to/shell-rprompt-ip.bash' >> ~/.bashrc

# Raw interface name -> short label.
_prompt_iface_label() {
  case "$1" in
    tun*|tap*|utun*|wg*|ppp*|ipsec*|gpd*) printf 'vpn'  ;;  # VPN / tunnels
    wl*)                                  printf 'wifi' ;;  # wlan0, wlp2s0, wlx...
    en*|eth*|em*|eno*|ens*|enp*|enx*)     printf 'eth'  ;;  # wired / predictable
    bond*|br*|team*)                      printf 'lan'  ;;  # bridges / bonds
    *)                                    printf '%s' "${1%%[0-9]*}" ;;  # strip digits
  esac
}

# Emit "[label/ip]..." for every up, global-scope IPv4 address.
_prompt_ip_chain() {
  local out="" iface ip
  if command -v ip >/dev/null 2>&1; then                       # Linux (iproute2)
    while read -r iface ip; do
      out+="[$(_prompt_iface_label "$iface")/${ip%%/*}]"
    done < <(ip -4 -o addr show up scope global 2>/dev/null | awk '{print $2, $4}')
  elif command -v ifconfig >/dev/null 2>&1; then               # macOS / BSD
    while read -r iface ip; do
      out+="[$(_prompt_iface_label "$iface")/$ip]"
    done < <(ifconfig 2>/dev/null | awk '
      /^[a-z0-9]+:? / {gsub(/:$/,"",$1); iface=$1}
      /[ \t]inet / && $2!="127.0.0.1" {print iface, $2}')
  fi
  printf '%s' "$out"
}

# Print the chain right-aligned on the current prompt line, then restore the
# cursor so PS1 draws normally.
_prompt_ip_rprompt() {
  local chain cols
  chain="$(_prompt_ip_chain)"
  [[ -z "$chain" ]] && return
  cols=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
  # \e[s save cursor; \e[<col>G go to column; cyan text; \e[u restore cursor.
  printf '\e[s\e[%dG\e[36m%s\e[0m\e[u' "$(( cols - ${#chain} + 1 ))" "$chain"
}

# Prepend to PROMPT_COMMAND without duplicating or dropping what's there.
case ";${PROMPT_COMMAND};" in
  *";_prompt_ip_rprompt;"*) ;;
  *) PROMPT_COMMAND="_prompt_ip_rprompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
