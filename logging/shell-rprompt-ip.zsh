# shell-rprompt-ip.zsh
# Right-prompt that shows each active interface's IPv4 as [label/ip], chained:
#   [eth/192.168.1.5][vpn/10.8.0.1]
# "label" collapses long/predictable iface names (enp0s3, wlp2s0, enx..., utun3)
# down to a short type tag. A short clock is kept on the far right.
#
# Usage:  echo 'source /path/to/shell-rprompt-ip.zsh' >> ~/.zshrc

autoload -Uz add-zsh-hook

# Raw interface name -> short label.
_prompt_iface_label() {
  case "$1" in
    tun*|tap*|utun*|wg*|ppp*|ipsec*|gpd*) print -r -- vpn  ;;  # VPN / tunnels
    wl*)                                  print -r -- wifi ;;  # wlan0, wlp2s0, wlx...
    en*|eth*|em*|eno*|ens*|enp*|enx*)     print -r -- eth  ;;  # wired / predictable
    bond*|br*|team*)                      print -r -- lan  ;;  # bridges / bonds
    *)                                    print -r -- "${1%%[0-9]*}" ;;  # strip digits
  esac
}

# Emit "[label/ip]..." for every up, global-scope IPv4 address.
_prompt_ip_chain() {
  local out="" iface ip
  if command -v ip >/dev/null 2>&1; then                       # Linux (iproute2)
    while read -r iface ip; do
      out+="[$(_prompt_iface_label $iface)/${ip%%/*}]"
    done < <(ip -4 -o addr show up scope global 2>/dev/null | awk '{print $2, $4}')
  elif command -v ifconfig >/dev/null 2>&1; then               # macOS / BSD
    while read -r iface ip; do
      out+="[$(_prompt_iface_label $iface)/$ip]"
    done < <(ifconfig 2>/dev/null | awk '
      /^[a-z0-9]+:? / {gsub(/:$/,"",$1); iface=$1}
      /[ \t]inet / && $2!="127.0.0.1" {print iface, $2}')
  fi
  print -r -- "$out"
}

# Recompute once per prompt (IPs change when you (dis)connect a VPN).
_prompt_ip_precmd() {
  local chain; chain="$(_prompt_ip_chain)"
  if [[ -n "$chain" ]]; then
    RPROMPT="%F{cyan}${chain}%f [%F{242}%D{%H:%M}%f]"
  else
    RPROMPT="[%F{242}%D{%H:%M}%f]"
  fi
}

add-zsh-hook precmd _prompt_ip_precmd
