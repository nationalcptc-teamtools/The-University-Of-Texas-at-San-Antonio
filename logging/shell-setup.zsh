# shell-setup.zsh  --  single drop-in for zsh
#
# Does two things:
#   1. Logs every interactive command with millisecond-precision start/end
#      timestamps (and exit code + duration) to a per-session logfile.
#   2. Shows a right prompt with each active interface's IPv4 as a chained
#      [label/ip] string, e.g. [eth/192.168.1.5][vpn/10.8.0.1], plus a clock.
#
# Usage:  echo 'source /path/to/shell-setup.zsh' >> ~/.zshrc
# Logfile: /tmp/shell-zsh-<YYYYMMDD-HHMMSS>.log   (one per shell session)

zmodload zsh/datetime 2>/dev/null          # EPOCHREALTIME / strftime
autoload -Uz add-zsh-hook

# --- time helper: sets _NOW_STAMP ("...HH:MM:SS.mmm") and _NOW_MS (epoch ms) --
_shell_log_now() {
  local t=$EPOCHREALTIME                    # "seconds.microseconds"
  local sec=${t%%.*} frac=${t#*.}
  frac=${frac}000000; frac=${frac:0:3}      # microseconds -> milliseconds
  _NOW_MS=$(( sec * 1000 + frac ))
  strftime -s _NOW_STAMP '%Y-%m-%d %H:%M:%S' $sec
  _NOW_STAMP="$_NOW_STAMP.$frac"
}

# --- pick the logfile once, at shell start ----------------------------------
if [[ -z "$SHELL_LOG_FILE" ]]; then
  export SHELL_LOG_FILE="/tmp/shell-zsh-$(date +%Y%m%d-%H%M%S).log"
  _shell_log_now
  print -r -- "=== zsh session started $_NOW_STAMP (pid $$, tty ${TTY:-?}) ===" >> "$SHELL_LOG_FILE"
fi

# --- interface name -> short label ------------------------------------------
_prompt_iface_label() {
  case "$1" in
    tun*|tap*|utun*|wg*|ppp*|ipsec*|gpd*) print -r -- vpn  ;;  # VPN / tunnels
    wl*)                                  print -r -- wifi ;;  # wlan0, wlp2s0...
    en*|eth*|em*|eno*|ens*|enp*|enx*)     print -r -- eth  ;;  # wired/predictable
    bond*|br*|team*)                      print -r -- lan  ;;  # bridges / bonds
    *)                                    print -r -- "${1%%[0-9]*}" ;;
  esac
}

# --- "[label/ip]..." for every up, global-scope IPv4 address ----------------
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
      /[ \t]inet / && $2!="127.0.0.1" && $2 !~ /^169\.254\./ {print iface, $2}')
  fi
  print -r -- "$out"
}

# --- hooks -------------------------------------------------------------------
# preexec: runs just before a command executes; $1 is the exact line typed.
_shell_preexec() {
  _SHELL_LOG_CMD="$1"
  _shell_log_now
  _SHELL_LOG_START_MS=$_NOW_MS
  print -r -- "[$_NOW_STAMP] START : $1" >> "$SHELL_LOG_FILE"
}

# precmd: runs before each prompt. Capture $? FIRST, log END, then set RPROMPT
# (the IP lookup runs subshells, which would otherwise clobber $?).
_shell_precmd() {
  local exit_status=$?
  if [[ -n "$_SHELL_LOG_CMD" ]]; then
    _shell_log_now
    local dms=$(( _NOW_MS - _SHELL_LOG_START_MS ))
    print -r -- "[$_NOW_STAMP] END   : (exit=$exit_status, $((dms/1000)).${(l:3::0:)$((dms%1000))}s / ${dms}ms) $_SHELL_LOG_CMD" >> "$SHELL_LOG_FILE"
    unset _SHELL_LOG_CMD
  fi
  local chain; chain="$(_prompt_ip_chain)"
  if [[ -n "$chain" ]]; then
    RPROMPT="%F{cyan}${chain}%f [%F{242}%D{%H:%M}%f]"
  else
    RPROMPT="[%F{242}%D{%H:%M}%f]"
  fi
}

add-zsh-hook preexec _shell_preexec
add-zsh-hook precmd  _shell_precmd
