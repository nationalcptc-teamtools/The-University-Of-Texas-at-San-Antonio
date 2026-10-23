#!/usr/bin/env bash
# shell-setup.bash  --  single drop-in for bash
#
# Does two things:
#   1. Logs every interactive command with millisecond-precision start/end
#      timestamps (and exit code + duration) to a per-session logfile.
#   2. Shows a zsh-style right prompt (right-aligned) with each active
#      interface's IPv4 as a chained [label/ip] string, e.g.
#      [eth/192.168.1.5][vpn/10.8.0.1].
#
# Usage:  echo 'source /path/to/shell-setup.bash' >> ~/.bashrc
# Logfile: /tmp/shell-bash-<YYYYMMDD-HHMMSS>.log   (one per shell session)
#
# Portability: a high-res clock is detected once ($EPOCHREALTIME -> GNU date %N
# -> perl Time::HiRes -> whole seconds), so it runs anywhere bash does, macOS
# bash 3.2 included; only millisecond resolution varies.

# --- high-resolution clock detection (once) ---------------------------------
if [[ -z "$_SHELL_LOG_CLOCK" ]]; then
  if   [[ -n "${EPOCHREALTIME:-}" ]];                 then _SHELL_LOG_CLOCK=epochrealtime
  elif date +%N 2>/dev/null | grep -q '^[0-9]';       then _SHELL_LOG_CLOCK=gnudate
  elif command -v perl >/dev/null 2>&1;               then _SHELL_LOG_CLOCK=perl
  else                                                     _SHELL_LOG_CLOCK=seconds
  fi
  export _SHELL_LOG_CLOCK
fi

_shell_log_raw() {
  case "$_SHELL_LOG_CLOCK" in
    epochrealtime) printf '%s' "$EPOCHREALTIME" ;;
    gnudate)       date +%s.%N ;;
    perl)          perl -MTime::HiRes=time -e 'my $t=time; printf "%d.%06d", int($t), int(($t-int($t))*1e6)' ;;
    *)             date +%s ;;
  esac
}

# --- time helper: sets _NOW_STAMP ("...HH:MM:SS.mmm") and _NOW_MS (epoch ms) --
_shell_log_now() {
  local t sec frac
  t=$(_shell_log_raw)
  if [[ $t == *[.,]* ]]; then sec=${t%%[.,]*}; frac=${t#*[.,]}; else sec=$t; frac=0; fi
  frac=${frac}000000; frac=${frac:0:3}
  _NOW_MS=$(( 10#$sec * 1000 + 10#$frac ))
  if ! printf -v _NOW_STAMP '%(%Y-%m-%d %H:%M:%S)T' "$sec" 2>/dev/null; then
    _NOW_STAMP=$(date '+%Y-%m-%d %H:%M:%S')   # bash < 4.2
  fi
  _NOW_STAMP="$_NOW_STAMP.$frac"
}

# --- pick the logfile once, at shell start ----------------------------------
if [[ -z "$SHELL_LOG_FILE" ]]; then
  export SHELL_LOG_FILE="/tmp/shell-bash-$(date +%Y%m%d-%H%M%S).log"
  _shell_log_now
  printf '=== bash session started %s (pid %s, tty %s) ===\n' "$_NOW_STAMP" "$$" "$(tty 2>/dev/null)" >> "$SHELL_LOG_FILE"
fi

# --- interface name -> short label ------------------------------------------
_prompt_iface_label() {
  case "$1" in
    tun*|tap*|utun*|wg*|ppp*|ipsec*|gpd*) printf 'vpn'  ;;  # VPN / tunnels
    wl*)                                  printf 'wifi' ;;  # wlan0, wlp2s0...
    en*|eth*|em*|eno*|ens*|enp*|enx*)     printf 'eth'  ;;  # wired/predictable
    bond*|br*|team*)                      printf 'lan'  ;;  # bridges / bonds
    *)                                    printf '%s' "${1%%[0-9]*}" ;;
  esac
}

# --- "[label/ip]..." for every up, global-scope IPv4 address ----------------
_prompt_ip_chain() {
  local out="" iface ip
  if command -v ip >/dev/null 2>&1; then                       # Linux (iproute2)
    while read -r iface ip; do out+="[$(_prompt_iface_label "$iface")/${ip%%/*}]"; done \
      < <(ip -4 -o addr show up scope global 2>/dev/null | awk '{print $2, $4}')
  elif command -v ifconfig >/dev/null 2>&1; then               # macOS / BSD
    while read -r iface ip; do out+="[$(_prompt_iface_label "$iface")/$ip]"; done \
      < <(ifconfig 2>/dev/null | awk '
        /^[a-z0-9]+:? / {gsub(/:$/,"",$1); iface=$1}
        /[ \t]inet / && $2!="127.0.0.1" && $2 !~ /^169\.254\./ {print iface, $2}')
  fi
  printf '%s' "$out"
}

# --- preexec, emulated via the DEBUG trap -----------------------------------
# A guard flag makes it fire once per command line (not once per simple cmd).
_shell_preexec() {
  [[ -n "$COMP_LINE" ]] && return
  [[ -n "$_SHELL_LOG_RUNNING" ]] && return
  case "$BASH_COMMAND" in _shell_precmd*|"$PROMPT_COMMAND") return ;; esac
  # Full typed line from history (BASH_COMMAND is only the first simple cmd).
  _SHELL_LOG_CMD="$(HISTTIMEFORMAT= history 1 | sed 's/^ *[0-9][0-9]*[ *]*//')"
  [[ -z "$_SHELL_LOG_CMD" ]] && { _SHELL_LOG_CMD=; return; }
  _SHELL_LOG_RUNNING=1
  _shell_log_now
  _SHELL_LOG_START_MS=$_NOW_MS
  printf '[%s] START : %s\n' "$_NOW_STAMP" "$_SHELL_LOG_CMD" >> "$SHELL_LOG_FILE"
}

# --- precmd, via PROMPT_COMMAND ---------------------------------------------
# Capture $? FIRST, log END, then draw the right prompt (the IP lookup runs
# subshells, which would otherwise clobber $?).
_shell_precmd() {
  local exit_status=$?
  if [[ -n "$_SHELL_LOG_CMD" ]]; then
    _shell_log_now
    local dms=$(( _NOW_MS - _SHELL_LOG_START_MS ))
    printf '[%s] END   : (exit=%s, %d.%03ds / %dms) %s\n' \
      "$_NOW_STAMP" "$exit_status" "$(( dms / 1000 ))" "$(( dms % 1000 ))" "$dms" "$_SHELL_LOG_CMD" >> "$SHELL_LOG_FILE"
    unset _SHELL_LOG_CMD
  fi
  _SHELL_LOG_RUNNING=
  local chain cols
  chain="$(_prompt_ip_chain)"
  if [[ -n "$chain" ]]; then
    cols=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
    # save cursor; go to column; cyan; chain; reset; restore cursor.
    printf '\e[s\e[%dG\e[36m%s\e[0m\e[u' "$(( cols - ${#chain} + 1 ))" "$chain"
  fi
}

trap '_shell_preexec' DEBUG
# Prepend our precmd FIRST in PROMPT_COMMAND (so $? is captured before anything
# else runs), without duplicating or dropping what's already there.
case ";${PROMPT_COMMAND};" in
  *";_shell_precmd;"*) ;;
  *) PROMPT_COMMAND="_shell_precmd${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
