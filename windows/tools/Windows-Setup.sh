# Replace existing CPTC block with a two-line Kali-style prompt (with IP)
sed -i '/# CPTC_HISTORY_PROMPT_START/,/# CPTC_HISTORY_PROMPT_END/d' ~/.zshrc

tee -a ~/.zshrc >/dev/null <<'ZSHCFG'
# CPTC_HISTORY_PROMPT_START
export HISTSIZE=100000
export SAVEHIST=100000
setopt PROMPT_SUBST

# Optional: force an interface (e.g., tun0). Otherwise auto-detect.
# export CPTC_IFACE=eth0

__cptc_ip() {
  local dev ipaddr
  if [[ -n "${CPTC_IFACE:-}" ]]; then
    dev="${CPTC_IFACE}"
  else
    dev="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  fi
  [[ -n "$dev" ]] && ipaddr="$(ip -o -4 addr show dev "$dev" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  [[ -z "$ipaddr" ]] && ipaddr="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "${ipaddr:-no-ip}"
}

# --- Two-line Kali-style prompt with IP next to host ---
# Looks like: 
# ┌──(user㉿host 10.1.2.3)-[~/dir]
# └─$
PROMPT=$'┌──(%n㉿%m '$(__cptc_ip)$')-[%~]\n└─$ '
# If you want color, use this instead (uncomment next line and comment the line above):
# PROMPT=$'%F{15}┌──(%f%F{10}%n%f㉿%F{12}%m%f %F{14}$(__cptc_ip)%f%F{15})-[%f%F{11}%~%f%F{15}]\n%f└─$ '

# CPTC_HISTORY_PROMPT_END
ZSHCFG

# Reload zsh (or just open a new terminal)
exec zsh
