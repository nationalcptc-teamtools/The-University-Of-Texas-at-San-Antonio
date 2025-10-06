cp -a ~/.zshrc ~/.zshrc.bak 2>/dev/null || true
cat >> ~/.zshrc <<'EOF'

RPROMPT='[%D{%F %H:%M}]'

export ip_address=$(ip addr show tun0 2>/dev/null | grep -oP '\d+(\.\d+){3}' | head -1); [ -z "$ip_address" ] && ip_address=$(ip addr show eth0 2>/dev/null | grep -oP '\d+(\.\d+){3}' | head -1)

PROMPT="%F{%(#.blue.green)}┌──${debian_chroot:+($debian_chroot)─}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))─}(%B%F{%(#.red.blue)}%n㉿%m%b%F{%(#.blue.green)})-[%B%F{blue}${ip_address}%b%F{%(#.blue.green)}]-[%F{reset}%B%(6~.%-1~/…/%4~.%5~)%b%F{%(#.blue.green)}]
└─%B%(#.%F{red}#.%F{blue}$)%b%F{reset} "
EOF

source ~/.zshrc