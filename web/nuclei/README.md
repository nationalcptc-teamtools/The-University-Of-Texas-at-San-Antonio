# Nuclei templates

From the repository root, copy the YAML files into Nuclei's template directory.
Use `-t` to run only this pack. Put one approved URL or `host:port` on each
line of the target file.

```bash
CUSTOM="$HOME/nuclei-templates/custom/host-exposure-audit"
mkdir -p "$CUSTOM"
cp nuclei/*.yaml "$CUSTOM/"

TARGETS="$HOME/private/targets.txt"

# Identify products.
nuclei -l "$TARGETS" -t "$CUSTOM" -tags detection -duc -ni -rl 5 -c 2 -bs 2

# Check exposed services.
nuclei -l "$TARGETS" -t "$CUSTOM" -tags exposure -duc -ni -rl 5 -c 2 -bs 2

# Identify OT services at a low rate.
nuclei -l "$TARGETS" -t "$CUSTOM" -tags ot -duc -ni \
  -rl 1 -c 1 -bs 1 -mhe 3 -timeout 10 -retries 0 -rsr 262144
```

## Sorting by technology

Every template carries a `themepark` tag, so `-tags themepark` selects the
whole pack. Filter by domain by adding the domain tag:

| Tag | Selects |
|---|---|
| `detection` | fingerprint only — what is this box |
| `exposure` | unauthenticated data/config exposure |
| `attack` | default-credential logins and takeover surfaces |
| `cve` | CVE-specific checks (2025/2026 focus) |
| `ot` | ride control, SCADA, PLC, BMS, gate/OT protocols |
| `pos` | point of sale, food service, kitchen display |
| `wifi` | captive portals, controllers, guest Wi-Fi |
| `cms` | WordPress/Joomla/Strapi/Ghost/Directus class |
| `commerce` | PrestaShop/Magento storefronts, payments |
| `hr` | employee self-service, payroll |
| `ticketing` | support/remediation backends |
| `booking` | reservations and scheduling |
| `parking` | parking operations |
| `signage` | digital signage players and CMS |
| `secops` | vulnerability managers, Nessus/Tenable |
| `notifications` | ntfy/Gotify push and emergency alerting |
| `data` | databases, caches, message queues |
| `devops` | CI/CD, registries, GitOps |
| `monitoring` | Grafana, Prometheus, Zabbix, uptime |
| `infrastructure` | virtualisation, asset, reverse proxies |
| `identity` | SSO, LDAP, secrets |
| `remote-management` | Cockpit, Portainer, consoles |
| `mobile` | mobile-app backend APIs |
| `default-login` | documented vendor default-credential attempts |
| `version` | unauthenticated version disclosure probes |

Examples:

```bash
# POS templates (detection + attack together).
nuclei -l "$TARGETS" -t "$CUSTOM" -tags pos -duc -ni

# OT detection at OT-safe rate.
nuclei -l "$TARGETS" -t "$CUSTOM" -tags ot -duc -ni \
  -rl 1 -c 1 -bs 1 -mhe 3 -timeout 10 -retries 0

# Everything CVE-related regardless of domain.
nuclei -l "$TARGETS" -t "$CUSTOM" -tags cve -duc -ni
```

Nuclei's `-tags` filter is OR: `-tags pos,attack` runs templates matching either.
For a single axis use one tag: `-tags pos` (everything POS, including its attack
templates), `-tags attack` (every attack template), `-tags cve` (every CVE).
To exclude a domain: `-tags attack -exclude-tags ot,wifi`.

A match is a lead, not a confirmed vulnerability. See [profiles](../docs/nuclei-profiles.md) for limits.
