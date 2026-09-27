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

A match is a lead, not a confirmed vulnerability. See [profiles](../docs/nuclei-profiles.md) for limits.
