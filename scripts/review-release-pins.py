#!/usr/bin/env python3
"""Check deployment pins offline, or write a separate candidate for human review."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--propose", type=Path, help="Write a NEW candidate; does not admit or replace the release manifest")
    args = parser.parse_args()
    package = Path(__file__).resolve().parents[1] / "cptc_harness"
    manifest_path = package / "resources/release-integrity.json"
    manifest = json.loads(manifest_path.read_text())
    candidate = {"version": manifest["version"], "workers": {}, "executables": {}}
    results = []
    for group in ("workers", "executables"):
        for name, expected in manifest[group].items():
            path = package / name if group == "workers" else Path(name)
            try:
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if group == "workers" and (Path(name).name != name or path.is_symlink()):
                    raise ValueError("worker path is not an ordinary release file")
            except (OSError, ValueError):
                results.append({"kind": group, "name": name, "status": "unavailable"})
                continue
            candidate[group][name] = actual
            results.append({"kind": group, "name": name, "status": "match" if actual == expected else "changed",
                            "expected_sha256": expected, "observed_sha256": actual})
    sys.path.insert(0, str(package.parent))
    from cptc_harness.tool_catalog import catalog_status, verified_resource
    for row in catalog_status():
        results.append({"kind": "native_tools", "name": row["tool_id"], "status": "match" if row["admitted"] else "unavailable_or_unadmitted"})
    native_manifest = json.loads((package / "resources/tool-catalog.json").read_bytes())
    for name in native_manifest.get("resources", {}):
        try:
            verified_resource(name)
            status = "match"
        except Exception:
            status = "changed_or_unavailable"
        results.append({"kind": "scanner_resources", "name": name, "status": status})
    if args.propose:
        if any(result["status"] == "unavailable" for result in results):
            parser.error("Cannot propose a partial manifest; resolve unavailable files first")
        destination = args.propose.absolute()
        if any(p.is_symlink() for p in (destination, *destination.parents)) or destination == manifest_path:
            parser.error("Choose a separate, non-symlink candidate file")
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(candidate, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    print(json.dumps({"offline": True, "admitted_manifest_changed": False, "files": results,
                      "candidate": str(args.propose) if args.propose else None,
                      "next_step": "Review provenance and changes, then repeat acceptance before any manual admission."}, indent=2))
    return 0 if all(result["status"] == "match" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
