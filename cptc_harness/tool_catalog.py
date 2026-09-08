"""Reviewed local tool pins. Discovery never admits an unknown executable."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from .contracts import PolicyError

CATALOG = Path(__file__).parent / "resources" / "tool-catalog.json"


def verified_resource(name: str) -> Path:
    try:
        manifest = json.loads(CATALOG.read_bytes())
        path = CATALOG.parent / name
        if Path(name).is_absolute() or ".." in Path(name).parts or path.is_symlink():
            raise ValueError()
        if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["resources"][name]:
            raise ValueError()
        return path
    except (OSError, ValueError, KeyError):
        raise PolicyError("passive scanner resource differs from reviewed release") from None


def _entries() -> list[dict]:
    try:
        value = json.loads(CATALOG.read_bytes())
        if value["version"] != 1 or not isinstance(value["tools"], list):
            raise ValueError()
        return value["tools"]
    except (OSError, ValueError, KeyError):
        raise PolicyError("reviewed native tool catalog unavailable") from None


def verified_native_file(name: str) -> Path:
    item = next((item for item in _entries() if item["tool_id"] == name), None)
    if item is None or item.get("admission") != "fixture_tested":
        raise PolicyError("native tool has no reviewed admission")
    path = Path(item["path"])
    try:
        if not path.is_absolute() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise PolicyError("native tool differs from reviewed deployment pin")
        root = path.parent
        if item.get("tree") and {str(child.relative_to(root)) for child in root.rglob("*") if child.is_file()} != set(item["tree"]):
            raise PolicyError("native tool tree contains unreviewed files")
        for relative, expected in item.get("tree", {}).items():
            child = root / relative
            if Path(relative).is_absolute() or ".." in Path(relative).parts or child.is_symlink():
                raise PolicyError("invalid native tool tree")
            if hashlib.sha256(child.read_bytes()).hexdigest() != expected:
                raise PolicyError("native tool dependency differs from release pin")
        for tree in item.get("runtime_trees", []):
            tree_root = Path(tree["root"])
            entries = {str(child.relative_to(tree_root)): child for child in tree_root.rglob("*") if child.is_file() or child.is_symlink()}
            if set(entries) != set(tree["files"]) | set(tree["symlinks"]):
                raise PolicyError("native runtime closure contains unreviewed files")
            for name, child in entries.items():
                if name in tree["symlinks"]:
                    if not child.is_symlink() or os.readlink(child) != tree["symlinks"][name]:
                        raise PolicyError("native runtime dependency link changed")
                elif child.is_symlink() or hashlib.sha256(child.read_bytes()).hexdigest() != tree["files"][name]:
                    raise PolicyError("native runtime dependency changed")
        return path
    except (OSError, KeyError):
        raise PolicyError("pinned native tool is unavailable") from None


def verified_java_root() -> Path:
    verified_native_file("java")
    item = next(item for item in _entries() if item["tool_id"] == "java")
    try:
        root = Path(item["runtime_trees"][0]["root"])
        if not root.is_absolute() or root.is_symlink() or not (root / "bin/java").is_file():
            raise ValueError()
        return root
    except (KeyError, IndexError, ValueError):
        raise PolicyError("reviewed Java runtime closure unavailable") from None


def catalog_status() -> list[dict]:
    rows = []
    for item in _entries():
        available = Path(item["path"]).is_file()
        pinned = False
        try:
            verified_native_file(item["tool_id"])
            pinned = True
        except PolicyError:
            pass
        rows.append({key: item[key] for key in ("tool_id", "version", "mode", "profiles", "network", "admission", "reason")}
                    | {"available": available, "pinned": pinned,
                       "admitted": pinned and item["admission"] == "fixture_tested",
                       "live_validation": "unverified"})
    return rows
