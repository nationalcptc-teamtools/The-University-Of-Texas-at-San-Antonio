"""Non-live tests for the human NetExec/BloodHound configuration helper."""
from pathlib import Path
import configparser
import hashlib
import os
import subprocess


ROOT = Path(__file__).parents[1]
HELPER = ROOT / "scripts" / "fix-nxc-bloodhound-config.sh"
ROOT_HELPER = ROOT / "nxc-fix.sh"


def test_root_helper_is_the_executable_canonical_copy():
    canonical = HELPER.read_bytes()
    root_copy = ROOT_HELPER.read_bytes()
    assert root_copy == canonical
    assert hashlib.sha256(root_copy).hexdigest() == hashlib.sha256(canonical).hexdigest()
    assert ROOT_HELPER.stat().st_mode & 0o111
    completed = subprocess.run(
        [str(ROOT_HELPER), "--help"], text=True, capture_output=True, timeout=10
    )
    assert completed.returncode == 0, completed.stderr
    usage = completed.stdout + completed.stderr
    assert "--ce" in usage and "--legacy" in usage


def _environment(tmp_path):
    binary = tmp_path / "bin"
    binary.mkdir()
    for name, body in (("nxc", "#!/bin/sh\nexit 0\n"), ("python", "#!/bin/sh\nexit 0\n")):
        path = binary / name
        path.write_text(body); path.chmod(0o755)
    return {"PATH": str(binary) + ":/usr/bin", "HOME": str(tmp_path), "LANG": "C.UTF-8"}


def _config(tmp_path):
    path = tmp_path / "nxc.conf"
    path.write_text("[Other]\nkeep = yes\n[BloodHound]\nbh_enabled = True\n")
    path.chmod(0o600)
    return path


def test_helper_switches_modes_preserves_other_values_and_creates_unique_backups(tmp_path):
    config = _config(tmp_path); environment = _environment(tmp_path)
    for mode, expected in (("--ce", ("False", "True")), ("--legacy", ("True", "False"))):
        completed = subprocess.run([str(HELPER), mode, str(config)], env=environment,
                                   text=True, capture_output=True, timeout=10)
        assert completed.returncode == 0, completed.stderr
        parser = configparser.ConfigParser(interpolation=None); parser.read(config)
        assert parser.get("Other", "keep") == "yes"
        assert (parser.get("BloodHound", "bh_enabled"),
                parser.get("BloodHound-CE", "bhce_enabled")) == expected
        assert "Active nxc:" in completed.stdout and "Backup:" in completed.stdout
    backups = list(tmp_path.glob("nxc.conf.bak.*"))
    assert len(backups) == 2 and len({path.name for path in backups}) == 2
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in backups)


def test_helper_rejects_symlinked_config_without_changing_target(tmp_path):
    target = _config(tmp_path); original = target.read_bytes()
    link = tmp_path / "linked.conf"; link.symlink_to(target)
    completed = subprocess.run([str(HELPER), "--ce", str(link)], env=_environment(tmp_path),
                               text=True, capture_output=True, timeout=10)
    assert completed.returncode == 1 and "symlinked" in completed.stderr
    assert target.read_bytes() == original and not list(tmp_path.glob("linked.conf.bak.*"))
