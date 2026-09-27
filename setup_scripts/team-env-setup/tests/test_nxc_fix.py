import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "nxc-fix.sh"
WRAPPER = ROOT / "team-env-setup.sh"


def executable(path, content):
    path.write_text(content)
    path.chmod(0o700)


def test_ce_is_preferred_and_backup_is_only_created_on_change(tmp_path):
    config_dir = tmp_path / "private-nxc"; config_dir.mkdir(mode=0o700)
    config = config_dir / "nxc.conf"; config.write_text("[BloodHound]\nbh_enabled = True\n")
    config.chmod(0o600)
    bindir = tmp_path / "bin"; bindir.mkdir(mode=0o700)
    nxc = bindir / "nxc"; executable(nxc, "#!/bin/sh\nexit 99\n")
    executable(bindir / "python", "#!/bin/sh\ncase \"$*\" in *netexec*) echo 1.2.3; exit 0 ;; *bloodhound-ce*) exit 0 ;; *bloodhound*) exit 0 ;; esac\nexit 1\n")
    environment = os.environ | {"NXC_BIN": str(nxc)}
    user = subprocess.check_output(["id", "-un"], text=True).strip()
    first = subprocess.run([str(HELPER), "--user", user, str(config)], text=True, capture_output=True, env=environment)
    assert first.returncode == 0, first.stderr
    assert "mode: ce" in first.stdout
    assert "bh_enabled = False" in config.read_text()
    assert "bhce_enabled = True" in config.read_text()
    backups = list(config_dir.glob("nxc.conf.bak.*"))
    assert len(backups) == 1 and backups[0].stat().st_mode & 0o777 == 0o600
    second = subprocess.run([str(HELPER), "--user", user, str(config)], text=True, capture_output=True, env=environment)
    assert second.returncode == 0, second.stderr
    assert "unchanged" in second.stdout and list(config_dir.glob("nxc.conf.bak.*")) == backups


def test_helper_refuses_unsafe_permissions_without_printing_content(tmp_path):
    config_dir = tmp_path / "unsafe"; config_dir.mkdir(mode=0o700)
    config = config_dir / "nxc.conf"; config.write_text("secret-value\n"); config.chmod(0o644)
    user = subprocess.check_output(["id", "-un"], text=True).strip()
    bad = subprocess.run([str(HELPER), "--user", user, str(config)], text=True, capture_output=True)
    assert bad.returncode == 1
    assert "permissions are unsafe" in bad.stderr
    assert "secret-value" not in bad.stdout + bad.stderr


def test_helper_changes_only_the_two_collector_values(tmp_path):
    config_dir = tmp_path / "private-nxc"; config_dir.mkdir(mode=0o700)
    original = (
        "# keep this heading exactly\n"
        "[General]\ncustom_spacing  =  keep-me\n\n"
        "[BloodHound]\nother = untouched\nbh_enabled: True  # legacy selector\n\n"
        "[BloodHound-CE]\nbhce_enabled = False ; CE selector\nlast = unchanged\n"
    )
    expected = original.replace("bh_enabled: True", "bh_enabled: False").replace(
        "bhce_enabled = False", "bhce_enabled = True"
    )
    config = config_dir / "nxc.conf"; config.write_text(original); config.chmod(0o600)
    bindir = tmp_path / "bin"; bindir.mkdir(mode=0o700)
    nxc = bindir / "nxc"; executable(nxc, "#!/bin/sh\nexit 99\n")
    executable(bindir / "python", "#!/bin/sh\ncase \"$*\" in *netexec*) echo 1.2.3; exit 0 ;; *bloodhound-ce*) exit 0 ;; esac\nexit 1\n")
    environment = os.environ | {"NXC_BIN": str(nxc)}
    user = subprocess.check_output(["id", "-un"], text=True).strip()

    result = subprocess.run([str(HELPER), "--user", user, str(config)], text=True, capture_output=True, env=environment)
    assert result.returncode == 0, result.stderr
    assert config.read_text() == expected
    backup = next(config_dir.glob("nxc.conf.bak.*"))
    assert backup.read_text() == original


def test_helper_accepts_the_normal_adjacent_python_symlink(tmp_path):
    config_dir = tmp_path / "private-nxc"; config_dir.mkdir(mode=0o700)
    config = config_dir / "nxc.conf"; config.write_text("[BloodHound]\nbh_enabled = True\n")
    config.chmod(0o600)
    bindir = tmp_path / "bin"; bindir.mkdir(mode=0o700)
    nxc = bindir / "nxc"; executable(nxc, "#!/bin/sh\nexit 99\n")
    runtime = bindir / "python-runtime"
    executable(runtime, "#!/bin/sh\ncase \"$*\" in *netexec*) echo 1.2.3; exit 0 ;; *bloodhound-ce*) exit 0 ;; esac\nexit 1\n")
    (bindir / "python3").symlink_to(runtime.name)
    environment = os.environ | {"NXC_BIN": str(nxc)}
    user = subprocess.check_output(["id", "-un"], text=True).strip()

    result = subprocess.run([str(HELPER), "--user", user, str(config)], text=True, capture_output=True, env=environment)
    assert result.returncode == 0, result.stderr
    assert "NetExec version: 1.2.3" in result.stdout


def test_common_setup_entry_point_delegates_to_nxc_fix(tmp_path):
    config_dir = tmp_path / "private-nxc"; config_dir.mkdir(mode=0o700)
    config = config_dir / "nxc.conf"; config.write_text("[BloodHound]\nbh_enabled = True\n")
    config.chmod(0o600)
    bindir = tmp_path / "bin"; bindir.mkdir(mode=0o700)
    nxc = bindir / "nxc"; executable(nxc, "#!/bin/sh\nexit 99\n")
    executable(bindir / "python", "#!/bin/sh\ncase \"$*\" in *netexec*) echo 1.2.3; exit 0 ;; *bloodhound-ce*) exit 0 ;; esac\nexit 1\n")
    environment = os.environ | {"NXC_BIN": str(nxc)}
    user = subprocess.check_output(["id", "-un"], text=True).strip()

    result = subprocess.run(
        [str(WRAPPER), "nxc-fix", "--auto", "--user", user, str(config)],
        text=True, capture_output=True, env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert "NetExec BloodHound mode: ce" in result.stdout
    assert "bhce_enabled = True" in config.read_text()


def test_common_setup_help_lists_nxc_fix():
    result = subprocess.run([str(WRAPPER), "--help"], text=True, capture_output=True)
    assert result.returncode == 0
    assert "nxc-fix" in result.stdout
