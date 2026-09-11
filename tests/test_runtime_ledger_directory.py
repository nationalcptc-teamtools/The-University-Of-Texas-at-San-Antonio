from __future__ import annotations

import os
from pathlib import Path

import pytest

from cptc_harness.contracts import PolicyError, PolicySnapshot, ScopeSpec
from cptc_harness.policy import save_policy
from cptc_harness.runtime import Runtime, initialize


_RECIPIENT = "age1c6wmzkphupzx0se6jvsra4z43gdsdnl5yn5umy23lxjsae2fc5xqz9vh0r"


def _workspace(
    tmp_path: Path, engagement_id: str, *, workspace_id: str = "workspace"
) -> Path:
    source = tmp_path / f"{engagement_id}-policy.json"
    save_policy(
        source,
        PolicySnapshot(
            engagement_id,
            "runtime-ledger-directory-v1",
            workspace_id,
            "arch-btw",
            "operator",
            ScopeSpec(),
            encrypted_storage=True,
        ),
    )
    root = tmp_path / f"{engagement_id}-runtime"
    initialize(
        root,
        source,
        recipient=_RECIPIENT,
        age_binary=Path(__file__).parents[1] / ".tools/age",
    )
    return root


def test_runtime_can_share_one_exact_ledger_directory_across_engagements(tmp_path):
    first = Runtime(
        _workspace(tmp_path, "engagement-one"),
        ledger_root=tmp_path / "ledger-container",
    )
    try:
        ledger_directory = first.ledger_root
        inode = os.stat(first.ledger.path)
        enrollment = first.ledger._db.execute(
            "SELECT * FROM workspace_enrollment WHERE workspace_id=?",
            ("workspace",),
        ).fetchone()
        first.ledger.stop("synthetic predecessor stop")
        second = Runtime(
            _workspace(tmp_path, "engagement-two"),
            ledger_directory=ledger_directory,
        )
        try:
            assert first.ledger_root == ledger_directory.absolute()
            assert second.ledger_root == ledger_directory.absolute()
            assert second.ledger.path == first.ledger.path
            assert os.stat(second.ledger.path).st_ino == inode.st_ino
            assert second.ledger._db.execute(
                "SELECT reason FROM stops WHERE engagement=?",
                ("engagement-one",),
            ).fetchone() == ("synthetic predecessor stop",)
            assert second.ledger._db.execute(
                "SELECT * FROM workspace_enrollment WHERE workspace_id=?",
                ("workspace",),
            ).fetchone() == enrollment
        finally:
            second.close()
    finally:
        first.close()


def test_runtime_rejects_conflicting_ledger_location_options(tmp_path):
    workspace = _workspace(tmp_path, "conflicting-ledger-options")
    ledger_root = tmp_path / "ledger-root"
    ledger_directory = tmp_path / "ledger-directory"
    ledger_directory.mkdir(mode=0o700)

    with pytest.raises(PolicyError, match="ledger"):
        Runtime(
            workspace,
            ledger_root=ledger_root,
            ledger_directory=ledger_directory,
        )


@pytest.mark.parametrize("kind", ("missing", "symlink", "group-readable"))
def test_runtime_requires_existing_owner_only_nonsymlink_ledger_directory(
    tmp_path, kind
):
    workspace = _workspace(tmp_path, f"unsafe-ledger-{kind}")
    ledger_directory = tmp_path / "shared-ledger"
    if kind == "symlink":
        target = tmp_path / "target-ledger"
        target.mkdir(mode=0o700)
        ledger_directory.symlink_to(target, target_is_directory=True)
    elif kind == "group-readable":
        ledger_directory.mkdir(mode=0o750)

    with pytest.raises(PolicyError):
        Runtime(workspace, ledger_directory=ledger_directory)
