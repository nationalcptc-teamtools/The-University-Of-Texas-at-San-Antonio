"""Synthetic frozen-wave factory for package-2 tests."""

from cptc11_readonly_wave_v1.catalog import PLAN_ID, plan_actions
from cptc11_readonly_wave_v1.contracts import FrozenWaveApproval, build_frozen_wave


def make_wave(*, engagement_id: str = "eng", device_id: str = "dev", workspace_id: str = "ws",
              actions=None) -> FrozenWaveApproval:
    selected = tuple(actions or plan_actions(PLAN_ID))
    return build_frozen_wave(
        engagement_id=engagement_id, device_id=device_id, workspace_id=workspace_id,
        plan_id=PLAN_ID, catalog_sha256=selected[0].catalog_sha256,
        policy_sha256="a" * 64, release_sha256="b" * 64, actions=selected,
        approval_id="approval", operator="captain", approved_at="2026-01-01T00:00:00.000000Z",
    )
