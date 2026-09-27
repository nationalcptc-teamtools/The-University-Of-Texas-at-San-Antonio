from __future__ import annotations

import inspect

import pytest

from cptc_harness.contracts import PolicyError
from cptc_harness.profile_runtime import capability
from cptc_harness.profile_runtime.catalog import load_profile


def test_legacy_channel_capability_is_an_import_compatible_tombstone():
    profile = load_profile("web.http_jellyfin_public_identity")

    with pytest.raises(PolicyError, match="removed"):
        capability.validate_portcast_channel_capability(object(), profile)
    with pytest.raises(PolicyError, match="removed"):
        capability._issue_portcast_channel_capability(profile)


def test_tombstone_accepts_no_callable_and_exposes_no_channel_method():
    signature = inspect.signature(capability._issue_portcast_channel_capability)
    assert tuple(signature.parameters) == ("profile",)
    assert not hasattr(capability, "PortcastChannelCapability")
