"""Fail-closed tombstones for the removed parent-owned channel capability."""

from __future__ import annotations

from typing import Any

from ..contracts import PolicyError


def _removed() -> None:
    raise PolicyError(
        "PortCast channel capability was removed; use the reservation-bound broker"
    )


def _issue_portcast_channel_capability(profile: Any) -> None:
    _removed()


def validate_portcast_channel_capability(value: Any, profile: Any) -> None:
    _removed()


__all__ = (
    "_issue_portcast_channel_capability",
    "validate_portcast_channel_capability",
)
