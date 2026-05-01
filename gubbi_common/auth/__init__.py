"""Auth primitives shared by journalctl and journalctl-cloud."""

from gubbi_common.auth.bearer_challenge import build_bearer_challenge

__all__ = ["build_bearer_challenge"]
