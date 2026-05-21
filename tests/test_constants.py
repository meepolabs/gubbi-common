"""Tests for shared cross-package constants."""

from __future__ import annotations

from urllib.parse import urlparse

import pytest

from gubbi_common import RESOURCE_DOCUMENTATION_URL as TOP_LEVEL_URL
from gubbi_common.constants import RESOURCE_DOCUMENTATION_URL


class TestResourceDocumentationURL:
    """Public OAuth Protected Resource Metadata docs URL (RFC 9728)."""

    @pytest.mark.unit
    def test_value_matches_published_url(self) -> None:
        # Pinned value -- consumers (gubbi + gubbi-cloud) emit this
        # literal in their /.well-known/oauth-protected-resource payloads,
        # so an accidental rename here would silently break clients.
        # Arrange / Act / Assert
        assert RESOURCE_DOCUMENTATION_URL == "https://gubbi.ai/docs/mcp"

    @pytest.mark.unit
    def test_is_https_url_with_non_empty_host(self) -> None:
        # Arrange
        parsed = urlparse(RESOURCE_DOCUMENTATION_URL)

        # Act / Assert
        assert parsed.scheme == "https"
        assert parsed.netloc != ""

    @pytest.mark.unit
    def test_top_level_reexport_is_same_object(self) -> None:
        # Guards against the top-level package re-export silently
        # diverging from the canonical constants module.
        assert TOP_LEVEL_URL is RESOURCE_DOCUMENTATION_URL
