"""Database utilities for gubbi-common consumers."""

from gubbi_common.db.user_scoped import MissingUserIdError, user_scoped_connection

__all__ = ["MissingUserIdError", "user_scoped_connection"]
