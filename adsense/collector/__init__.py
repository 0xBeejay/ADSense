"""Shared LDAP entry helpers for all collectors."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def get_str(entry, attr: str) -> str:
    """Extract string attribute from ldap3 Entry or paged_search dict."""
    try:
        if isinstance(entry, dict):
            val = entry.get("attributes", {}).get(attr, "")
        else:
            val = entry[attr]
            if hasattr(val, "value"):
                val = val.value
        return str(val) if val else ""
    except (KeyError, IndexError, TypeError):
        return ""


def get_int(entry, attr: str) -> int:
    """Extract integer attribute."""
    try:
        if isinstance(entry, dict):
            val = entry.get("attributes", {}).get(attr, 0)
        else:
            val = entry[attr]
            if hasattr(val, "value"):
                val = val.value
        return int(val) if val else 0
    except (KeyError, IndexError, ValueError, TypeError):
        return 0


def get_list(entry, attr: str) -> list[str]:
    """Extract list attribute."""
    try:
        if isinstance(entry, dict):
            val = entry.get("attributes", {}).get(attr, [])
        else:
            val = entry[attr]
            if hasattr(val, "values"):
                return [str(v) for v in val.values]
            if hasattr(val, "value"):
                val = val.value
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)] if val else []
    except (KeyError, IndexError, TypeError):
        return []


def filetime_to_datetime(ft: int) -> datetime | None:
    """Convert Windows FILETIME (100ns intervals since 1601) to datetime."""
    if not ft or ft <= 0 or ft == 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return _WINDOWS_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def filetime_duration_to_minutes(ft: int) -> int:
    """Convert a negative FILETIME duration to minutes."""
    if not ft:
        return 0
    return abs(ft) // 10_000_000 // 60


def filetime_duration_to_days(ft: int) -> int:
    """Convert a negative FILETIME duration to days."""
    if not ft:
        return 0
    return abs(ft) // 10_000_000 // 86400
