"""Computer account overview and OS breakdown."""

from __future__ import annotations

from typing import TYPE_CHECKING

from adsense.analyser.models import ComputerInfo
from adsense.collector import get_str, get_int

if TYPE_CHECKING:
    from adsense.connection import LDAPConnection

_OLD_OS_PATTERNS = [
    "Windows Server 2003",
    "Windows Server 2008",
    "Windows Server 2012",
    "Windows XP",
    "Windows 7",
    "Windows Vista",
    "Windows 8",
]


def enumerate_computers(conn: LDAPConnection) -> ComputerInfo:
    """Collect computer statistics: counts, OS breakdown, DCs, old OS."""
    info = ComputerInfo()

    try:
        entries = conn.paged_search(
            search_base=conn.auth.domain_dn,
            search_filter="(objectClass=computer)",
            attributes=[
                "sAMAccountName", "operatingSystem",
                "userAccountControl",
            ],
        )
    except Exception:
        return info

    info.total = len(entries)
    os_counts: dict[str, int] = {}

    for entry in entries:
        attrs = entry.get("attributes", {})
        sam = str(attrs.get("sAMAccountName", ""))
        os_name = str(attrs.get("operatingSystem", "") or "Unknown")
        uac = int(attrs.get("userAccountControl", 0) or 0)

        # Enabled/disabled
        if uac & 0x2:
            info.disabled += 1
        else:
            info.enabled += 1

        # OS breakdown
        os_counts[os_name] = os_counts.get(os_name, 0) + 1

        # Domain controllers (SERVER_TRUST 0x2000)
        is_dc = bool(uac & 0x2000)
        if is_dc:
            info.dcs.append(sam.rstrip("$"))

        # Unconstrained delegation (0x80000), exclude DCs
        if (uac & 0x80000) and not is_dc:
            info.unconstrained.append(sam.rstrip("$"))

        # Old OS check
        for pattern in _OLD_OS_PATTERNS:
            if pattern.lower() in os_name.lower():
                info.old_os.append({
                    "name": sam.rstrip("$"),
                    "os": os_name,
                })
                break

    # Sort OS breakdown by count descending
    info.os_breakdown = dict(
        sorted(os_counts.items(), key=lambda x: x[1], reverse=True)
    )

    return info
