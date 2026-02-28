"""AS-REP roastable account enumeration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from adsense.analyser.models import ASREPAccount
from adsense.collector import get_str, get_int, get_list, filetime_to_datetime

if TYPE_CHECKING:
    from adsense.connection import LDAPConnection


def enumerate_asrep(
    conn: LDAPConnection,
    protected_users_dn: str = "",
) -> list[ASREPAccount]:
    """Find accounts with DONT_REQUIRE_PREAUTH set."""
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    )
    attributes = [
        "sAMAccountName", "userAccountControl", "adminCount",
        "pwdLastSet", "description", "memberOf",
    ]

    try:
        entries = conn.search(
            search_base=conn.auth.domain_dn,
            search_filter=search_filter,
            attributes=attributes,
        )
    except Exception:
        return []

    results = []
    for entry in entries:
        sam = get_str(entry, "sAMAccountName")
        if not sam:
            continue

        uac = get_int(entry, "userAccountControl")
        member_of = get_list(entry, "memberOf")

        results.append(ASREPAccount(
            samaccountname=sam,
            enabled=not bool(uac & 0x2),
            admin_count=get_int(entry, "adminCount"),
            pwd_last_set=filetime_to_datetime(get_int(entry, "pwdLastSet")),
            description=get_str(entry, "description"),
            in_protected_users=protected_users_dn.lower() in [
                m.lower() for m in member_of
            ] if protected_users_dn else False,
        ))

    return results
