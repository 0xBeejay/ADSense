"""Kerberoastable account enumeration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from adsense.analyser.models import KerberoastableAccount
from adsense.collector import get_str, get_int, get_list, filetime_to_datetime

if TYPE_CHECKING:
    from adsense.connection import LDAPConnection


def enumerate_kerberoastable(
    conn: LDAPConnection,
    protected_users_dn: str = "",
) -> list[KerberoastableAccount]:
    """Find user accounts with SPNs set (Kerberoastable)."""
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        "(servicePrincipalName=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(sAMAccountName=krbtgt)))"
    )
    attributes = [
        "sAMAccountName", "servicePrincipalName", "adminCount",
        "pwdLastSet", "description", "objectClass", "memberOf",
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

        obj_classes = get_list(entry, "objectClass")
        member_of = get_list(entry, "memberOf")

        results.append(KerberoastableAccount(
            samaccountname=sam,
            spns=get_list(entry, "servicePrincipalName"),
            admin_count=get_int(entry, "adminCount"),
            pwd_last_set=filetime_to_datetime(get_int(entry, "pwdLastSet")),
            description=get_str(entry, "description"),
            in_protected_users=protected_users_dn.lower() in [
                m.lower() for m in member_of
            ] if protected_users_dn else False,
            is_gmsa="msDS-GroupManagedServiceAccount" in obj_classes,
        ))

    return results
