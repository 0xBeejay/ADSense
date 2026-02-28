"""Interesting account flag enumeration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from adsense.analyser.models import AccountFlag, AccountFlagType
from adsense.collector import get_str, get_int, filetime_to_datetime

if TYPE_CHECKING:
    from adsense.connection import LDAPConnection


_COMMON_ATTRS = [
    "sAMAccountName", "userAccountControl", "adminCount",
    "description", "whenCreated",
]


def enumerate_account_flags(conn: LDAPConnection) -> list[AccountFlag]:
    """Find accounts with interesting security-relevant flags."""
    results: list[AccountFlag] = []

    # 1. PASSWD_NOTREQD (UAC 0x20)
    results.extend(_query_flag(
        conn,
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=32))",
        AccountFlagType.PASSWD_NOTREQD,
    ))

    # 2. PASSWORD_NEVER_EXPIRES (UAC 0x10000)
    results.extend(_query_flag(
        conn,
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        AccountFlagType.PASSWORD_NEVER_EXPIRES,
    ))

    # 3. adminCount=1
    results.extend(_query_flag(
        conn,
        "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
        AccountFlagType.ADMIN_COUNT,
    ))

    # 4. Recently created (last 30 days)
    thirty_days_ago = datetime.now(timezone.utc).strftime("%Y%m%d000000.0Z")
    # Calculate actual 30 days ago
    from datetime import timedelta
    actual_30d = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
        "%Y%m%d%H%M%S.0Z"
    )
    results.extend(_query_flag(
        conn,
        f"(&(objectCategory=person)(objectClass=user)"
        f"(whenCreated>={actual_30d}))",
        AccountFlagType.RECENTLY_CREATED,
    ))

    # 5. Disabled privileged (adminCount=1 + disabled)
    results.extend(_query_flag(
        conn,
        "(&(objectCategory=person)(objectClass=user)(adminCount=1)"
        "(userAccountControl:1.2.840.113556.1.4.803:=2))",
        AccountFlagType.DISABLED_PRIVILEGED,
    ))

    # 6. Service accounts (naming patterns + SPN holders)
    results.extend(_query_flag(
        conn,
        "(&(objectCategory=person)(objectClass=user)"
        "(|(sAMAccountName=svc_*)(sAMAccountName=svc-*)"
        "(sAMAccountName=sa_*)(sAMAccountName=sa-*)"
        "(sAMAccountName=service_*)(sAMAccountName=service-*))"
        "(!(sAMAccountName=krbtgt)))",
        AccountFlagType.SERVICE_ACCOUNT,
    ))

    return results


def _query_flag(
    conn: LDAPConnection,
    search_filter: str,
    flag_type: AccountFlagType,
) -> list[AccountFlag]:
    """Run a single flag query and return AccountFlag objects."""
    try:
        entries = conn.search(
            search_base=conn.auth.domain_dn,
            search_filter=search_filter,
            attributes=_COMMON_ATTRS,
        )
    except Exception:
        return []

    results = []
    for entry in entries:
        sam = get_str(entry, "sAMAccountName")
        if not sam:
            continue

        uac = get_int(entry, "userAccountControl")

        # whenCreated comes as a datetime string from AD, not FILETIME
        created = None
        created_raw = get_str(entry, "whenCreated")
        if created_raw:
            try:
                # ldap3 may return datetime objects directly
                val = entry["whenCreated"]
                if hasattr(val, "value") and isinstance(val.value, datetime):
                    created = val.value
            except (KeyError, TypeError):
                pass

        results.append(AccountFlag(
            samaccountname=sam,
            flag_type=flag_type,
            admin_count=get_int(entry, "adminCount"),
            enabled=not bool(uac & 0x2),
            description=get_str(entry, "description"),
            created_date=created,
        ))

    return results
