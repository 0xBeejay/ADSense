"""LAPS deployment detection and password readability check."""

from __future__ import annotations

from typing import TYPE_CHECKING

from adsense.analyser.models import LAPSStatus
from adsense.collector import get_str

if TYPE_CHECKING:
    from adsense.connection import LDAPConnection


def enumerate_laps(conn: LDAPConnection) -> LAPSStatus:
    """Check LAPS schema, deployment coverage, and readable passwords."""
    status = LAPSStatus()

    # 1. Get schema naming context from rootDSE
    schema_nc = ""
    if conn.conn and conn.conn.server.info:
        try:
            schema_nc = conn.conn.server.info.other.get(
                "schemaNamingContext", [""]
            )[0]
        except (AttributeError, IndexError, TypeError):
            pass

    if not schema_nc:
        schema_nc = f"CN=Schema,CN=Configuration,{conn.auth.domain_dn}"

    # 2. Check for legacy LAPS schema (ms-Mcs-AdmPwd)
    try:
        legacy_check = conn.search(
            search_base=schema_nc,
            search_filter="(&(objectClass=attributeSchema)(lDAPDisplayName=ms-Mcs-AdmPwd))",
            attributes=["lDAPDisplayName"],
        )
        if legacy_check:
            status.legacy_laps = True
            status.deployed = True
    except Exception:
        pass

    # 3. Check for Windows LAPS schema (msLAPS-Password)
    try:
        win_check = conn.search(
            search_base=schema_nc,
            search_filter="(&(objectClass=attributeSchema)(lDAPDisplayName=msLAPS-Password))",
            attributes=["lDAPDisplayName"],
        )
        if win_check:
            status.windows_laps = True
            status.deployed = True
    except Exception:
        pass

    if not status.deployed:
        return status

    # 4. Count total computers
    try:
        total_entries = conn.paged_search(
            search_base=conn.auth.domain_dn,
            search_filter="(objectClass=computer)",
            attributes=["cn"],
        )
        status.total_computers = len(total_entries)
    except Exception:
        pass

    # 5. Count LAPS-configured computers and check readability
    if status.legacy_laps:
        _check_laps_attribute(
            conn, status,
            expiry_attr="ms-Mcs-AdmPwdExpirationTime",
            password_attr="ms-Mcs-AdmPwd",
        )

    if status.windows_laps:
        _check_laps_attribute(
            conn, status,
            expiry_attr="msLAPS-PasswordExpirationTime",
            password_attr="msLAPS-Password",
        )

    return status


def _check_laps_attribute(
    conn: LDAPConnection,
    status: LAPSStatus,
    expiry_attr: str,
    password_attr: str,
):
    """Check LAPS coverage and readable passwords for a given attribute set."""
    # Count computers with LAPS configured (expiry time set = LAPS manages them)
    try:
        configured = conn.paged_search(
            search_base=conn.auth.domain_dn,
            search_filter=f"(&(objectClass=computer)({expiry_attr}=*))",
            attributes=["sAMAccountName", password_attr, expiry_attr],
        )
        status.laps_configured_count += len(configured)

        # Check if passwords are readable
        for entry in configured:
            attrs = entry.get("attributes", {})
            password = attrs.get(password_attr, "")
            if password:
                computer = attrs.get("sAMAccountName", "")
                expiry = attrs.get(expiry_attr, "")
                status.readable_passwords.append({
                    "computer": str(computer).rstrip("$"),
                    "password": str(password),
                    "expiry": str(expiry),
                })
    except Exception:
        pass
