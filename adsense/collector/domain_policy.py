"""Domain password policy and fine-grained policy enumeration."""

from __future__ import annotations

from typing import TYPE_CHECKING

import ldap3

from adsense.analyser.models import (
    DomainPolicyResult,
    FineGrainedPolicy,
    PasswordPolicy,
)
from adsense.collector import (
    get_str,
    get_int,
    get_list,
    filetime_duration_to_days,
    filetime_duration_to_minutes,
)

if TYPE_CHECKING:
    from adsense.connection import LDAPConnection


def enumerate_domain_policy(conn: LDAPConnection) -> DomainPolicyResult:
    """Collect default password policy, fine-grained policies, and MAQ."""
    result = DomainPolicyResult()

    # 1. Default domain password policy (from domain object)
    try:
        entries = conn.search(
            search_base=conn.auth.domain_dn,
            search_filter="(objectClass=domain)",
            attributes=[
                "minPwdLength", "pwdProperties", "lockoutThreshold",
                "lockoutDuration", "lockOutObservationWindow",
                "maxPwdAge", "minPwdAge", "pwdHistoryLength",
                "ms-DS-MachineAccountQuota",
            ],
            search_scope=ldap3.BASE,
        )
    except Exception:
        return result

    if entries:
        entry = entries[0]
        pwd_props = get_int(entry, "pwdProperties")

        result.default_policy = PasswordPolicy(
            min_length=get_int(entry, "minPwdLength"),
            complexity=bool(pwd_props & 1),
            lockout_threshold=get_int(entry, "lockoutThreshold"),
            lockout_duration=filetime_duration_to_minutes(
                get_int(entry, "lockoutDuration")
            ),
            lockout_window=filetime_duration_to_minutes(
                get_int(entry, "lockOutObservationWindow")
            ),
            max_age=filetime_duration_to_days(get_int(entry, "maxPwdAge")),
            min_age=filetime_duration_to_days(get_int(entry, "minPwdAge")),
            history_count=get_int(entry, "pwdHistoryLength"),
        )

        maq = get_int(entry, "ms-DS-MachineAccountQuota")
        result.machine_account_quota = maq if maq is not None else 10

    # 2. Fine-grained password policies
    pso_base = f"CN=Password Settings Container,CN=System,{conn.auth.domain_dn}"
    try:
        fgp_entries = conn.search(
            search_base=pso_base,
            search_filter="(objectClass=msDS-PasswordSettings)",
            attributes=[
                "cn", "msDS-PasswordSettingsPrecedence",
                "msDS-PSOAppliesTo", "msDS-MinimumPasswordLength",
                "msDS-PasswordComplexityEnabled", "msDS-LockoutThreshold",
                "msDS-LockoutDuration", "msDS-MaximumPasswordAge",
                "msDS-MinimumPasswordAge",
            ],
        )
    except Exception:
        fgp_entries = []

    for entry in fgp_entries:
        name = get_str(entry, "cn")
        if not name:
            continue

        applies_to = get_list(entry, "msDS-PSOAppliesTo")
        # Extract just the CN from each DN for readability
        applies_short = []
        for dn in applies_to:
            if dn.upper().startswith("CN="):
                applies_short.append(dn.split(",")[0][3:])
            else:
                applies_short.append(dn)

        complexity_val = get_str(entry, "msDS-PasswordComplexityEnabled")
        complexity = complexity_val.lower() in ("true", "1")

        result.fine_grained.append(FineGrainedPolicy(
            name=name,
            dn=get_str(entry, "distinguishedName") if hasattr(entry, "entry_dn") else "",
            precedence=get_int(entry, "msDS-PasswordSettingsPrecedence"),
            applies_to=applies_short,
            min_length=get_int(entry, "msDS-MinimumPasswordLength"),
            complexity=complexity,
            lockout_threshold=get_int(entry, "msDS-LockoutThreshold"),
            lockout_duration=filetime_duration_to_minutes(
                get_int(entry, "msDS-LockoutDuration")
            ),
            max_age=filetime_duration_to_days(
                get_int(entry, "msDS-MaximumPasswordAge")
            ),
            min_age=filetime_duration_to_days(
                get_int(entry, "msDS-MinimumPasswordAge")
            ),
        ))

    # Sort by precedence
    result.fine_grained.sort(key=lambda p: p.precedence)

    return result
