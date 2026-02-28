"""Non-default group enumeration with recursive member resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from adsense.analyser.models import (
    DomainGroup,
    GroupCategory,
    GroupMember,
    GroupScope,
    MemberType,
)
from adsense.collector import get_str, get_int, get_list

if TYPE_CHECKING:
    from adsense.connection import LDAPConnection

# Well-known default AD groups to filter out (case-insensitive)
DEFAULT_GROUPS = frozenset({
    "domain users", "domain computers", "domain admins",
    "enterprise admins", "schema admins", "domain controllers",
    "group policy creator owners", "dns admins", "dnsadmins",
    "dnsupdateproxy", "ras and ias servers",
    "enterprise read-only domain controllers",
    "read-only domain controllers", "cloneable domain controllers",
    "protected users", "key admins", "enterprise key admins",
    "cert publishers", "allowed rodc password replication group",
    "denied rodc password replication group",
    "domain guests", "guests", "users", "administrators",
    "print operators", "backup operators", "replicator",
    "remote desktop users", "network configuration operators",
    "performance monitor users", "performance log users",
    "distributed com users", "iis_iusrs",
    "cryptographic operators", "event log readers",
    "certificate service dcom access",
    "terminal server license servers",
    "incoming forest trust builders",
    "windows authorization access group",
    "pre-windows 2000 compatible access",
    "account operators", "server operators",
    "access control assistance operators",
    "remote management users", "storage replica administrators",
    "hyper-v administrators",
})

_MAX_MEMBERS_DISPLAY = 100
_MAX_NESTING_DEPTH = 5


def enumerate_groups(conn: LDAPConnection) -> list[DomainGroup]:
    """Enumerate non-default domain groups with members."""
    try:
        entries = conn.paged_search(
            search_base=conn.auth.domain_dn,
            search_filter="(objectClass=group)",
            attributes=[
                "sAMAccountName", "distinguishedName",
                "groupType", "member",
            ],
        )
    except Exception:
        return []

    # DN -> resolved GroupMember cache (avoid re-querying same member)
    member_cache: dict[str, GroupMember] = {}
    results: list[DomainGroup] = []

    for entry in entries:
        attrs = entry.get("attributes", {})
        name = str(attrs.get("sAMAccountName", ""))
        if not name:
            continue

        # Skip default groups
        if name.lower() in DEFAULT_GROUPS:
            continue

        dn = str(attrs.get("distinguishedName", ""))
        group_type = int(attrs.get("groupType", 0) or 0)

        scope = _parse_scope(group_type)
        category = (
            GroupCategory.SECURITY
            if group_type & 0x80000000
            else GroupCategory.DISTRIBUTION
        )

        # Get direct member DNs
        member_dns = attrs.get("member", [])
        if isinstance(member_dns, str):
            member_dns = [member_dns]

        # Resolve members (recursively for nested groups)
        resolved_members: list[GroupMember] = []
        visited_groups: set[str] = {dn.lower()}
        _resolve_members(
            conn, member_dns, resolved_members,
            member_cache, visited_groups, depth=0,
        )

        total_count = len(resolved_members)

        # Truncate display if too many
        display_members = resolved_members[:_MAX_MEMBERS_DISPLAY]

        results.append(DomainGroup(
            name=name,
            dn=dn,
            scope=scope,
            category=category,
            members=display_members,
            member_count=total_count,
        ))

    # Sort: security groups first, then by member count descending
    results.sort(key=lambda g: (
        g.category != GroupCategory.SECURITY,
        -g.member_count,
    ))

    return results


def _resolve_members(
    conn: LDAPConnection,
    member_dns: list,
    resolved: list[GroupMember],
    cache: dict[str, GroupMember],
    visited_groups: set[str],
    depth: int,
):
    """Recursively resolve member DNs to GroupMember objects."""
    if depth > _MAX_NESTING_DEPTH:
        return

    for dn in member_dns:
        dn = str(dn)
        dn_lower = dn.lower()

        # Foreign security principal (cross-domain SID)
        if dn_lower.startswith("cn=s-1-5-"):
            sid = dn.split(",")[0][3:]  # Extract SID from CN=S-1-5-...
            resolved.append(GroupMember(
                samaccountname=sid,
                dn=dn,
                member_type=MemberType.FOREIGN,
            ))
            continue

        # Check cache
        if dn_lower in cache:
            member = cache[dn_lower]
            if member.member_type == MemberType.GROUP:
                # Don't add the group itself, but check if we should recurse
                if dn_lower not in visited_groups:
                    visited_groups.add(dn_lower)
                    _resolve_nested_group(
                        conn, dn, resolved, cache,
                        visited_groups, depth + 1,
                    )
            else:
                resolved.append(member)
            continue

        # Query LDAP for this member
        try:
            entries = conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                attributes=["sAMAccountName", "objectClass"],
                search_scope="BASE",
            )
        except Exception:
            resolved.append(GroupMember(
                samaccountname=dn.split(",")[0][3:] if dn.startswith("CN=") else dn,
                dn=dn,
                member_type=MemberType.UNKNOWN,
            ))
            continue

        if not entries:
            continue

        sam = get_str(entries[0], "sAMAccountName")
        obj_classes = get_list(entries[0], "objectClass")
        member_type = _classify_member(obj_classes)

        member = GroupMember(
            samaccountname=sam or dn.split(",")[0][3:],
            dn=dn,
            member_type=member_type,
        )
        cache[dn_lower] = member

        if member_type == MemberType.GROUP:
            if dn_lower not in visited_groups:
                visited_groups.add(dn_lower)
                _resolve_nested_group(
                    conn, dn, resolved, cache,
                    visited_groups, depth + 1,
                )
        else:
            resolved.append(member)


def _resolve_nested_group(
    conn: LDAPConnection,
    group_dn: str,
    resolved: list[GroupMember],
    cache: dict[str, GroupMember],
    visited_groups: set[str],
    depth: int,
):
    """Resolve members of a nested group."""
    try:
        entries = conn.search(
            search_base=group_dn,
            search_filter="(objectClass=*)",
            attributes=["member"],
            search_scope="BASE",
        )
    except Exception:
        return

    if not entries:
        return

    nested_dns = get_list(entries[0], "member")
    _resolve_members(conn, nested_dns, resolved, cache, visited_groups, depth)


def _classify_member(obj_classes: list[str]) -> MemberType:
    """Determine member type from objectClass list."""
    classes_lower = [c.lower() for c in obj_classes]
    if "computer" in classes_lower:
        return MemberType.COMPUTER
    if "group" in classes_lower:
        return MemberType.GROUP
    if "user" in classes_lower or "person" in classes_lower:
        return MemberType.USER
    return MemberType.UNKNOWN


def _parse_scope(group_type: int) -> GroupScope:
    """Parse group scope from groupType bitmask."""
    if group_type & 0x2:
        return GroupScope.GLOBAL
    if group_type & 0x4:
        return GroupScope.DOMAIN_LOCAL
    if group_type & 0x8:
        return GroupScope.UNIVERSAL
    return GroupScope.UNKNOWN
