"""Markdown export for ADSense results."""

from __future__ import annotations

from datetime import datetime, timezone

from adsense.analyser.models import (
    AccountFlag,
    AccountFlagType,
    ASREPAccount,
    ComputerInfo,
    DomainGroup,
    DomainPolicyResult,
    KerberoastableAccount,
    LAPSStatus,
)


def generate_markdown(
    domain: str,
    policy: DomainPolicyResult | None = None,
    groups: list[DomainGroup] | None = None,
    kerberoastable: list[KerberoastableAccount] | None = None,
    asrep: list[ASREPAccount] | None = None,
    laps: LAPSStatus | None = None,
    account_flags: list[AccountFlag] | None = None,
    computers: ComputerInfo | None = None,
) -> str:
    """Generate clean markdown report for notes/Obsidian."""
    sections: list[str] = []

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections.append(f"# ADSense Report - {domain.upper()}")
    sections.append(f"*Generated: {timestamp}*")

    if policy:
        sections.append(_md_policy(policy))

    if groups is not None:
        sections.append(_md_groups(groups))

    if kerberoastable is not None:
        sections.append(_md_kerberoastable(kerberoastable))

    if asrep is not None:
        sections.append(_md_asrep(asrep))

    if laps is not None:
        sections.append(_md_laps(laps))

    if account_flags is not None:
        sections.append(_md_flags(account_flags))

    if computers is not None:
        sections.append(_md_computers(computers))

    return "\n\n".join(sections) + "\n"


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Generate a markdown table."""
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def _fmt_date(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d") if dt else "-"


def _md_policy(result: DomainPolicyResult) -> str:
    lines = ["## Domain Password Policy"]
    p = result.default_policy
    lines.append(_md_table(
        ["Property", "Value"],
        [
            ["Min Length", str(p.min_length)],
            ["Complexity", "Yes" if p.complexity else "No"],
            ["Lockout Threshold", str(p.lockout_threshold) if p.lockout_threshold else "None"],
            ["Lockout Duration", f"{p.lockout_duration} min" if p.lockout_threshold else "-"],
            ["Max Password Age", f"{p.max_age} days" if p.max_age else "Never"],
            ["Min Password Age", f"{p.min_age} days"],
            ["History Count", str(p.history_count)],
            ["Machine Account Quota", str(result.machine_account_quota)],
        ],
    ))

    if result.fine_grained:
        lines.append("")
        lines.append("### Fine-Grained Policies")
        rows = []
        for fgp in result.fine_grained:
            rows.append([
                fgp.name,
                str(fgp.precedence),
                str(fgp.min_length),
                "Yes" if fgp.complexity else "No",
                str(fgp.lockout_threshold),
                ", ".join(fgp.applies_to[:5]),
            ])
        lines.append(_md_table(
            ["Name", "Precedence", "Min Len", "Complexity", "Lockout", "Applies To"],
            rows,
        ))

    return "\n".join(lines)


def _md_groups(groups: list[DomainGroup]) -> str:
    lines = ["## Non-Default Groups"]
    if not groups:
        lines.append("No non-default groups found.")
        return "\n".join(lines)

    rows = []
    for g in groups:
        members = ", ".join(m.samaccountname for m in g.members[:15])
        if g.member_count > 15:
            members += f" (+{g.member_count - 15})"
        rows.append([
            g.name,
            g.scope.value,
            g.category.value,
            str(g.member_count),
            members,
        ])

    lines.append(_md_table(
        ["Group", "Scope", "Type", "Members", "Member List"],
        rows,
    ))
    return "\n".join(lines)


def _md_kerberoastable(accounts: list[KerberoastableAccount]) -> str:
    lines = ["## Kerberoastable Accounts"]
    if not accounts:
        lines.append("No Kerberoastable accounts found.")
        return "\n".join(lines)

    rows = []
    for a in accounts:
        spn = a.spns[0] if a.spns else "-"
        notes = []
        if a.is_gmsa:
            notes.append("gMSA")
        if a.in_protected_users:
            notes.append("Protected")
        if a.admin_count:
            notes.append("PRIVILEGED")
        rows.append([
            a.samaccountname,
            spn,
            "Yes" if a.admin_count else "-",
            _fmt_date(a.pwd_last_set),
            " ".join(notes) if notes else "-",
        ])

    lines.append(_md_table(
        ["Account", "SPN", "Admin", "Pwd Last Set", "Notes"],
        rows,
    ))
    return "\n".join(lines)


def _md_asrep(accounts: list[ASREPAccount]) -> str:
    lines = ["## AS-REP Roastable Accounts"]
    if not accounts:
        lines.append("No AS-REP roastable accounts found.")
        return "\n".join(lines)

    rows = []
    for a in accounts:
        rows.append([
            a.samaccountname,
            "Yes" if a.enabled else "No",
            "Yes" if a.admin_count else "-",
            _fmt_date(a.pwd_last_set),
            a.description[:40] if a.description else "-",
        ])

    lines.append(_md_table(
        ["Account", "Enabled", "Admin", "Pwd Last Set", "Description"],
        rows,
    ))
    return "\n".join(lines)


def _md_laps(status: LAPSStatus) -> str:
    lines = ["## LAPS Status"]

    if not status.deployed:
        lines.append("LAPS is **NOT deployed** (schema attributes not found).")
        return "\n".join(lines)

    if status.legacy_laps:
        lines.append("- Legacy LAPS (ms-Mcs-AdmPwd): deployed")
    if status.windows_laps:
        lines.append("- Windows LAPS (msLAPS-Password): deployed")

    if status.total_computers > 0:
        pct = (status.laps_configured_count / status.total_computers) * 100
        lines.append(
            f"- Coverage: {status.laps_configured_count}/"
            f"{status.total_computers} ({pct:.0f}%)"
        )

    if status.readable_passwords:
        lines.append("")
        lines.append(f"### Readable Passwords ({len(status.readable_passwords)})")
        rows = [[pw["computer"], pw["password"]] for pw in status.readable_passwords]
        lines.append(_md_table(["Computer", "Password"], rows))

    return "\n".join(lines)


def _md_flags(flags: list[AccountFlag]) -> str:
    lines = ["## Interesting Account Flags"]
    if not flags:
        lines.append("No interesting account flags found.")
        return "\n".join(lines)

    # Group by flag type
    by_type: dict[AccountFlagType, list[AccountFlag]] = {}
    for f in flags:
        by_type.setdefault(f.flag_type, []).append(f)

    for flag_type, accts in by_type.items():
        lines.append(f"### {flag_type.value} ({len(accts)})")
        rows = []
        for a in accts:
            rows.append([
                a.samaccountname,
                "Yes" if a.admin_count else "-",
                "Yes" if a.enabled else "No",
            ])
        lines.append(_md_table(["Account", "Admin", "Enabled"], rows))
        lines.append("")

    return "\n".join(lines)


def _md_computers(info: ComputerInfo) -> str:
    lines = ["## Computer Overview"]

    lines.append(_md_table(
        ["Metric", "Count"],
        [
            ["Total", str(info.total)],
            ["Enabled", str(info.enabled)],
            ["Disabled", str(info.disabled)],
            ["Domain Controllers", str(len(info.dcs))],
        ],
    ))

    if info.dcs:
        lines.append("")
        lines.append("### Domain Controllers")
        for dc in info.dcs:
            lines.append(f"- {dc}")

    if info.os_breakdown:
        lines.append("")
        lines.append("### OS Breakdown")
        rows = [[os_name, str(count)] for os_name, count in info.os_breakdown.items()]
        lines.append(_md_table(["Operating System", "Count"], rows))

    if info.unconstrained:
        lines.append("")
        lines.append("### Unconstrained Delegation (Non-DC)")
        for name in info.unconstrained:
            lines.append(f"- {name}")

    if info.old_os:
        lines.append("")
        lines.append("### Legacy OS (Potential Quick Wins)")
        rows = [[e["name"], e["os"]] for e in info.old_os]
        lines.append(_md_table(["Computer", "OS"], rows))

    return "\n".join(lines)
