"""Rich table formatters for ADSense output."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from adsense.analyser.models import (
    AccountFlag,
    AccountFlagType,
    ASREPAccount,
    ComputerInfo,
    DomainGroup,
    DomainPolicyResult,
    GroupCategory,
    KerberoastableAccount,
    LAPSStatus,
    MemberType,
)


def domain_policy_table(result: DomainPolicyResult) -> Table:
    """Default password policy as a key-value table."""
    table = Table(
        title="Domain Password Policy",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )
    table.add_column("Property", style="bold white", width=25)
    table.add_column("Value", justify="right")

    p = result.default_policy

    min_len_style = "red" if p.min_length < 8 else "green"
    table.add_row("Min Password Length", f"[{min_len_style}]{p.min_length}[/{min_len_style}]")
    table.add_row("Complexity Required", "[green]Yes[/green]" if p.complexity else "[red]No[/red]")
    table.add_row("Lockout Threshold", f"{p.lockout_threshold}" if p.lockout_threshold else "[red]None (no lockout)[/red]")
    if p.lockout_threshold:
        table.add_row("Lockout Duration", f"{p.lockout_duration} min")
        table.add_row("Lockout Window", f"{p.lockout_window} min")
    table.add_row("Max Password Age", f"{p.max_age} days" if p.max_age else "[yellow]Never expires[/yellow]")
    table.add_row("Min Password Age", f"{p.min_age} days")
    table.add_row("History Count", str(p.history_count))

    maq = result.machine_account_quota
    maq_style = "red" if maq > 0 else "green"
    table.add_row(
        "Machine Account Quota",
        f"[{maq_style}]{maq}[/{maq_style}]",
    )

    return table


def fine_grained_table(result: DomainPolicyResult) -> Table | None:
    """Fine-grained password policies table."""
    if not result.fine_grained:
        return None

    table = Table(
        title="Fine-Grained Password Policies",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )
    table.add_column("Name", style="bold white")
    table.add_column("Precedence", justify="center")
    table.add_column("Min Len", justify="center")
    table.add_column("Complexity", justify="center")
    table.add_column("Lockout", justify="center")
    table.add_column("Applies To", style="dim")

    for fgp in result.fine_grained:
        applies = ", ".join(fgp.applies_to[:5])
        if len(fgp.applies_to) > 5:
            applies += f" (+{len(fgp.applies_to) - 5})"

        table.add_row(
            fgp.name,
            str(fgp.precedence),
            str(fgp.min_length),
            "[green]Yes[/green]" if fgp.complexity else "[red]No[/red]",
            str(fgp.lockout_threshold) if fgp.lockout_threshold else "[dim]-[/dim]",
            applies,
        )

    return table


def groups_table(groups: list[DomainGroup], brief: bool = False) -> Table:
    """Non-default groups with members."""
    table = Table(
        title="Non-Default Groups",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )
    table.add_column("Group", style="bold white")
    table.add_column("Scope", justify="center")
    table.add_column("Type", justify="center")
    table.add_column("Members", justify="center")

    if not brief:
        table.add_column("Member List", style="dim", max_width=60)

    for group in groups:
        scope_str = group.scope.value
        cat_color = "cyan" if group.category == GroupCategory.SECURITY else "dim"
        cat_str = f"[{cat_color}]{group.category.value}[/{cat_color}]"
        count_str = str(group.member_count)

        if brief:
            table.add_row(group.name, scope_str, cat_str, count_str)
        else:
            # Show first N members with type indicators
            member_parts = []
            for m in group.members[:20]:
                prefix = ""
                if m.member_type == MemberType.COMPUTER:
                    prefix = "[cyan]$[/cyan]"
                elif m.member_type == MemberType.FOREIGN:
                    prefix = "[yellow]@[/yellow]"
                member_parts.append(f"{prefix}{m.samaccountname}")

            member_str = ", ".join(member_parts)
            if group.member_count > 20:
                member_str += f" [dim](+{group.member_count - 20} more)[/dim]"

            table.add_row(group.name, scope_str, cat_str, count_str, member_str)

    return table


def kerberoastable_table(
    accounts: list[KerberoastableAccount],
    brief: bool = False,
) -> Table:
    """Kerberoastable accounts table."""
    table = Table(
        title="Kerberoastable Accounts",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )
    table.add_column("Account", style="bold white")
    table.add_column("SPN", style="dim")
    table.add_column("Admin", justify="center")
    table.add_column("Pwd Last Set", justify="center")
    if not brief:
        table.add_column("Notes", style="dim")

    for acct in accounts:
        spn_str = acct.spns[0] if acct.spns else ""
        if len(acct.spns) > 1:
            spn_str += f" (+{len(acct.spns) - 1})"

        admin_str = "[yellow]Yes[/yellow]" if acct.admin_count else "[dim]-[/dim]"

        pwd_str = "[dim]Unknown[/dim]"
        if acct.pwd_last_set:
            pwd_str = acct.pwd_last_set.strftime("%Y-%m-%d")

        notes_parts = []
        if acct.is_gmsa:
            notes_parts.append("[green]gMSA[/green]")
        if acct.in_protected_users:
            notes_parts.append("[green]Protected[/green]")
        if acct.admin_count:
            notes_parts.append("[red]PRIVILEGED[/red]")

        if brief:
            name = acct.samaccountname
            if acct.is_gmsa:
                name += " [green](gMSA)[/green]"
            table.add_row(name, spn_str, admin_str, pwd_str)
        else:
            table.add_row(
                acct.samaccountname, spn_str, admin_str, pwd_str,
                " ".join(notes_parts) if notes_parts else "[dim]-[/dim]",
            )

    return table


def asrep_table(accounts: list[ASREPAccount], brief: bool = False) -> Table:
    """AS-REP roastable accounts table."""
    table = Table(
        title="AS-REP Roastable Accounts",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )
    table.add_column("Account", style="bold white")
    table.add_column("Enabled", justify="center")
    table.add_column("Admin", justify="center")
    table.add_column("Pwd Last Set", justify="center")
    if not brief:
        table.add_column("Description", style="dim", max_width=40)

    for acct in accounts:
        enabled_str = "[green]Yes[/green]" if acct.enabled else "[dim]No[/dim]"
        admin_str = "[yellow]Yes[/yellow]" if acct.admin_count else "[dim]-[/dim]"

        pwd_str = "[dim]Unknown[/dim]"
        if acct.pwd_last_set:
            pwd_str = acct.pwd_last_set.strftime("%Y-%m-%d")

        if brief:
            table.add_row(acct.samaccountname, enabled_str, admin_str, pwd_str)
        else:
            desc = acct.description[:40] if acct.description else "[dim]-[/dim]"
            table.add_row(acct.samaccountname, enabled_str, admin_str, pwd_str, desc)

    return table


def laps_panel(status: LAPSStatus) -> Panel:
    """LAPS deployment status panel."""
    lines = []

    if not status.deployed:
        lines.append("[red]LAPS is NOT deployed (schema attributes not found)[/red]")
    else:
        if status.legacy_laps:
            lines.append("[green]+[/green] Legacy LAPS (ms-Mcs-AdmPwd): deployed")
        if status.windows_laps:
            lines.append("[green]+[/green] Windows LAPS (msLAPS-Password): deployed")

        if status.total_computers > 0:
            pct = (status.laps_configured_count / status.total_computers) * 100
            color = "green" if pct > 80 else "yellow" if pct > 30 else "red"
            lines.append(
                f"  Coverage: [{color}]{status.laps_configured_count}/"
                f"{status.total_computers} ({pct:.0f}%)[/{color}]"
            )

        if status.readable_passwords:
            lines.append("")
            lines.append(f"[red]Readable LAPS passwords: {len(status.readable_passwords)}[/red]")
            for pw in status.readable_passwords[:10]:
                lines.append(f"  {pw['computer']}: [bold green]{pw['password']}[/bold green]")
            if len(status.readable_passwords) > 10:
                lines.append(f"  [dim](+{len(status.readable_passwords) - 10} more)[/dim]")

    return Panel(
        "\n".join(lines),
        title="LAPS Status",
        border_style="blue",
        expand=True,
    )


def account_flags_table(
    flags: list[AccountFlag],
    brief: bool = False,
) -> Table:
    """Interesting account flags table."""
    table = Table(
        title="Interesting Account Flags",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )

    if brief:
        # Brief: just show counts per flag type
        table.add_column("Flag", style="bold white")
        table.add_column("Count", justify="center")

        counts: dict[AccountFlagType, int] = {}
        for f in flags:
            counts[f.flag_type] = counts.get(f.flag_type, 0) + 1

        for flag_type, count in counts.items():
            color = flag_type.color
            table.add_row(
                f"[{color}]{flag_type.value}[/{color}]",
                str(count),
            )
    else:
        table.add_column("Account", style="bold white")
        table.add_column("Flag", justify="center")
        table.add_column("Admin", justify="center")
        table.add_column("Enabled", justify="center")
        table.add_column("Description", style="dim", max_width=35)

        for f in flags:
            color = f.flag_type.color
            table.add_row(
                f.samaccountname,
                f"[{color}]{f.flag_type.value}[/{color}]",
                "[yellow]Yes[/yellow]" if f.admin_count else "[dim]-[/dim]",
                "[green]Yes[/green]" if f.enabled else "[dim]No[/dim]",
                f.description[:35] if f.description else "[dim]-[/dim]",
            )

    return table


def computer_overview_table(info: ComputerInfo) -> Table:
    """Computer statistics summary."""
    table = Table(
        title="Computer Overview",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )
    table.add_column("Metric", style="bold white", width=25)
    table.add_column("Value", justify="right")

    table.add_row("Total Computers", str(info.total))
    table.add_row("Enabled", f"[green]{info.enabled}[/green]")
    table.add_row("Disabled", f"[dim]{info.disabled}[/dim]")
    table.add_row("Domain Controllers", str(len(info.dcs)))
    if info.dcs:
        table.add_row("  DC List", ", ".join(info.dcs))
    if info.unconstrained:
        table.add_row(
            "[red]Unconstrained Delegation[/red]",
            ", ".join(info.unconstrained),
        )
    if info.old_os:
        table.add_row(
            "[red]Legacy OS[/red]",
            f"[red]{len(info.old_os)} systems[/red]",
        )

    return table


def computer_os_table(os_breakdown: dict[str, int]) -> Table | None:
    """OS version distribution table."""
    if not os_breakdown:
        return None

    table = Table(
        title="OS Breakdown",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
    )
    table.add_column("Operating System", style="white")
    table.add_column("Count", justify="right")

    old_patterns = [
        "2003", "2008", "2012", "xp", "windows 7", "vista", "windows 8",
    ]

    for os_name, count in os_breakdown.items():
        is_old = any(p in os_name.lower() for p in old_patterns)
        if is_old:
            table.add_row(f"[red]{os_name}[/red]", f"[red]{count}[/red]")
        else:
            table.add_row(os_name, str(count))

    return table


def old_os_table(old_os: list[dict]) -> Table | None:
    """Legacy OS systems table."""
    if not old_os:
        return None

    table = Table(
        title="Legacy OS Systems",
        show_header=True,
        header_style="bold red",
        border_style="red",
    )
    table.add_column("Computer", style="bold white")
    table.add_column("Operating System", style="red")

    for entry in old_os:
        table.add_row(entry["name"], entry["os"])

    return table
