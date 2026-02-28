"""Main output orchestrator for ADSense."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from adsense.analyser.models import (
    AccountFlag,
    ASREPAccount,
    ComputerInfo,
    DomainGroup,
    DomainPolicyResult,
    KerberoastableAccount,
    LAPSStatus,
)
from adsense.output.tables import (
    account_flags_table,
    asrep_table,
    computer_os_table,
    computer_overview_table,
    domain_policy_table,
    fine_grained_table,
    groups_table,
    kerberoastable_table,
    laps_panel,
    old_os_table,
)


class ADSenseOutput:
    """Orchestrates the full output flow for ADSense."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def print_banner(self, domain: str):
        banner = Text()
        banner.append("ADSENSE", style="bold red")
        banner.append(" v1.0", style="dim")
        banner.append("  |  Situational awareness for ", style="dim")
        banner.append(domain.upper(), style="bold yellow")

        self.console.print()
        self.console.print(Panel(banner, border_style="red", expand=True))
        self.console.print()

    def print_results(
        self,
        domain: str,
        policy: DomainPolicyResult | None = None,
        groups: list[DomainGroup] | None = None,
        kerberoastable: list[KerberoastableAccount] | None = None,
        asrep: list[ASREPAccount] | None = None,
        laps: LAPSStatus | None = None,
        account_flags: list[AccountFlag] | None = None,
        computers: ComputerInfo | None = None,
        brief: bool = False,
        focus_account: str | None = None,
    ):
        """Print all sections in order."""
        # Account focus: filter where applicable
        if focus_account:
            focus = focus_account.upper()
            if kerberoastable:
                kerberoastable = [
                    a for a in kerberoastable
                    if a.samaccountname.upper() == focus
                ]
            if asrep:
                asrep = [
                    a for a in asrep
                    if a.samaccountname.upper() == focus
                ]
            if account_flags:
                account_flags = [
                    f for f in account_flags
                    if f.samaccountname.upper() == focus
                ]
            if groups:
                groups = [
                    g for g in groups
                    if any(
                        m.samaccountname.upper() == focus
                        for m in g.members
                    )
                ]

        # 1. Domain Policy
        if policy:
            self.print_section("Domain Policy")
            self.console.print(domain_policy_table(policy))
            self.console.print()

            fgp = fine_grained_table(policy)
            if fgp:
                self.console.print(fgp)
                self.console.print()

        # 2. Groups
        if groups is not None:
            self.print_section("Non-Default Groups")
            if groups:
                self.console.print(groups_table(groups, brief=brief))
            else:
                self.console.print("[dim]  No non-default groups found.[/dim]")
            self.console.print()

        # 3. Kerberoastable
        if kerberoastable is not None:
            self.print_section("Kerberoastable Accounts")
            if kerberoastable:
                self.console.print(
                    kerberoastable_table(kerberoastable, brief=brief)
                )
            else:
                self.console.print("[dim]  No Kerberoastable accounts found.[/dim]")
            self.console.print()

        # 4. AS-REP Roastable
        if asrep is not None:
            self.print_section("AS-REP Roastable Accounts")
            if asrep:
                self.console.print(asrep_table(asrep, brief=brief))
            else:
                self.console.print("[dim]  No AS-REP roastable accounts found.[/dim]")
            self.console.print()

        # 5. LAPS
        if laps is not None:
            self.print_section("LAPS Status")
            self.console.print(laps_panel(laps))
            self.console.print()

        # 6. Account Flags
        if account_flags is not None:
            self.print_section("Interesting Account Flags")
            if account_flags:
                self.console.print(
                    account_flags_table(account_flags, brief=brief)
                )
            else:
                self.console.print("[dim]  No interesting account flags found.[/dim]")
            self.console.print()

        # 7. Computers
        if computers is not None:
            self.print_section("Computer Overview")
            self.console.print(computer_overview_table(computers))
            self.console.print()

            if not brief:
                os_tbl = computer_os_table(computers.os_breakdown)
                if os_tbl:
                    self.console.print(os_tbl)
                    self.console.print()

                old_tbl = old_os_table(computers.old_os)
                if old_tbl:
                    self.console.print(old_tbl)
                    self.console.print()

    def print_error(self, message: str):
        self.console.print(f"[bold red]Error:[/bold red] {message}")

    def print_info(self, message: str):
        self.console.print(f"[dim]{message}[/dim]")

    def print_section(self, title: str):
        self.console.print()
        self.console.print(Rule(title, style="cyan"))
        self.console.print()

    def print_collector_status(self, name: str, count: int):
        if count > 0:
            self.console.print(
                f"  [green]+[/green] {name}: [bold]{count}[/bold] results"
            )
        else:
            self.console.print(
                f"  [dim]-[/dim] {name}: [dim]none found[/dim]"
            )
