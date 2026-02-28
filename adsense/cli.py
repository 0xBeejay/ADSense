"""Click CLI, auth handling, and argument parsing for ADSense."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from adsense.collector.accounts import enumerate_account_flags
from adsense.collector.asreproast import enumerate_asrep
from adsense.collector.computers import enumerate_computers
from adsense.collector.domain_policy import enumerate_domain_policy
from adsense.collector.groups import enumerate_groups
from adsense.collector.kerberoastable import enumerate_kerberoastable
from adsense.collector.laps import enumerate_laps
from adsense.connection import AuthConfig, LDAPConnection
from adsense.output.console import ADSenseOutput
from adsense.output.markdown import generate_markdown


@click.command()
@click.option("-d", "--domain", required=True, help="Target domain (e.g. corp.local)")
@click.option("-u", "--username", default=None, help="Username for authentication")
@click.option("-p", "--password", default=None, help="Password for authentication")
@click.option("-H", "--hashes", default=None, help="NTLM hash (LM:NT or :NT format)")
@click.option("-k", "--kerberos", is_flag=True, help="Use Kerberos auth (KRB5CCNAME)")
@click.option("--dc", required=True, help="Domain controller IP address")
@click.option("--ldaps", is_flag=True, help="Use LDAPS (port 636)")
@click.option("--brief", is_flag=True, help="Compact tables only, no detail columns")
@click.option(
    "--markdown", "-m", default=None, type=click.Path(),
    help="Export results to markdown file",
)
@click.option("--no-groups", is_flag=True, help="Skip group enumeration (faster)")
@click.option("--no-computers", is_flag=True, help="Skip computer overview")
@click.option("--account", default=None, help="Focus on a specific account")
def main(
    domain: str,
    username: str | None,
    password: str | None,
    hashes: str | None,
    kerberos: bool,
    dc: str,
    ldaps: bool,
    brief: bool,
    markdown: str | None,
    no_groups: bool,
    no_computers: bool,
    account: str | None,
):
    """ADSense - AD situational awareness for the first 5 minutes.

    Enumerates domain password policy, non-default groups, Kerberoastable
    accounts, AS-REP roastable accounts, LAPS deployment, interesting
    account flags, and computer overview.
    """
    console = Console()
    output = ADSenseOutput(console)
    output.print_banner(domain)

    # Validate auth options
    if not kerberos and not username:
        output.print_error("Must provide -u/--username or -k/--kerberos")
        sys.exit(1)

    if not kerberos and not password and not hashes:
        output.print_error("Must provide -p/--password, -H/--hashes, or -k/--kerberos")
        sys.exit(1)

    # Parse hash
    nthash = None
    if hashes:
        if ":" in hashes:
            nthash = hashes.split(":")[-1]
        else:
            nthash = hashes

    auth = AuthConfig(
        domain=domain,
        username=username or "",
        dc_ip=dc,
        password=password,
        nthash=nthash,
        use_kerberos=kerberos,
        use_ldaps=ldaps,
    )

    # Connect
    ldap_conn = LDAPConnection(auth)

    try:
        output.print_info(f"Connecting to {dc} ({domain})...")
        ldap_conn.connect()
        output.print_info("Connected successfully.")
    except Exception as e:
        output.print_error(f"Failed to connect: {e}")
        sys.exit(1)

    try:
        output.print_section("Collecting Domain Information")

        # Pre-collect: resolve Protected Users group DN
        protected_users_dn = ""
        try:
            pu_entries = ldap_conn.search(
                search_base=ldap_conn.auth.domain_dn,
                search_filter="(&(objectClass=group)(cn=Protected Users))",
                attributes=["distinguishedName"],
            )
            if pu_entries:
                from adsense.collector import get_str
                protected_users_dn = get_str(pu_entries[0], "distinguishedName")
        except Exception:
            pass

        # Phase 1: Domain Policy (always)
        output.print_info("Collecting domain password policy...")
        policy = enumerate_domain_policy(ldap_conn)
        output.print_collector_status("Password policy", 1 if policy else 0)

        # Phase 2: Groups (unless --no-groups)
        groups_result = None
        if not no_groups:
            output.print_info("Enumerating non-default groups...")
            groups_result = enumerate_groups(ldap_conn)
            output.print_collector_status("Non-default groups", len(groups_result))

        # Phase 3: Kerberoastable
        output.print_info("Enumerating Kerberoastable accounts...")
        kerberoastable = enumerate_kerberoastable(ldap_conn, protected_users_dn)
        output.print_collector_status("Kerberoastable accounts", len(kerberoastable))

        # Phase 4: AS-REP Roastable
        output.print_info("Enumerating AS-REP roastable accounts...")
        asrep = enumerate_asrep(ldap_conn, protected_users_dn)
        output.print_collector_status("AS-REP roastable accounts", len(asrep))

        # Phase 5: LAPS
        output.print_info("Checking LAPS deployment...")
        laps = enumerate_laps(ldap_conn)
        status = "deployed" if laps.deployed else "not deployed"
        output.print_collector_status(f"LAPS ({status})", 1 if laps.deployed else 0)

        # Phase 6: Account Flags
        output.print_info("Enumerating interesting account flags...")
        account_flags = enumerate_account_flags(ldap_conn)
        output.print_collector_status("Interesting account flags", len(account_flags))

        # Phase 7: Computers (unless --no-computers)
        computers = None
        if not no_computers:
            output.print_info("Collecting computer overview...")
            computers = enumerate_computers(ldap_conn)
            output.print_collector_status("Computers", computers.total)

        # Output results
        output.print_results(
            domain=domain,
            policy=policy,
            groups=groups_result,
            kerberoastable=kerberoastable,
            asrep=asrep,
            laps=laps,
            account_flags=account_flags,
            computers=computers,
            brief=brief,
            focus_account=account,
        )

        # Markdown export
        if markdown:
            md_content = generate_markdown(
                domain=domain,
                policy=policy,
                groups=groups_result,
                kerberoastable=kerberoastable,
                asrep=asrep,
                laps=laps,
                account_flags=account_flags,
                computers=computers,
            )
            with open(markdown, "w") as f:
                f.write(md_content)
            output.print_info(f"Markdown report saved to {markdown}")

    except Exception as e:
        output.print_error(f"Enumeration failed: {e}")
        raise
    finally:
        ldap_conn.close()


if __name__ == "__main__":
    main()
