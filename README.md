# ADSense

AD situational awareness tool for the first 5 minutes after getting domain credentials. Enumerates password policy, non-default groups, Kerberoastable accounts, AS-REP roastable accounts, LAPS deployment, interesting account flags, and computer overview via LDAP.

Built for pentesters and red teamers who need a quick domain snapshot with clean, copy-paste-friendly output.

## Features

- **Domain Password Policy** — Default policy, fine-grained password policies, and machine account quota
- **Non-Default Groups** — Filters out ~50 well-known groups, resolves members recursively (depth 5), identifies foreign security principals
- **Kerberoastable Accounts** — Users with SPNs (excludes krbtgt, disabled, computers), flags gMSAs and Protected Users members
- **AS-REP Roastable Accounts** — Accounts with `DONT_REQUIRE_PREAUTH` set, cross-referenced with Protected Users
- **LAPS Status** — Schema detection (legacy + Windows LAPS), deployment coverage percentage, readable passwords if accessible
- **Interesting Account Flags** — `PASSWD_NOTREQD`, `PASSWORD_NEVER_EXPIRES`, `adminCount=1`, recently created (30 days), disabled privileged accounts, service accounts
- **Computer Overview** — OS breakdown, domain controllers, unconstrained delegation (non-DC), legacy OS detection
- **Markdown Export** — Clean pipe-delimited tables for Obsidian/notes, no terminal markup

## Installation

```bash
git clone https://github.com/0xBeejay/ADSense.git
cd ADSense
pip install .
```

### Requirements

- Python 3.9+
- `ldap3`, `impacket`, `rich`, `click`

## Usage

```bash
# Password authentication
adsense -d corp.local -u admin -p 'Password1' --dc 10.10.1.1

# NTLM hash authentication
adsense -d corp.local -u admin -H aad3b435:ntlmhash --dc 10.10.1.1

# Kerberos authentication (uses KRB5CCNAME)
adsense -d corp.local -k --dc 10.10.1.1

# LDAPS
adsense -d corp.local -u admin -p pass --dc 10.10.1.1 --ldaps

# Compact output (no description/notes columns)
adsense -d corp.local -u admin -p pass --dc 10.10.1.1 --brief

# Export to markdown
adsense -d corp.local -u admin -p pass --dc 10.10.1.1 -m report.md

# Focus on a specific account
adsense -d corp.local -u admin -p pass --dc 10.10.1.1 --account svc_web

# Skip slow collectors
adsense -d corp.local -u admin -p pass --dc 10.10.1.1 --no-groups --no-computers
```

## Options

```
-d, --domain        Target domain (e.g. corp.local)                        [required]
-u, --username      Username for authentication
-p, --password      Password for authentication
-H, --hashes        NTLM hash (LM:NT or :NT format)
-k, --kerberos      Use Kerberos auth (KRB5CCNAME)
--dc                Domain controller IP address                            [required]
--ldaps             Use LDAPS (port 636)
--brief             Compact tables only, no detail columns
-m, --markdown      Export results to markdown file
--no-groups         Skip group enumeration (faster)
--no-computers      Skip computer overview
--account           Focus on a specific account
```

## Output

ADSense produces 7 sections:

1. **Domain Password Policy** — Min length, complexity, lockout settings, max/min age, history, machine account quota
2. **Fine-Grained Policies** — Name, precedence, settings, and applies-to targets
3. **Non-Default Groups** — Group name, scope, type, member count, and member list with type indicators (`$` = computer, `@` = foreign)
4. **Kerberoastable Accounts** — Account, SPN, admin status, password age, notes (gMSA/Protected/Privileged)
5. **AS-REP Roastable** — Account, enabled status, admin, password age, description
6. **LAPS Status** — Deployment type (legacy/Windows), coverage percentage, readable passwords
7. **Computer Overview** — Total/enabled/disabled counts, DCs, OS breakdown, unconstrained delegation, legacy OS

### Markdown Export

The `-m` flag generates clean markdown with pipe-delimited tables, suitable for direct paste into Obsidian or any markdown editor. No terminal formatting or color codes.

## Account Flags Detected

| Flag | LDAP Indicator | Why It Matters |
|------|---------------|----------------|
| PASSWD_NOTREQD | `userAccountControl` & `0x20` | Account can have an empty password |
| PASSWORD_NEVER_EXPIRES | `userAccountControl` & `0x10000` | Password may be very old |
| adminCount=1 | `adminCount` attribute | Current or former privileged group member |
| Recently Created | `whenCreated` within 30 days | New accounts worth investigating |
| Disabled Privileged | adminCount=1 + ACCOUNTDISABLE | Dormant privileged account |
| Service Account | sAMAccountName matches `svc_*`, `sa_*`, `service_*` | Often over-privileged with weak passwords |

## Legacy OS Detection

Computers running the following are flagged:

- Windows Server 2003 / 2008 / 2012
- Windows XP / Vista / 7 / 8

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Only use against environments you have explicit permission to test.
