"""Data models for ADSense domain situational awareness."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class MemberType(enum.Enum):
    USER = "User"
    COMPUTER = "Computer"
    GROUP = "Group"
    FOREIGN = "Foreign"
    UNKNOWN = "Unknown"


class GroupScope(enum.Enum):
    GLOBAL = "Global"
    DOMAIN_LOCAL = "Domain Local"
    UNIVERSAL = "Universal"
    UNKNOWN = "Unknown"


class GroupCategory(enum.Enum):
    SECURITY = "Security"
    DISTRIBUTION = "Distribution"


class AccountFlagType(enum.Enum):
    PASSWD_NOTREQD = "PASSWD_NOTREQD"
    PASSWORD_NEVER_EXPIRES = "PWD_NEVER_EXPIRES"
    ADMIN_COUNT = "adminCount=1"
    RECENTLY_CREATED = "Recently Created"
    DISABLED_PRIVILEGED = "Disabled + Privileged"
    SERVICE_ACCOUNT = "Service Account"

    @property
    def color(self) -> str:
        return {
            "PASSWD_NOTREQD": "red",
            "PWD_NEVER_EXPIRES": "yellow",
            "adminCount=1": "yellow",
            "Recently Created": "cyan",
            "Disabled + Privileged": "dim",
            "Service Account": "cyan",
        }[self.value]


@dataclass
class GroupMember:
    samaccountname: str
    dn: str
    member_type: MemberType = MemberType.UNKNOWN


@dataclass
class DomainGroup:
    name: str
    dn: str
    scope: GroupScope = GroupScope.UNKNOWN
    category: GroupCategory = GroupCategory.SECURITY
    members: list[GroupMember] = field(default_factory=list)
    member_count: int = 0


@dataclass
class KerberoastableAccount:
    samaccountname: str
    spns: list[str] = field(default_factory=list)
    admin_count: int = 0
    pwd_last_set: datetime | None = None
    description: str = ""
    in_protected_users: bool = False
    is_gmsa: bool = False


@dataclass
class ASREPAccount:
    samaccountname: str
    enabled: bool = True
    admin_count: int = 0
    pwd_last_set: datetime | None = None
    description: str = ""
    in_protected_users: bool = False


@dataclass
class PasswordPolicy:
    min_length: int = 0
    complexity: bool = False
    lockout_threshold: int = 0
    lockout_duration: int = 0       # minutes
    lockout_window: int = 0         # minutes
    max_age: int = 0                # days
    min_age: int = 0                # days
    history_count: int = 0


@dataclass
class FineGrainedPolicy:
    name: str
    dn: str = ""
    precedence: int = 0
    applies_to: list[str] = field(default_factory=list)
    min_length: int = 0
    complexity: bool = False
    lockout_threshold: int = 0
    lockout_duration: int = 0       # minutes
    max_age: int = 0                # days
    min_age: int = 0                # days


@dataclass
class DomainPolicyResult:
    default_policy: PasswordPolicy = field(default_factory=PasswordPolicy)
    fine_grained: list[FineGrainedPolicy] = field(default_factory=list)
    machine_account_quota: int = 10


@dataclass
class LAPSStatus:
    deployed: bool = False
    legacy_laps: bool = False
    windows_laps: bool = False
    total_computers: int = 0
    laps_configured_count: int = 0
    readable_passwords: list[dict] = field(default_factory=list)


@dataclass
class AccountFlag:
    samaccountname: str
    flag_type: AccountFlagType
    admin_count: int = 0
    enabled: bool = True
    description: str = ""
    created_date: datetime | None = None


@dataclass
class ComputerInfo:
    total: int = 0
    enabled: int = 0
    disabled: int = 0
    os_breakdown: dict[str, int] = field(default_factory=dict)
    dcs: list[str] = field(default_factory=list)
    unconstrained: list[str] = field(default_factory=list)
    old_os: list[dict] = field(default_factory=list)
