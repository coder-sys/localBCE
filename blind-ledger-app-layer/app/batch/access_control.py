from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Set


ADMIN = "Admin"
OPERATOR = "Operator"
AUDITOR = "Auditor"


class AccessDenied(PermissionError):
    pass


@dataclass
class RoleBook:
    """Role routing only; no key material is exposed here.

    This is shaped for later enterprise SSO plus managed/HSM signing. Operators
    see ordinary roles, not wallets or seed phrases.
    """

    roles: Dict[str, Set[str]] = field(default_factory=lambda: {ADMIN: set(), OPERATOR: set(), AUDITOR: set()})

    @staticmethod
    def _validated_account(account: str) -> str:
        if not isinstance(account, str):
            raise ValueError("invalid account id")
        if not account or account != account.strip() or account != account.lower() or any(char.isspace() for char in account):
            raise ValueError("invalid account id")
        return account

    def grant(self, role: str, account: str) -> None:
        if role not in self.roles:
            raise ValueError("unknown role")
        self.roles[role].add(self._validated_account(account))

    def has(self, role: str, account: str) -> bool:
        try:
            normalized = self._validated_account(account)
        except ValueError:
            return False
        return normalized in self.roles.get(role, set())

    def can_submit_batch(self, account: str) -> bool:
        return self.has(ADMIN, account) or self.has(OPERATOR, account)

    def can_read_appeals(self, account: str) -> bool:
        return self.can_submit_batch(account) or self.has(AUDITOR, account)

    def require_batch_submitter(self, account: str) -> None:
        if not self.can_submit_batch(account):
            raise AccessDenied("account lacks batch submission role")

    def require_appeal_reader(self, account: str) -> None:
        if not self.can_read_appeals(account):
            raise AccessDenied("account lacks appeal queue role")
