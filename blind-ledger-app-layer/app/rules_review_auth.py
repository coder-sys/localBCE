from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Any


REVIEW_ROLES = {"policy_reviewer", "legal_verifier", "rules_admin"}


class RulesAuthError(RuntimeError):
    pass


@dataclass(frozen=True)
class RulesPrincipal:
    subject: str
    roles: frozenset[str]

    def require(self, role: str) -> None:
        if role not in self.roles:
            raise RulesAuthError(f"{role} role is required")


def _is_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value.lower() == "localhost"


def _roles_from_claims(claims: dict[str, Any]) -> frozenset[str]:
    values: set[str] = set()
    roles = claims.get("roles")
    if isinstance(roles, list):
        values.update(str(role) for role in roles)
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict) and isinstance(realm_access.get("roles"), list):
        values.update(str(role) for role in realm_access["roles"])
    return frozenset(values.intersection(REVIEW_ROLES))


def authenticate_rules_request(
    *,
    client_host: str,
    authorization: str | None,
    local_subject: str | None = None,
    local_roles: str | None = None,
) -> RulesPrincipal:
    if os.environ.get("RULES_REVIEW_LOCAL_MOCK") == "1":
        bind_host = os.environ.get("RULES_REVIEW_BIND_HOST", "127.0.0.1")
        if not _is_loopback(client_host) or not _is_loopback(bind_host):
            raise RulesAuthError("local mock identity is allowed only on loopback")
        subject = str(local_subject or "").strip()
        roles = frozenset(part.strip() for part in str(local_roles or "").split(",") if part.strip())
        if not subject or not roles or not roles.issubset(REVIEW_ROLES):
            raise RulesAuthError("valid local reviewer subject and roles are required")
        return RulesPrincipal(subject=subject, roles=roles)

    if not authorization or not authorization.startswith("Bearer "):
        raise RulesAuthError("OIDC bearer token is required")
    issuer = os.environ.get("RULES_OIDC_ISSUER")
    audience = os.environ.get("RULES_OIDC_AUDIENCE")
    jwks_url = os.environ.get("RULES_OIDC_JWKS_URL")
    if not issuer or not audience or not jwks_url:
        raise RulesAuthError("OIDC issuer, audience, and JWKS URL must be configured")
    try:
        import jwt

        key = jwt.PyJWKClient(jwks_url).get_signing_key_from_jwt(authorization[7:]).key
        claims = jwt.decode(
            authorization[7:],
            key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except Exception as exc:
        raise RulesAuthError("OIDC token validation failed") from exc
    roles = _roles_from_claims(claims)
    if not roles:
        raise RulesAuthError("OIDC token has no rules-review role")
    return RulesPrincipal(subject=str(claims["sub"]), roles=roles)
