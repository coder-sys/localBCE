from __future__ import annotations

import base64
import os
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from typing import Any, Dict, Iterable, Mapping, MutableSet

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from app.canonical_encoding import canonical_record, stable_private_hash


ORACLE_PUBLIC_KEY_ENV = "BL_ORACLE_PUBLIC_KEY_ED25519_B64"
ORACLE_TEST_PRIVATE_KEY_ENV = "BL_TEST_ORACLE_PRIVATE_KEY_ED25519_B64"
DEV_MODE_ENV = "BL_DEV"
ENVIRONMENT_ENV = "BL_ENV"
VERIFIED = "VERIFIED"
UNVERIFIED = "UNVERIFIED"
ORACLE_INTERFACE_STATUS = (
    "ASYMMETRIC ED25519 ORACLE INTERFACE ONLY; real HSM custody, real feeds, "
    "and in-circuit signature verification are NOT built; PENDING CRYPTO AUDIT"
)

_DEV_PRIVATE_KEY_B64 = "E0qybn/TJ4aoBeIwWlBf1sjyE98tFywRZw2zPGRPp+8="
_DEV_PUBLIC_KEY_B64 = "yHtNJ2bSwHJTdzhoZdZipkDXEg6CeryZIqFVigrk/TY="


@dataclass(frozen=True)
class OracleAttestation:
    fact: str
    value: bool
    source_id: str
    valid_from: str
    valid_until: str
    claim_id: str
    nullifier: str
    signature: str

    @property
    def validity_window(self) -> str:
        return f"{self.valid_from}/{self.valid_until}"

    def signed_payload(self) -> bytes:
        return canonical_record(
            "oracle_attestation_v2",
            [
                self.fact,
                self.value,
                self.source_id,
                self.valid_from,
                self.valid_until,
                self.claim_id,
                self.nullifier,
            ],
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _dev_mode_allowed() -> bool:
    if os.environ.get(ENVIRONMENT_ENV, "").strip().lower() in {"prod", "production"}:
        return False
    return os.environ.get(DEV_MODE_ENV) == "1"


def _b64decode_key(value: str, label: str) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise RuntimeError(f"invalid oracle key encoding:{label}") from exc
    if len(raw) != 32:
        raise RuntimeError(f"invalid oracle key length:{label}")
    return raw


def _public_key() -> Ed25519PublicKey:
    value = os.environ.get(ORACLE_PUBLIC_KEY_ENV)
    if not value:
        if _dev_mode_allowed():
            value = _DEV_PUBLIC_KEY_B64
        else:
            raise RuntimeError(f"missing required oracle public key: {ORACLE_PUBLIC_KEY_ENV}")
    return Ed25519PublicKey.from_public_bytes(_b64decode_key(value, ORACLE_PUBLIC_KEY_ENV))


def _test_private_key() -> Ed25519PrivateKey:
    value = os.environ.get(ORACLE_TEST_PRIVATE_KEY_ENV)
    if not value:
        if _dev_mode_allowed():
            value = _DEV_PRIVATE_KEY_B64
        else:
            raise RuntimeError(f"missing oracle signing key outside dev mode: {ORACLE_TEST_PRIVATE_KEY_ENV}")
    return Ed25519PrivateKey.from_private_bytes(_b64decode_key(value, ORACLE_TEST_PRIVATE_KEY_ENV))


def oracle_public_key_b64() -> str:
    key = _public_key()
    return base64.b64encode(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def oracle_dev_private_key_b64() -> str:
    key = _test_private_key()
    return base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode("ascii")


def oracle_attestation_nullifier(fact: str, source_id: str, claim_id: str, valid_from: str, valid_until: str) -> str:
    return stable_private_hash(["oracle_attestation_nullifier_v1", fact, source_id, claim_id, valid_from, valid_until])


def sign_oracle_attestation(
    fact: str,
    value: bool,
    source_id: str,
    valid_from: str,
    valid_until: str,
    claim_id: str,
) -> str:
    nullifier = oracle_attestation_nullifier(fact, source_id, claim_id, valid_from, valid_until)
    unsigned = OracleAttestation(fact, value, source_id, valid_from, valid_until, claim_id, nullifier, "")
    signature = _test_private_key().sign(unsigned.signed_payload())
    return base64.b64encode(signature).decode("ascii")


def make_test_attestation(
    fact: str,
    value: bool,
    *,
    source_id: str = "TEST_ORACLE_FIXTURE",
    valid_from: str = "2026-01-01",
    valid_until: str = "2026-12-31",
    claim_id: str = "BL-CLAIM-0001",
) -> OracleAttestation:
    nullifier = oracle_attestation_nullifier(fact, source_id, claim_id, valid_from, valid_until)
    return OracleAttestation(
        fact=fact,
        value=value,
        source_id=source_id,
        valid_from=valid_from,
        valid_until=valid_until,
        claim_id=claim_id,
        nullifier=nullifier,
        signature=sign_oracle_attestation(fact, value, source_id, valid_from, valid_until, claim_id),
    )


def _coerce_attestation(value: OracleAttestation | Mapping[str, Any]) -> OracleAttestation:
    if isinstance(value, OracleAttestation):
        return value
    valid_from = str(value.get("valid_from", ""))
    valid_until = str(value.get("valid_until", ""))
    if not valid_from and not valid_until and value.get("validity_window"):
        parts = str(value["validity_window"]).split("/", 1)
        valid_from = parts[0]
        valid_until = parts[1] if len(parts) > 1 else ""
    return OracleAttestation(
        fact=str(value.get("fact", "")),
        value=bool(value.get("value", False)),
        source_id=str(value.get("source_id", "")),
        valid_from=valid_from,
        valid_until=valid_until,
        claim_id=str(value.get("claim_id", "")),
        nullifier=str(value.get("nullifier", "")),
        signature=str(value.get("signature", "")),
    )


def _date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def verify_oracle_attestation(
    attestation: OracleAttestation | Mapping[str, Any],
    *,
    claim_id: str,
    now: date | None = None,
    replay_cache: MutableSet[str] | None = None,
) -> bool:
    item = _coerce_attestation(attestation)
    if not all([item.fact, item.source_id, item.valid_from, item.valid_until, item.claim_id, item.nullifier, item.signature]):
        return False
    if item.claim_id != claim_id:
        return False
    expected_nullifier = oracle_attestation_nullifier(item.fact, item.source_id, item.claim_id, item.valid_from, item.valid_until)
    if item.nullifier != expected_nullifier:
        return False
    try:
        today = now or datetime.now(UTC).date()
        if not (_date(item.valid_from) <= today <= _date(item.valid_until)):
            return False
        signature = base64.b64decode(item.signature.encode("ascii"), validate=True)
        _public_key().verify(signature, item.signed_payload())
    except (InvalidSignature, ValueError, RuntimeError):
        return False
    if replay_cache is not None:
        if item.nullifier in replay_cache:
            return False
        replay_cache.add(item.nullifier)
    return True


def resolve_attested_flags(
    raw_flags: Mapping[str, Any] | None,
    attestations: Iterable[OracleAttestation | Mapping[str, Any]] | None,
    *,
    strict: bool = True,
    required_facts: Iterable[str] = (),
    claim_id: str,
    replay_cache: MutableSet[str] | None = None,
) -> tuple[Dict[str, Any], Dict[str, str]]:
    flags: Dict[str, Any] = dict(raw_flags or {})
    status: Dict[str, str] = {key: UNVERIFIED for key in flags}
    seen_in_payload: set[str] = set()
    for raw in attestations or []:
        item = _coerce_attestation(raw)
        if item.nullifier in seen_in_payload:
            if strict:
                raise ValueError(f"oracle_attestation_replay:{item.fact or 'missing_fact'}")
            status[item.fact or "missing_fact"] = UNVERIFIED
            continue
        seen_in_payload.add(item.nullifier)
        if not verify_oracle_attestation(item, claim_id=claim_id, replay_cache=replay_cache):
            if strict:
                raise ValueError(f"oracle_attestation_invalid:{item.fact or 'missing_fact'}")
            status[item.fact or "missing_fact"] = UNVERIFIED
            continue
        flags[item.fact] = item.value
        status[item.fact] = VERIFIED

    missing = [fact for fact in required_facts if status.get(fact) != VERIFIED]
    if strict and missing:
        raise ValueError(f"oracle_attestation_required:{','.join(sorted(missing))}")
    for fact in required_facts:
        status.setdefault(fact, UNVERIFIED)
    return flags, status
