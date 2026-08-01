from __future__ import annotations

import base64
import os
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from typing import Any, Dict, Iterable, Mapping, MutableSet

from pqcrypto.sign import sphincs_sha2_128f_simple as oracle_signature

from app.canonical_encoding import canonical_record, stable_private_hash


ORACLE_PUBLIC_KEY_ENV = "BL_ORACLE_PUBLIC_KEY_SPHINCS_B64"
ORACLE_TEST_PRIVATE_KEY_ENV = "BL_TEST_ORACLE_PRIVATE_KEY_SPHINCS_B64"
DEV_MODE_ENV = "BL_DEV"
ENVIRONMENT_ENV = "BL_ENV"
LOCAL_TEST_ORACLE_KEYS_ENV = "BL_ALLOW_LOCAL_TEST_ORACLE_KEYS"
VERIFIED = "VERIFIED"
UNVERIFIED = "UNVERIFIED"
ORACLE_SIGNATURE_SCHEME = "SPHINCS+-SHA2-128f-simple (PQClean C reference)"
ORACLE_PUBLIC_KEY_SIZE = oracle_signature.PUBLIC_KEY_SIZE
ORACLE_PRIVATE_KEY_SIZE = oracle_signature.SECRET_KEY_SIZE
ORACLE_SIGNATURE_SIZE = oracle_signature.SIGNATURE_SIZE
ORACLE_INTERFACE_STATUS = (
    "ASYMMETRIC SPHINCS+-SHA2-128f-simple (PQClean C reference) ORACLE INTERFACE ONLY; "
    "real HSM custody, real feeds, and in-circuit signature verification are NOT built; "
    "FIPS-205 standards upgrade pending liboqs build environment (cmake); PENDING CRYPTO AUDIT"
)

_DEV_PRIVATE_KEY_B64 = "n26mgGDhAMYGf8dAjQ+1MJfFK1yIYByQzkDgoIwP4JCPIV/ctQRUE1bRdtyfh2TzfDSOVNlTdjdU0AYaxk8vVA=="
_DEV_PUBLIC_KEY_B64 = "jyFf3LUEVBNW0Xbcn4dk83w0jlTZU3Y3VNAGGsZPL1Q="
_LOCAL_TEST_ENVS = {"", "local", "test", "unit", "ci"}


@dataclass(frozen=True)
class OracleAttestation:
    fact: str
    value: bool
    source_id: str
    valid_from: str
    valid_until: str
    claim_id: str
    claim_source_commitment: str
    tar_authorization_commitment: str
    nullifier: str
    signature: str

    @property
    def validity_window(self) -> str:
        return f"{self.valid_from}/{self.valid_until}"

    def signed_payload(self) -> bytes:
        return canonical_record(
            "oracle_attestation_v3",
            [
                self.fact,
                self.value,
                self.source_id,
                self.valid_from,
                self.valid_until,
                self.claim_id,
                self.claim_source_commitment,
                self.tar_authorization_commitment,
                self.nullifier,
            ],
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _dev_mode_allowed() -> bool:
    environment = os.environ.get(ENVIRONMENT_ENV, "").strip().lower()
    if environment not in _LOCAL_TEST_ENVS:
        return False
    return os.environ.get(DEV_MODE_ENV) == "1" and os.environ.get(LOCAL_TEST_ORACLE_KEYS_ENV) == "1"


def _b64decode_key(value: str, label: str, expected_size: int) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise RuntimeError(f"invalid oracle key encoding:{label}") from exc
    if len(raw) != expected_size:
        raise RuntimeError(f"invalid oracle key length:{label}")
    return raw


def _b64decode_signature(value: str) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise RuntimeError("invalid oracle signature encoding") from exc
    if len(raw) != ORACLE_SIGNATURE_SIZE:
        raise RuntimeError("invalid oracle signature length")
    return raw


def _public_key() -> bytes:
    value = os.environ.get(ORACLE_PUBLIC_KEY_ENV)
    if not value:
        if _dev_mode_allowed():
            value = _DEV_PUBLIC_KEY_B64
        else:
            raise RuntimeError(f"missing required oracle public key: {ORACLE_PUBLIC_KEY_ENV}")
    return _b64decode_key(value, ORACLE_PUBLIC_KEY_ENV, ORACLE_PUBLIC_KEY_SIZE)


def _test_private_key() -> bytes:
    value = os.environ.get(ORACLE_TEST_PRIVATE_KEY_ENV)
    if not value:
        if _dev_mode_allowed():
            value = _DEV_PRIVATE_KEY_B64
        else:
            raise RuntimeError(f"missing oracle signing key outside dev mode: {ORACLE_TEST_PRIVATE_KEY_ENV}")
    return _b64decode_key(value, ORACLE_TEST_PRIVATE_KEY_ENV, ORACLE_PRIVATE_KEY_SIZE)


def oracle_public_key_b64() -> str:
    key = _public_key()
    return base64.b64encode(key).decode("ascii")


def oracle_dev_private_key_b64() -> str:
    key = _test_private_key()
    return base64.b64encode(key).decode("ascii")


def oracle_attestation_nullifier(fact: str, source_id: str, claim_id: str, valid_from: str, valid_until: str) -> str:
    return stable_private_hash(["oracle_attestation_nullifier_v1", fact, source_id, claim_id, valid_from, valid_until])


def canonical_claim_source_commitment(value: int | str) -> str:
    raw = str(value).strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        raise ValueError("missing_claim_source_commitment")
    try:
        parsed = int(raw, 16) if any(ch in "abcdef" for ch in raw) or len(raw) == 64 else int(raw, 10)
    except ValueError as exc:
        raise ValueError("invalid_claim_source_commitment") from exc
    if parsed < 0:
        raise ValueError("invalid_claim_source_commitment")
    return f"{parsed:064x}"


def canonical_tar_authorization_commitment(value: int | str | None) -> str:
    if value is None:
        return f"{0:064x}"
    raw = str(value).strip()
    if not raw:
        return f"{0:064x}"
    lowered = raw.lower()
    try:
        if lowered.startswith("0x"):
            parsed = int(lowered[2:], 16)
        elif all(ch in "0123456789abcdef" for ch in lowered) and len(lowered) == 64:
            parsed = int(lowered, 16)
        elif raw.isdigit():
            parsed = int(raw, 10)
        else:
            from app.batch.stark_encoding import pack_felt_text

            parsed = pack_felt_text(raw)
    except ValueError as exc:
        raise ValueError("invalid_tar_authorization_commitment") from exc
    if parsed < 0:
        raise ValueError("invalid_tar_authorization_commitment")
    return f"{parsed:064x}"


def sign_oracle_attestation(
    fact: str,
    value: bool,
    source_id: str,
    valid_from: str,
    valid_until: str,
    claim_id: str,
    claim_source_commitment: int | str,
    tar_authorization_commitment: int | str | None = 0,
) -> str:
    nullifier = oracle_attestation_nullifier(fact, source_id, claim_id, valid_from, valid_until)
    unsigned = OracleAttestation(
        fact,
        value,
        source_id,
        valid_from,
        valid_until,
        claim_id,
        canonical_claim_source_commitment(claim_source_commitment),
        canonical_tar_authorization_commitment(tar_authorization_commitment),
        nullifier,
        "",
    )
    signature = oracle_signature.sign(_test_private_key(), unsigned.signed_payload())
    return base64.b64encode(signature).decode("ascii")


def make_test_attestation(
    fact: str,
    value: bool,
    *,
    source_id: str = "TEST_ORACLE_FIXTURE",
    valid_from: str = "2026-01-01",
    valid_until: str = "2026-12-31",
    claim_id: str = "BL-CLAIM-0001",
    claim_source_commitment: int | str = 0,
    tar_authorization_commitment: int | str | None = 0,
) -> OracleAttestation:
    nullifier = oracle_attestation_nullifier(fact, source_id, claim_id, valid_from, valid_until)
    canonical_commitment = canonical_claim_source_commitment(claim_source_commitment)
    canonical_tar_commitment = canonical_tar_authorization_commitment(tar_authorization_commitment)
    return OracleAttestation(
        fact=fact,
        value=value,
        source_id=source_id,
        valid_from=valid_from,
        valid_until=valid_until,
        claim_id=claim_id,
        claim_source_commitment=canonical_commitment,
        tar_authorization_commitment=canonical_tar_commitment,
        nullifier=nullifier,
        signature=sign_oracle_attestation(
            fact,
            value,
            source_id,
            valid_from,
            valid_until,
            claim_id,
            canonical_commitment,
            canonical_tar_commitment,
        ),
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
        claim_source_commitment=str(value.get("claim_source_commitment", "")),
        tar_authorization_commitment=str(value.get("tar_authorization_commitment", "0")),
        nullifier=str(value.get("nullifier", "")),
        signature=str(value.get("signature", "")),
    )


def _date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def verify_oracle_attestation(
    attestation: OracleAttestation | Mapping[str, Any],
    *,
    claim_id: str,
    claim_source_commitment: int | str | None = None,
    tar_authorization_commitment: int | str | None = None,
    now: date | None = None,
    replay_cache: MutableSet[str] | None = None,
) -> bool:
    item = _coerce_attestation(attestation)
    if not all(
        [
            item.fact,
            item.source_id,
            item.valid_from,
            item.valid_until,
            item.claim_id,
            item.claim_source_commitment,
            item.tar_authorization_commitment,
            item.nullifier,
            item.signature,
        ]
    ):
        return False
    if item.claim_id != claim_id:
        return False
    if claim_source_commitment is None:
        return False
    try:
        expected_claim_source = canonical_claim_source_commitment(claim_source_commitment)
        actual_claim_source = canonical_claim_source_commitment(item.claim_source_commitment)
    except ValueError:
        return False
    if actual_claim_source != expected_claim_source:
        return False
    if tar_authorization_commitment is not None:
        try:
            expected_tar_authorization = canonical_tar_authorization_commitment(tar_authorization_commitment)
            actual_tar_authorization = canonical_tar_authorization_commitment(item.tar_authorization_commitment)
        except ValueError:
            return False
        if actual_tar_authorization != expected_tar_authorization:
            return False
    expected_nullifier = oracle_attestation_nullifier(item.fact, item.source_id, item.claim_id, item.valid_from, item.valid_until)
    if item.nullifier != expected_nullifier:
        return False
    try:
        today = now or datetime.now(UTC).date()
        if not (_date(item.valid_from) <= today <= _date(item.valid_until)):
            return False
        signature = _b64decode_signature(item.signature)
        verified = oracle_signature.verify(_public_key(), item.signed_payload(), signature)
        if verified is not True:
            return False
    except (ValueError, RuntimeError):
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
    claim_source_commitment: int | str | None = None,
    tar_authorization_commitment: int | str | None = None,
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
        if not verify_oracle_attestation(
            item,
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
            tar_authorization_commitment=tar_authorization_commitment,
            replay_cache=replay_cache,
        ):
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
