"""Small, bounded operational owner for the Mirror V2 services.

The owner composes the existing Ingress, Core, and Recovery services.  It does
not own raw captures, database state, source truth, payment, clearance, or
publication.  All public failures and results are fixed-shape and sanitized.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import secrets
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from app.mirror import core_v2 as core
from app.mirror import core_v2_independent as core_independent
from app.mirror import ingress_v2 as ingress
from app.mirror import ingress_v2_independent as ingress_independent
from app.mirror import recovery_v2 as recovery
from app.mirror import recovery_v2_independent as recovery_independent
from app.mirror import writer_authority


SCHEMA = "mirror-operational-owner-v1"
SCHEMA_VERSION = 1
STATUS_COMPLETE = "COMPLETE"
OUTCOME_KEYS = (
    "eligible",
    "processed",
    "scheduled",
    "claimed",
    "admitted",
    "held",
    "acquisition_rejected",
    "admission_rejected",
    "claim_rejected",
    "core_recovered",
    "core_ingested",
    "core_pending",
    "recovery_created",
)
_HEX = frozenset("0123456789abcdef")
_MAX_OBSERVATION_BYTES = ingress_independent.MAX_OBSERVATION_BYTES
_MAX_VERIFICATION_RECEIPT_BYTES = ingress_independent.MAX_VERIFICATION_RECEIPT_BYTES


class OperationalOwnerError(ValueError):
    """Fixed public operational-owner error."""


@dataclass(frozen=True)
class OperationalConfigV1:
    """Pinned acquisition identity, policy/profile, and per-run bound."""

    acquisition_identity: str
    external_policy_digest: str
    profile_digest: str
    max_due: int = 16

    def __post_init__(self) -> None:
        if (
            type(self.acquisition_identity) is not str
            or not self.acquisition_identity
            or len(self.acquisition_identity) > 256
        ):
            raise OperationalOwnerError("mirror:operational-config")
        try:
            encoded = self.acquisition_identity.encode("ascii")
        except UnicodeEncodeError:
            raise OperationalOwnerError("mirror:operational-config") from None
        if not encoded or any(byte < 0x21 or byte > 0x7E for byte in encoded):
            raise OperationalOwnerError("mirror:operational-config")
        for value in (self.external_policy_digest, self.profile_digest):
            if (
                type(value) is not str
                or len(value) != 128
                or any(char not in _HEX for char in value)
            ):
                raise OperationalOwnerError("mirror:operational-config")
        if type(self.max_due) is not int or not 1 <= self.max_due <= 16:
            raise OperationalOwnerError("mirror:operational-config")


@dataclass(frozen=True)
class SanitizedObservationPayloadV1:
    """Exactly the two bounded non-PHI bytes handed to Ingress admission."""

    observation: bytes
    verification_receipt: bytes

    def __post_init__(self) -> None:
        if (
            type(self.observation) is not bytes
            or type(self.verification_receipt) is not bytes
            or not self.observation
            or not self.verification_receipt
            or len(self.observation) > _MAX_OBSERVATION_BYTES
            or len(self.verification_receipt) > _MAX_VERIFICATION_RECEIPT_BYTES
        ):
            raise OperationalOwnerError("mirror:operational-acquisition")
        try:
            ingress_independent.verify_observation_pair(self.observation, self.verification_receipt)
        except Exception:
            raise OperationalOwnerError("mirror:operational-acquisition") from None


class AcquisitionPort(Protocol):
    acquisition_identity: str
    external_policy_digest: str
    profile_digest: str

    def acquire(self, slot_id: str, scheduled_at: int, attempt: int) -> SanitizedObservationPayloadV1: ...

@dataclass(frozen=True)
class OperationalAggregateV1:
    schema: str
    schema_version: int
    status: str
    counts: Mapping[str, int]
    recovery_created: bool
    ingress_config_digest: str
    core_config_digest: str
    recovery_config_digest: str
    external_policy_digest: str
    profile_digest: str
    ingress_head_root: str
    ingress_sequence: int
    core_head_root: str
    core_sequence: int
    recovery_head_root: str
    recovery_sequence: int

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.schema_version != SCHEMA_VERSION or self.status != STATUS_COMPLETE:
            raise OperationalOwnerError("mirror:operational-result")
        if type(self.counts) is not MappingProxyType:
            object.__setattr__(self, "counts", MappingProxyType(dict(self.counts)))
        if tuple(self.counts) != OUTCOME_KEYS or any(type(value) is not int or value < 0 for value in self.counts.values()):
            raise OperationalOwnerError("mirror:operational-result")
        if type(self.recovery_created) is not bool:
            raise OperationalOwnerError("mirror:operational-result")
        for value in (
            self.ingress_config_digest,
            self.core_config_digest,
            self.recovery_config_digest,
            self.external_policy_digest,
            self.profile_digest,
            self.ingress_head_root,
            self.core_head_root,
            self.recovery_head_root,
        ):
            if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
                raise OperationalOwnerError("mirror:operational-result")
        for value in (self.ingress_sequence, self.core_sequence, self.recovery_sequence):
            if type(value) is not int or value < 0:
                raise OperationalOwnerError("mirror:operational-result")


def _admission_is_operational(error: BaseException) -> bool:
    try:
        value = str(error)
    except Exception:
        return True
    return (
        value.startswith("ingress:database")
        or value in {"ingress:busy", "ingress:capacity", "ingress:clock", "ingress:clock-rewind"}
    )


def _claim_is_operational(error: BaseException) -> bool:
    try:
        value = str(error)
    except Exception:
        return True
    return value in {
        "ingress:database-open",
        "ingress:database",
        "ingress:database-initialize",
        "ingress:busy",
        "ingress:capacity",
        "ingress:clock",
        "ingress:clock-rewind",
    }


class MirrorOperationalOwnerV1:
    """One locked, bounded owner for the three existing Mirror V2 services."""

    def __init__(
        self,
        root: str | Path,
        ingress_config: ingress.IngressConfigV2,
        core_config: core.CoreConfigV2,
        recovery_config: recovery.RecoveryConfigV2,
        acquisition_port: AcquisitionPort,
        custody: recovery.KeyCustodyPort,
        storage: recovery.RecoveryStoragePort,
        *,
        clock: Callable[[], int],
        operational_config: OperationalConfigV1,
    ) -> None:
        if not callable(clock):
            raise OperationalOwnerError("mirror:operational-config")
        if type(operational_config) is not OperationalConfigV1:
            raise OperationalOwnerError("mirror:operational-config")
        try:
            root_path = writer_authority.safe_root(root)
        except writer_authority.WriterAuthorityError:
            raise OperationalOwnerError("mirror:operational-root") from None
        if type(ingress_config) is not ingress.IngressConfigV2 or type(core_config) is not core.CoreConfigV2 or type(recovery_config) is not recovery.RecoveryConfigV2:
            raise OperationalOwnerError("mirror:operational-config")
        if (
            core_config.ingress_database_id != ingress_config.database_id
            or core_config.ingress_chain_id != ingress_config.chain_id
            or core_config.ingress_config_digest != ingress_config.digest
            or core_config.runtime_profile_digest != ingress_config.source_contract_digest
            or recovery_config.ingress_database_id != ingress_config.database_id
            or recovery_config.core_database_id != core_config.database_id
            or recovery_config.ingress_config_digest != ingress_config.digest
            or recovery_config.core_config_digest != core_config.digest
            or operational_config.profile_digest != ingress_config.source_contract_digest
        ):
            raise OperationalOwnerError("mirror:operational-config")
        try:
            acquisition_identity = getattr(acquisition_port, "acquisition_identity")
            external_policy_digest = getattr(acquisition_port, "external_policy_digest")
            profile_digest = getattr(acquisition_port, "profile_digest")
            custody_id = getattr(custody, "custody_id")
            storage_id = getattr(storage, "storage_id")
            acquire = getattr(acquisition_port, "acquire")
        except Exception:
            raise OperationalOwnerError("mirror:operational-config") from None
        if (
            type(acquisition_identity) is not str
            or acquisition_identity != operational_config.acquisition_identity
            or type(external_policy_digest) is not str
            or external_policy_digest != operational_config.external_policy_digest
            or type(profile_digest) is not str
            or profile_digest != operational_config.profile_digest
            or type(custody_id) is not str
            or custody_id != recovery_config.custody_id
            or type(storage_id) is not str
            or storage_id != recovery_config.storage_id
            or not callable(acquire)
        ):
            raise OperationalOwnerError("mirror:operational-config")

        self.root = root_path
        self.ingress_path = root_path / "ingress.sqlite"
        self.core_path = root_path / "core.sqlite"
        self.recovery_path = root_path / "recovery.sqlite"
        self.lock_path = root_path / "operational.lock"
        self.ingress_config = ingress_config
        self.core_config = core_config
        self.recovery_config = recovery_config
        self.acquisition = acquisition_port
        self.custody = custody
        self.storage = storage
        self.clock = clock
        self.operational_config = operational_config
        self._closed = False
        self._authority: writer_authority.WriterAuthority | None = None
        self.ingress: ingress.IngressServiceV2 | None = None
        self.core: core.CoreServiceV2 | None = None
        self.recovery: recovery.RecoveryServiceV2 | None = None
        try:
            self._authority = writer_authority.WriterAuthority(root_path)
            initial_layout = self._authority.layout(allow_missing_stores=True)
            locked_layout = self._authority.layout(allow_missing_stores=True)
            self._assert_layout_transition(initial_layout, locked_layout)
            self._assert_root_lock_identity()
            before_ingress = self._authority.layout(allow_missing_stores=True)
            self._assert_root_lock_identity()
            self.ingress = ingress.IngressServiceV2(self.ingress_path, ingress_config, clock=self._authority.current_run_time, authority=self._authority)
            after_ingress = self._authority.layout(allow_missing_stores=True)
            self._assert_layout_transition(before_ingress, after_ingress)
            if after_ingress["ingress.sqlite"] is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_root_lock_identity()
            before_core = self._authority.layout(allow_missing_stores=True)
            self._assert_root_lock_identity()
            self.core = core.CoreServiceV2(self.core_path, core_config, clock=self._authority.current_run_time, authority=self._authority)
            after_core = self._authority.layout(allow_missing_stores=True)
            self._assert_layout_transition(before_core, after_core)
            if after_core["core.sqlite"] is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_root_lock_identity()
            before_recovery = self._authority.layout(allow_missing_stores=True)
            self._assert_root_lock_identity()
            self.recovery = recovery.RecoveryServiceV2(self.recovery_path, recovery_config, custody, storage, authority=self._authority)
            after_recovery = self._authority.layout(allow_missing_stores=True)
            self._assert_layout_transition(before_recovery, after_recovery)
            if after_recovery["recovery.sqlite"] is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_root_lock_identity()
            self._store_identities = self._read_store_identities()
            self._assert_owner_identity()
        except OperationalOwnerError:
            self.close()
            raise
        except writer_authority.WriterAuthorityError as error:
            self.close()
            code = {
                "writer:lock": "mirror:operational-lock",
                "writer:root": "mirror:operational-root",
                "writer:indeterminate": "mirror:operational-indeterminate",
            }.get(str(error), "mirror:operational-initialize")
            raise OperationalOwnerError(code) from None
        except (ingress.IngressError, core.CoreError, recovery.RecoveryError):
            self.close()
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        except Exception:
            self.close()
            raise OperationalOwnerError("mirror:operational-initialize") from None

    def _read_store_identities(self) -> dict[str, tuple[int, int, int]]:
        if self._authority is None:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        result = self._authority.layout(allow_missing_stores=False)
        values: dict[str, tuple[int, int, int]] = {}
        for name in ("ingress.sqlite", "core.sqlite", "recovery.sqlite", "operational.lock"):
            value = result.get(name)
            if value is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            values[name] = value
        return values

    @staticmethod
    def _assert_layout_transition(
        before: Mapping[str, tuple[int, int, int] | None],
        after: Mapping[str, tuple[int, int, int] | None],
    ) -> None:
        for name in set(before) | set(after):
            if before.get(name) is not None and after.get(name) != before[name]:
                raise OperationalOwnerError("mirror:operational-indeterminate")

    def _assert_root_lock_identity(self) -> None:
        if self._closed or self._authority is None:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        try:
            self._authority.assert_identity()
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None

    def _assert_port_identity(self) -> None:
        try:
            acquisition_identity = getattr(self.acquisition, "acquisition_identity")
            external_policy_digest = getattr(self.acquisition, "external_policy_digest")
            profile_digest = getattr(self.acquisition, "profile_digest")
            custody_id = getattr(self.custody, "custody_id")
            storage_id = getattr(self.storage, "storage_id")
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        if (
            type(acquisition_identity) is not str
            or acquisition_identity != self.operational_config.acquisition_identity
            or type(external_policy_digest) is not str
            or external_policy_digest != self.operational_config.external_policy_digest
            or type(profile_digest) is not str
            or profile_digest != self.operational_config.profile_digest
            or type(custody_id) is not str
            or custody_id != self.recovery_config.custody_id
            or type(storage_id) is not str
            or storage_id != self.recovery_config.storage_id
        ):
            raise OperationalOwnerError("mirror:operational-indeterminate")

    def _assert_owner_identity(self) -> None:
        if self._closed:
            raise OperationalOwnerError("mirror:operational-closed")
        try:
            self._assert_root_lock_identity()
            current = self._read_store_identities()
            if current != self._store_identities:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_port_identity()
        except OperationalOwnerError:
            raise
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None

    @staticmethod
    def _validate_schedule(values: tuple[int, ...], config: ingress.IngressConfigV2) -> None:
        if type(values) is not tuple or len(values) > 16:
            raise OperationalOwnerError("mirror:operational-input")
        for value in values:
            if (
                type(value) is not int
                or not config.effective_start <= value <= config.effective_end
                or (value - config.effective_start) % config.cadence_seconds
            ):
                raise OperationalOwnerError("mirror:operational-input")
        if len(set(values)) != len(values):
            raise OperationalOwnerError("mirror:operational-input")

    def _validate_eligible(self, values: object, limit: int) -> tuple[ingress.EligibleSlotV1, ...]:
        if type(values) is not tuple or len(values) > limit:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        seen: set[str] = set()
        for slot in values:
            if type(slot) is not ingress.EligibleSlotV1:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            if (
                type(slot.slot_id) is not str
                or len(slot.slot_id) != 128
                or any(char not in _HEX for char in slot.slot_id)
                or slot.slot_id in seen
                or type(slot.scheduled_at) is not int
                or not self.ingress_config.effective_start <= slot.scheduled_at <= self.ingress_config.effective_end
                or (slot.scheduled_at - self.ingress_config.effective_start) % self.ingress_config.cadence_seconds
                or type(slot.attempt) is not int
                or not 0 <= slot.attempt <= self.ingress_config.max_attempts
                or type(slot.state) is not str
                or slot.state not in {"DUE", "LEASED"}
            ):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            seen.add(slot.slot_id)
        return values

    @staticmethod
    def _validate_projection(values: object, limit: int) -> tuple[str, ...]:
        if type(values) is not tuple or len(values) > limit:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        seen: set[str] = set()
        for value in values:
            if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value) or value in seen:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            seen.add(value)
        return values

    def _reconciliation_pending(self) -> tuple[str, ...]:
        assert self.ingress is not None and self.core is not None
        try:
            self._assert_owner_identity()
            ingress_result = ingress_independent.verify_database(
                self.ingress_path,
                expected_database_id=self.ingress_config.database_id,
                expected_config_digest=self.ingress_config.digest,
            )
            self._assert_owner_identity()
            core_result = core_independent.verify_database(
                self.core_path,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
                ingress_path=self.ingress_path,
            )
            self._assert_owner_identity()
            if ingress_result.get("database_id") != self.ingress_config.database_id or core_result.get("ingress_bound") is not True:
                raise ValueError("mirror:reconciliation-binding")
            quarantined = self.ingress._operational_quarantined_artifact_ids(self.ingress_config.max_slots)
            self._assert_owner_identity()
            represented = self.core._operational_represented_ingress_artifact_ids(self.ingress_config.max_slots)
            self._assert_owner_identity()
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        quarantined = self._validate_projection(quarantined, self.ingress_config.max_slots)
        represented = self._validate_projection(represented, self.ingress_config.max_slots)
        quarantined_set = set(quarantined)
        represented_set = set(represented)
        if not represented_set.issubset(quarantined_set):
            raise OperationalOwnerError("mirror:operational-indeterminate")
        if tuple(value for value in quarantined if value in represented_set) != represented:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        return tuple(value for value in quarantined if value not in represented_set)

    def _verified_recovery_point_count(self) -> int:
        """Read the recovery count from one independently verified snapshot."""

        self._assert_owner_identity()
        try:
            result = recovery_independent.verify_database(
                self.recovery_path,
                expected_database_id=self.recovery_config.database_id,
                expected_config_digest=self.recovery_config.digest,
            )
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        self._assert_owner_identity()
        count = result.get("point_count")
        if type(count) is not int or count < 0 or count > recovery_independent.MAX_RECOVERY_POINTS:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        return count

    def _process_slot(self, slot: ingress.EligibleSlotV1, counts: dict[str, int], admitted: list[str]) -> None:
        self._assert_owner_identity()
        assert self.ingress is not None
        try:
            lease_token = secrets.token_hex(32)
            receipt = self.ingress.claim_slot(slot.slot_id, lease_token=lease_token)
        except (ingress.IngressConflictError, ingress.IngressError) as error:
            if _claim_is_operational(error):
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            counts["claim_rejected"] += 1
            return
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        self._assert_owner_identity()
        if type(receipt) is not ingress.IngressReceipt or type(receipt.next_state) is not str:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        counts["claimed"] += 1
        if receipt.next_state == "HELD":
            counts["held"] += 1
            counts["processed"] += 1
            return
        if receipt.next_state != "LEASED" or type(slot.attempt) is not int or slot.attempt < 0:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        attempt = slot.attempt + 1
        try:
            self._assert_port_identity()
            assert self._authority is not None
            with self._authority.external_scope():
                payload = self.acquisition.acquire(slot.slot_id, slot.scheduled_at, attempt)
        except Exception:
            self._assert_owner_identity()
            counts["acquisition_rejected"] += 1
            counts["processed"] += 1
            return
        if type(payload) is not SanitizedObservationPayloadV1:
            self._assert_owner_identity()
            counts["acquisition_rejected"] += 1
            counts["processed"] += 1
            return
        self._assert_owner_identity()
        try:
            admitted_receipt = self.ingress.admit_observation(
                payload.observation,
                payload.verification_receipt,
                scheduled_at=slot.scheduled_at,
                attempt=attempt,
                lease_token=lease_token,
            )
        except (ingress.IngressConflictError, ingress.IngressError) as error:
            if _admission_is_operational(error):
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            self._assert_owner_identity()
            counts["admission_rejected"] += 1
            counts["processed"] += 1
            return
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        self._assert_owner_identity()
        if type(admitted_receipt) is not ingress.IngressReceipt:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        if type(admitted_receipt.next_state) is not str or admitted_receipt.next_state != "QUARANTINED" or type(admitted_receipt.artifact_id) is not str or len(admitted_receipt.artifact_id) != 128 or any(char not in _HEX for char in admitted_receipt.artifact_id):
            counts["admission_rejected"] += 1
            counts["processed"] += 1
            return
        admitted.append(admitted_receipt.artifact_id)
        counts["admitted"] += 1
        counts["processed"] += 1

    def _verify_all(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        assert self._authority is not None
        try:
            self._assert_owner_identity()
            ingress_result = ingress_independent.verify_database(
                self.ingress_path,
                expected_database_id=self.ingress_config.database_id,
                expected_config_digest=self.ingress_config.digest,
            )
            self._assert_owner_identity()
            core_result = core_independent.verify_database(
                self.core_path,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
                ingress_path=self.ingress_path,
            )
            self._assert_owner_identity()
            recovery_result = recovery_independent.verify_database(
                self.recovery_path,
                expected_database_id=self.recovery_config.database_id,
                expected_config_digest=self.recovery_config.digest,
            )
            if core_result.get("ingress_bound") is not True:
                raise ValueError("core-bound")
            ingress_latest = ingress_result.get("latest_observed_at")
            core_latest = core_result.get("latest_observed_at")
            pending = recovery_result.get("object_pending_generation")
            if (
                type(ingress_latest) is not int
                or ingress_latest < 0
                or type(core_latest) is not int
                or core_latest < 0
                or pending is not None
                and (type(pending) is not int or not 1 <= pending <= recovery_independent.MAX_RECOVERY_POINTS)
            ):
                raise ValueError("chronology-summary")
            if self._authority.current_run_time() < ingress_latest or self._authority.current_run_time() < core_latest:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            return ingress_result, core_result, recovery_result
        except OperationalOwnerError:
            raise
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None

    def run(
        self,
        scheduled_at: tuple[int, ...] = (),
        *,
        recovery_generation: int | None = None,
    ) -> OperationalAggregateV1:
        assert self._authority is not None
        self._assert_owner_identity()
        try:
            with self._authority.run_scope():
                with self._authority.external_scope():
                    try:
                        run_now = self.clock()
                    except Exception:
                        raise OperationalOwnerError("mirror:operational-clock") from None
                    if type(run_now) is not int or run_now < 0:
                        raise OperationalOwnerError("mirror:operational-clock")
                    self._authority.set_run_time(run_now)
                return self._run(scheduled_at, recovery_generation=recovery_generation)
        except OperationalOwnerError:
            raise
        except writer_authority.WriterAuthorityError:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None

    def _run(
        self,
        scheduled_at: tuple[int, ...] = (),
        *,
        recovery_generation: int | None = None,
    ) -> OperationalAggregateV1:
        """Process at most ``max_due`` slots and verify all three stores."""

        self._assert_owner_identity()
        self._validate_schedule(scheduled_at, self.ingress_config)
        if recovery_generation is not None and (
            type(recovery_generation) is not int
            or not 1 <= recovery_generation <= recovery_independent.MAX_RECOVERY_POINTS
        ):
            raise OperationalOwnerError("mirror:operational-input")
        assert self.ingress is not None and self.core is not None and self.recovery is not None
        ingress_result, core_result, recovery_result = self._verify_all()
        pending_generation = recovery_result.get("object_pending_generation")
        if pending_generation is not None:
            self._assert_owner_identity()
            try:
                self.recovery.create_point(
                    self.ingress_path,
                    self.core_path,
                    generation=int(pending_generation),
                )
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            self._assert_owner_identity()
            ingress_result, core_result, recovery_result = self._verify_all()
        counts = {key: 0 for key in OUTCOME_KEYS}
        admitted: list[str] = []
        pending = self._reconciliation_pending()
        budget = self.operational_config.max_due
        recovered = pending[:budget]
        if recovered:
            self._assert_owner_identity()
            try:
                self.core.ingest_sources(self.ingress_path, tuple(recovered))
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            self._assert_owner_identity()
            if set(recovered).intersection(self._reconciliation_pending()):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            counts["core_recovered"] = len(recovered)
            budget -= len(recovered)
        try:
            first = self.ingress.eligible_slots(budget) if budget else ()
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        first = self._validate_eligible(first, budget) if budget else ()
        counts["eligible"] += len(first)
        for slot in first:
            self._process_slot(slot, counts, admitted)
        remaining = budget - len(first)
        self._assert_owner_identity()
        for value in scheduled_at:
            try:
                self._assert_owner_identity()
                self.ingress.ensure_slot(value)
                self._assert_owner_identity()
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            counts["scheduled"] += 1
        if remaining:
            try:
                second = self.ingress.eligible_slots(remaining)
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            second = self._validate_eligible(second, remaining)
            counts["eligible"] += len(second)
            for slot in second:
                self._process_slot(slot, counts, admitted)
        if admitted:
            if len(set(admitted)) != len(admitted):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_owner_identity()
            try:
                self.core.ingest_sources(self.ingress_path, tuple(admitted))
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            self._assert_owner_identity()
            if set(admitted).intersection(self._reconciliation_pending()):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            counts["core_ingested"] = len(admitted)
        recovery_created = False
        if recovery_generation is not None:
            self._assert_owner_identity()
            try:
                self._assert_port_identity()
                before_points = self._verified_recovery_point_count()
                receipt = self.recovery.create_point(self.ingress_path, self.core_path, generation=recovery_generation)
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            self._assert_owner_identity()
            after_points = self._verified_recovery_point_count()
            point_delta = after_points - before_points
            if point_delta not in (0, 1):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            if type(receipt) is not recovery.RecoveryReceipt or type(receipt.state) is not str or receipt.state not in {"VERIFIED", "PUBLISHED"}:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            recovery_created = point_delta == 1
            counts["recovery_created"] = point_delta
        ingress_result, core_result, recovery_result = self._verify_all()
        final_pending = self._reconciliation_pending()
        counts["core_pending"] = len(final_pending)
        self._assert_owner_identity()
        try:
            return OperationalAggregateV1(
                schema=SCHEMA,
                schema_version=SCHEMA_VERSION,
                status=STATUS_COMPLETE,
                counts=MappingProxyType(dict(counts)),
                recovery_created=recovery_created,
                ingress_config_digest=self.ingress_config.digest,
                core_config_digest=self.core_config.digest,
                recovery_config_digest=self.recovery_config.digest,
                external_policy_digest=self.operational_config.external_policy_digest,
                profile_digest=self.operational_config.profile_digest,
                ingress_head_root=str(ingress_result["head_root"]),
                ingress_sequence=int(ingress_result["sequence"]),
                core_head_root=str(core_result["head_root"]),
                core_sequence=int(core_result["sequence"]),
                recovery_head_root=str(recovery_result["head_root"]),
                recovery_sequence=int(recovery_result["sequence"]),
            )
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for service in (self.ingress, self.core, self.recovery):
            close = getattr(service, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
        if self._authority is not None:
            self._authority.close()
            self._authority = None

    def __enter__(self) -> "MirrorOperationalOwnerV1":
        self._assert_owner_identity()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


__all__ = [
    "SCHEMA",
    "SCHEMA_VERSION",
    "STATUS_COMPLETE",
    "OUTCOME_KEYS",
    "OperationalOwnerError",
    "OperationalConfigV1",
    "AcquisitionPort",
    "SanitizedObservationPayloadV1",
    "OperationalAggregateV1",
    "MirrorOperationalOwnerV1",
]
