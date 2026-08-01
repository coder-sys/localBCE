"""Gate 2E-5 state migration, rollback, recovery, and failure reference.

This module is a synthetic, nonactivating state-plane controller.  It makes
the state publication boundary explicit: a complete S4 composition is
independently replayed before a compare-and-swap publication, migration
preserves the authenticated logical-state identities while rotating the
versioned plane, and recovery can only restore a known complete checkpoint at
a strictly newer epoch.  Every failed operation leaves the immutable current
checkpoint unchanged.

The equivalence record is reference evidence, not a migration theorem.  It
binds the old/new roots, state manifest, sequence, layout, parameter,
verifier, and migration version; it does not claim that a production witness
has been generated or that old private bytes can be reinterpreted.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha3_512
from threading import RLock
from typing import Final

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from experiments.bl_pq512_crypto_foundation.atomic_state_composition import (
    AtomicComposition,
    AtomicCompositionError,
    independently_verify_composition,
)
from experiments.bl_pq512_crypto_foundation.state_interface import StateTransitionV1


STATUS: Final[str] = "S5_STATE_MIGRATION_RECOVERY_V1_SYNTHETIC_REFERENCE_NONPRODUCTION"
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False
MIGRATION_EQUIVALENCE_STATUS: Final[str] = "REFERENCE_EQUIVALENCE_ONLY"
CHECKPOINT_VERSION: Final[int] = 1

_LAYOUT_DOMAIN = b"BL/PQ512/S5/STATE-LAYOUT/v1\x00"
_STATE_DIGEST_DOMAIN = b"BL/PQ512/S5/STATE-DIGEST/v1\x00"
_CHECKPOINT_DOMAIN = b"BL/PQ512/S5/CHECKPOINT/v1\x00"
_PUBLICATION_DOMAIN = b"BL/PQ512/S5/PUBLICATION/v1\x00"
_MIGRATION_EQUIVALENCE_DOMAIN = b"BL/PQ512/S5/MIGRATION-EQUIVALENCE/v1\x00"
_MIGRATION_RECORD_DOMAIN = b"BL/PQ512/S5/MIGRATION-RECORD/v1\x00"
_RECOVERY_EVENT_DOMAIN = b"BL/PQ512/S5/RECOVERY-EVENT/v1\x00"


class MigrationRecoveryError(ValueError):
    """Stable fail-closed error for the S5 state-plane boundary."""


def _synthetic() -> None:
    require_synthetic_reference_enabled()


def _text(value: object, label: str, maximum: int = 96) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise MigrationRecoveryError(f"s5_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise MigrationRecoveryError(f"s5_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise MigrationRecoveryError(f"s5_{label}_nul")
    return encoded


def _bytes(value: object, label: str, length: int = 64, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise MigrationRecoveryError(f"s5_{label}_length_invalid")
    if nonzero and not any(value):
        raise MigrationRecoveryError(f"s5_{label}_zero")
    return value


def _u64(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise MigrationRecoveryError(f"s5_{label}_invalid")
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise MigrationRecoveryError("s5_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _u64_bytes(value: int) -> bytes:
    return value.to_bytes(8, "big")


def derive_state_layout_identity(composition: AtomicComposition) -> bytes:
    """Derive the S5 layout identity from the already-bound S4 statement."""

    _synthetic()
    if type(composition) is not AtomicComposition:
        raise MigrationRecoveryError("s5_composition_type_invalid")
    return _hash(
        _LAYOUT_DOMAIN,
        _text(composition.profile_id, "profile_id"),
        _text(composition.transition.parameter_identity, "parameter_identity"),
        composition.commitment.statement_digest_512,
    )


def _state_digest(
    profile_id: str,
    layout_id_512: bytes,
    parameter_identity: str,
    verifier_identity_512: bytes,
    epoch: int,
    sequence: int,
    state_root_512: bytes,
    state_manifest_digest_512: bytes,
) -> bytes:
    return _hash(
        _STATE_DIGEST_DOMAIN,
        _text(profile_id, "profile_id"),
        layout_id_512,
        _text(parameter_identity, "parameter_identity"),
        verifier_identity_512,
        _u64_bytes(epoch),
        _u64_bytes(sequence),
        state_root_512,
        state_manifest_digest_512,
    )


def _checkpoint_digest(
    profile_id: str,
    layout_id_512: bytes,
    parameter_identity: str,
    verifier_identity_512: bytes,
    epoch: int,
    sequence: int,
    state_root_512: bytes,
    state_manifest_digest_512: bytes,
    state_digest_512: bytes,
) -> bytes:
    return _hash(
        _CHECKPOINT_DOMAIN,
        _u64_bytes(CHECKPOINT_VERSION),
        _text(profile_id, "profile_id"),
        layout_id_512,
        _text(parameter_identity, "parameter_identity"),
        verifier_identity_512,
        _u64_bytes(epoch),
        _u64_bytes(sequence),
        state_root_512,
        state_manifest_digest_512,
        state_digest_512,
    )


@dataclass(frozen=True, slots=True)
class StateCheckpoint:
    profile_id: str
    layout_id_512: bytes
    parameter_identity: str
    verifier_identity_512: bytes
    epoch: int
    sequence: int
    state_root_512: bytes
    state_manifest_digest_512: bytes
    state_digest_512: bytes = b""
    checkpoint_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        _text(self.profile_id, "profile_id", 32)
        _bytes(self.layout_id_512, "layout_id", nonzero=True)
        _text(self.parameter_identity, "parameter_identity", 96)
        _bytes(self.verifier_identity_512, "verifier_identity", nonzero=True)
        _u64(self.epoch, "epoch")
        _u64(self.sequence, "sequence")
        _bytes(self.state_root_512, "state_root", nonzero=True)
        _bytes(self.state_manifest_digest_512, "state_manifest", nonzero=True)
        expected_state = _state_digest(
            self.profile_id,
            self.layout_id_512,
            self.parameter_identity,
            self.verifier_identity_512,
            self.epoch,
            self.sequence,
            self.state_root_512,
            self.state_manifest_digest_512,
        )
        if self.state_digest_512 not in (b"", expected_state):
            raise MigrationRecoveryError("s5_state_digest_mismatch")
        object.__setattr__(self, "state_digest_512", expected_state)
        expected_checkpoint = _checkpoint_digest(
            self.profile_id,
            self.layout_id_512,
            self.parameter_identity,
            self.verifier_identity_512,
            self.epoch,
            self.sequence,
            self.state_root_512,
            self.state_manifest_digest_512,
            expected_state,
        )
        if self.checkpoint_digest_512 not in (b"", expected_checkpoint):
            raise MigrationRecoveryError("s5_checkpoint_digest_mismatch")
        object.__setattr__(self, "checkpoint_digest_512", expected_checkpoint)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BLSC",
                bytes((CHECKPOINT_VERSION,)),
                _text(self.profile_id, "profile_id"),
                self.layout_id_512,
                _text(self.parameter_identity, "parameter_identity"),
                self.verifier_identity_512,
                _u64_bytes(self.epoch),
                _u64_bytes(self.sequence),
                self.state_root_512,
                self.state_manifest_digest_512,
                self.state_digest_512,
                self.checkpoint_digest_512,
            )
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "profile_id": self.profile_id,
            "layout_id_sha3_512_hex": self.layout_id_512.hex(),
            "parameter_identity": self.parameter_identity,
            "verifier_identity_sha3_512_hex": self.verifier_identity_512.hex(),
            "epoch": self.epoch,
            "sequence": self.sequence,
            "state_root_sha3_512_hex": self.state_root_512.hex(),
            "state_manifest_digest_sha3_512_hex": self.state_manifest_digest_512.hex(),
            "state_digest_sha3_512_hex": self.state_digest_512.hex(),
            "checkpoint_digest_sha3_512_hex": self.checkpoint_digest_512.hex(),
        }


def checkpoint_from_composition(
    composition: AtomicComposition,
    *,
    stage: str,
    state_manifest_digest_512: bytes | None = None,
) -> StateCheckpoint:
    """Create a reference checkpoint from an independently accepted S4 object."""

    _synthetic()
    if type(composition) is not AtomicComposition:
        raise MigrationRecoveryError("s5_composition_type_invalid")
    if stage not in {"before", "after"}:
        raise MigrationRecoveryError("s5_checkpoint_stage_invalid")
    manifest = (
        composition.transition.manifest_digest
        if state_manifest_digest_512 is None
        else _bytes(state_manifest_digest_512, "state_manifest", nonzero=True)
    )
    if stage == "before":
        epoch = composition.epoch
        sequence = composition.sequence_before
        root = composition.transition.old_root
    else:
        epoch = composition.epoch
        sequence = composition.transition.sequence_after
        root = composition.transition.new_root
    return StateCheckpoint(
        composition.profile_id,
        derive_state_layout_identity(composition),
        composition.transition.parameter_identity,
        composition.verifier_identity_512,
        epoch,
        sequence,
        root,
        manifest,
    )


def _transition_digest(transition: StateTransitionV1) -> bytes:
    return _hash(b"BL/PQ512/S5/TRANSITION/v1\x00", transition.encoded)


def _publication_digest(
    old_checkpoint: StateCheckpoint,
    new_checkpoint: StateCheckpoint,
    transition: StateTransitionV1,
    attempt_id_512: bytes,
    transition_digest_512: bytes,
    status: str,
) -> bytes:
    return _hash(
        _PUBLICATION_DOMAIN,
        old_checkpoint.checkpoint_digest_512,
        new_checkpoint.checkpoint_digest_512,
        transition.encoded,
        attempt_id_512,
        transition_digest_512,
        _text(status, "publication_status"),
    )


@dataclass(frozen=True, slots=True)
class StatePublication:
    old_checkpoint: StateCheckpoint
    new_checkpoint: StateCheckpoint
    transition: StateTransitionV1
    attempt_id_512: bytes
    transition_digest_512: bytes
    status: str = "PREPARED"
    publication_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        if type(self.old_checkpoint) is not StateCheckpoint or type(self.new_checkpoint) is not StateCheckpoint:
            raise MigrationRecoveryError("s5_publication_checkpoint_type_invalid")
        if type(self.transition) is not StateTransitionV1:
            raise MigrationRecoveryError("s5_publication_transition_type_invalid")
        _bytes(self.attempt_id_512, "publication_attempt_id", nonzero=True)
        _bytes(self.transition_digest_512, "publication_transition_digest", nonzero=True)
        if self.transition_digest_512 != _transition_digest(self.transition):
            raise MigrationRecoveryError("s5_publication_transition_digest_mismatch")
        if self.status not in {"PREPARED", "PUBLISHED"}:
            raise MigrationRecoveryError("s5_publication_status_invalid")
        if self.old_checkpoint.profile_id != self.new_checkpoint.profile_id:
            raise MigrationRecoveryError("s5_publication_profile_mismatch")
        transition = self.transition
        if transition.profile_id != self.old_checkpoint.profile_id:
            raise MigrationRecoveryError("s5_publication_transition_profile_mismatch")
        if transition.parameter_identity != self.old_checkpoint.parameter_identity:
            raise MigrationRecoveryError("s5_publication_transition_parameter_mismatch")
        if transition.epoch != self.old_checkpoint.epoch:
            raise MigrationRecoveryError("s5_publication_transition_epoch_mismatch")
        if transition.sequence_before != self.old_checkpoint.sequence:
            raise MigrationRecoveryError("s5_publication_transition_sequence_before_mismatch")
        if transition.sequence_after != self.new_checkpoint.sequence:
            raise MigrationRecoveryError("s5_publication_transition_sequence_after_mismatch")
        if transition.old_root != self.old_checkpoint.state_root_512:
            raise MigrationRecoveryError("s5_publication_transition_old_root_mismatch")
        if transition.new_root != self.new_checkpoint.state_root_512:
            raise MigrationRecoveryError("s5_publication_transition_new_root_mismatch")
        if transition.manifest_digest != self.old_checkpoint.state_manifest_digest_512:
            raise MigrationRecoveryError("s5_publication_transition_manifest_mismatch")
        if self.old_checkpoint.layout_id_512 != self.new_checkpoint.layout_id_512:
            raise MigrationRecoveryError("s5_publication_layout_mismatch")
        if self.old_checkpoint.parameter_identity != self.new_checkpoint.parameter_identity:
            raise MigrationRecoveryError("s5_publication_parameter_mismatch")
        if self.old_checkpoint.verifier_identity_512 != self.new_checkpoint.verifier_identity_512:
            raise MigrationRecoveryError("s5_publication_verifier_mismatch")
        if self.old_checkpoint.epoch != self.new_checkpoint.epoch:
            raise MigrationRecoveryError("s5_publication_epoch_mismatch")
        if self.new_checkpoint.sequence != self.old_checkpoint.sequence + 1:
            raise MigrationRecoveryError("s5_publication_sequence_mismatch")
        if self.old_checkpoint.state_manifest_digest_512 != self.new_checkpoint.state_manifest_digest_512:
            raise MigrationRecoveryError("s5_publication_manifest_mismatch")
        expected = _publication_digest(
            self.old_checkpoint,
            self.new_checkpoint,
            self.transition,
            self.attempt_id_512,
            self.transition_digest_512,
            self.status,
        )
        if self.publication_digest_512 not in (b"", expected):
            raise MigrationRecoveryError("s5_publication_digest_mismatch")
        object.__setattr__(self, "publication_digest_512", expected)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "attempt_id_sha3_512_hex": self.attempt_id_512.hex(),
            "transition_profile_id": self.transition.profile_id,
            "transition_digest_sha3_512_hex": self.transition_digest_512.hex(),
            "old_checkpoint_digest_sha3_512_hex": self.old_checkpoint.checkpoint_digest_512.hex(),
            "new_checkpoint_digest_sha3_512_hex": self.new_checkpoint.checkpoint_digest_512.hex(),
            "publication_digest_sha3_512_hex": self.publication_digest_512.hex(),
        }


def _migration_equivalence_digest(
    old_checkpoint: StateCheckpoint,
    new_checkpoint: StateCheckpoint,
    migration_version: str,
) -> bytes:
    return _hash(
        _MIGRATION_EQUIVALENCE_DOMAIN,
        old_checkpoint.profile_id.encode("ascii"),
        old_checkpoint.state_root_512,
        new_checkpoint.state_root_512,
        old_checkpoint.state_manifest_digest_512,
        new_checkpoint.state_manifest_digest_512,
        _u64_bytes(old_checkpoint.sequence),
        _u64_bytes(new_checkpoint.sequence),
        old_checkpoint.layout_id_512,
        new_checkpoint.layout_id_512,
        _text(old_checkpoint.parameter_identity, "parameter_identity"),
        _text(new_checkpoint.parameter_identity, "parameter_identity"),
        old_checkpoint.verifier_identity_512,
        new_checkpoint.verifier_identity_512,
        _text(migration_version, "migration_version"),
    )


def _migration_record_digest(
    old_checkpoint: StateCheckpoint,
    new_checkpoint: StateCheckpoint,
    migration_version: str,
    equivalence_digest_512: bytes,
    status: str,
) -> bytes:
    return _hash(
        _MIGRATION_RECORD_DOMAIN,
        old_checkpoint.checkpoint_digest_512,
        new_checkpoint.checkpoint_digest_512,
        _text(migration_version, "migration_version"),
        equivalence_digest_512,
        _text(status, "migration_status"),
    )


@dataclass(frozen=True, slots=True)
class MigrationRecord:
    old_checkpoint: StateCheckpoint
    new_checkpoint: StateCheckpoint
    migration_version: str
    equivalence_digest_512: bytes = b""
    status: str = "PREPARED"
    migration_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        if type(self.old_checkpoint) is not StateCheckpoint or type(self.new_checkpoint) is not StateCheckpoint:
            raise MigrationRecoveryError("s5_migration_checkpoint_type_invalid")
        _text(self.migration_version, "migration_version", 96)
        if self.equivalence_digest_512:
            _bytes(self.equivalence_digest_512, "migration_equivalence", nonzero=True)
        if self.status not in {"PREPARED", "PUBLISHED"}:
            raise MigrationRecoveryError("s5_migration_status_invalid")
        old = self.old_checkpoint
        new = self.new_checkpoint
        if old.profile_id != new.profile_id:
            raise MigrationRecoveryError("s5_migration_profile_mismatch")
        if new.epoch != old.epoch + 1:
            raise MigrationRecoveryError("s5_migration_epoch_not_monotonic")
        if new.sequence != old.sequence:
            raise MigrationRecoveryError("s5_migration_sequence_changed")
        if new.state_root_512 != old.state_root_512:
            raise MigrationRecoveryError("s5_migration_root_equivalence_failed")
        if new.state_manifest_digest_512 != old.state_manifest_digest_512:
            raise MigrationRecoveryError("s5_migration_manifest_equivalence_failed")
        if (
            old.layout_id_512 == new.layout_id_512
            and old.parameter_identity == new.parameter_identity
            and old.verifier_identity_512 == new.verifier_identity_512
        ):
            raise MigrationRecoveryError("s5_migration_identity_noop")
        expected_equivalence = _migration_equivalence_digest(old, new, self.migration_version)
        if self.equivalence_digest_512 not in (b"", expected_equivalence):
            raise MigrationRecoveryError("s5_migration_equivalence_digest_mismatch")
        object.__setattr__(self, "equivalence_digest_512", expected_equivalence)
        expected_record = _migration_record_digest(
            old,
            new,
            self.migration_version,
            expected_equivalence,
            self.status,
        )
        if self.migration_digest_512 not in (b"", expected_record):
            raise MigrationRecoveryError("s5_migration_record_digest_mismatch")
        object.__setattr__(self, "migration_digest_512", expected_record)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "migration_version": self.migration_version,
            "old_checkpoint_digest_sha3_512_hex": self.old_checkpoint.checkpoint_digest_512.hex(),
            "new_checkpoint_digest_sha3_512_hex": self.new_checkpoint.checkpoint_digest_512.hex(),
            "equivalence_status": MIGRATION_EQUIVALENCE_STATUS,
            "equivalence_digest_sha3_512_hex": self.equivalence_digest_512.hex(),
            "migration_digest_sha3_512_hex": self.migration_digest_512.hex(),
        }


def _recovery_event_digest(
    old_checkpoint: StateCheckpoint,
    target_checkpoint: StateCheckpoint,
    new_checkpoint: StateCheckpoint,
    recovery_kind: str,
    recovery_epoch: int,
    status: str,
) -> bytes:
    return _hash(
        _RECOVERY_EVENT_DOMAIN,
        old_checkpoint.checkpoint_digest_512,
        target_checkpoint.checkpoint_digest_512,
        new_checkpoint.checkpoint_digest_512,
        _text(recovery_kind, "recovery_kind"),
        _u64_bytes(recovery_epoch),
        _text(status, "recovery_status"),
    )


@dataclass(frozen=True, slots=True)
class RecoveryRecord:
    old_checkpoint: StateCheckpoint
    target_checkpoint: StateCheckpoint
    new_checkpoint: StateCheckpoint
    recovery_kind: str
    recovery_epoch: int
    status: str = "PREPARED"
    recovery_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        for value, label in (
            (self.old_checkpoint, "old_checkpoint"),
            (self.target_checkpoint, "target_checkpoint"),
            (self.new_checkpoint, "new_checkpoint"),
        ):
            if type(value) is not StateCheckpoint:
                raise MigrationRecoveryError(f"s5_recovery_{label}_type_invalid")
        if self.recovery_kind not in {"ROLLBACK", "RECOVERY"}:
            raise MigrationRecoveryError("s5_recovery_kind_invalid")
        _u64(self.recovery_epoch, "recovery_epoch")
        if self.status not in {"PREPARED", "PUBLISHED"}:
            raise MigrationRecoveryError("s5_recovery_status_invalid")
        old = self.old_checkpoint
        target = self.target_checkpoint
        new = self.new_checkpoint
        if target.profile_id != old.profile_id or new.profile_id != old.profile_id:
            raise MigrationRecoveryError("s5_recovery_profile_mismatch")
        if target.epoch > old.epoch:
            raise MigrationRecoveryError("s5_recovery_target_from_future")
        if new.epoch != self.recovery_epoch or new.epoch <= old.epoch:
            raise MigrationRecoveryError("s5_recovery_epoch_not_newer")
        if new.sequence != target.sequence:
            raise MigrationRecoveryError("s5_recovery_sequence_mismatch")
        if new.state_root_512 != target.state_root_512:
            raise MigrationRecoveryError("s5_recovery_root_mismatch")
        if new.state_manifest_digest_512 != target.state_manifest_digest_512:
            raise MigrationRecoveryError("s5_recovery_manifest_mismatch")
        if new.layout_id_512 != target.layout_id_512:
            raise MigrationRecoveryError("s5_recovery_layout_mismatch")
        if new.parameter_identity != target.parameter_identity:
            raise MigrationRecoveryError("s5_recovery_parameter_mismatch")
        if new.verifier_identity_512 != target.verifier_identity_512:
            raise MigrationRecoveryError("s5_recovery_verifier_mismatch")
        expected = _recovery_event_digest(
            old,
            target,
            new,
            self.recovery_kind,
            self.recovery_epoch,
            self.status,
        )
        if self.recovery_digest_512 not in (b"", expected):
            raise MigrationRecoveryError("s5_recovery_digest_mismatch")
        object.__setattr__(self, "recovery_digest_512", expected)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "recovery_kind": self.recovery_kind,
            "recovery_epoch": self.recovery_epoch,
            "old_checkpoint_digest_sha3_512_hex": self.old_checkpoint.checkpoint_digest_512.hex(),
            "target_checkpoint_digest_sha3_512_hex": self.target_checkpoint.checkpoint_digest_512.hex(),
            "new_checkpoint_digest_sha3_512_hex": self.new_checkpoint.checkpoint_digest_512.hex(),
            "recovery_digest_sha3_512_hex": self.recovery_digest_512.hex(),
        }


def _validate_publication(publication: StatePublication) -> None:
    expected = _publication_digest(
        publication.old_checkpoint,
        publication.new_checkpoint,
        publication.transition,
        publication.attempt_id_512,
        publication.transition_digest_512,
        publication.status,
    )
    if publication.publication_digest_512 != expected:
        raise MigrationRecoveryError("s5_publication_digest_mismatch")


def _validate_migration(record: MigrationRecord) -> None:
    expected = _migration_record_digest(
        record.old_checkpoint,
        record.new_checkpoint,
        record.migration_version,
        record.equivalence_digest_512,
        record.status,
    )
    if record.migration_digest_512 != expected:
        raise MigrationRecoveryError("s5_migration_record_digest_mismatch")


def _validate_recovery(record: RecoveryRecord) -> None:
    expected = _recovery_event_digest(
        record.old_checkpoint,
        record.target_checkpoint,
        record.new_checkpoint,
        record.recovery_kind,
        record.recovery_epoch,
        record.status,
    )
    if record.recovery_digest_512 != expected:
        raise MigrationRecoveryError("s5_recovery_digest_mismatch")


class AtomicStateStore:
    """In-memory reference store with atomic immutable-checkpoint publication."""

    def __init__(self, genesis: StateCheckpoint) -> None:
        _synthetic()
        if type(genesis) is not StateCheckpoint:
            raise MigrationRecoveryError("s5_genesis_checkpoint_type_invalid")
        self._lock = RLock()
        self._current = genesis
        self._history: tuple[StateCheckpoint, ...] = (genesis,)
        self._known: dict[bytes, StateCheckpoint] = {genesis.checkpoint_digest_512: genesis}
        self._pending_publications: dict[bytes, StatePublication] = {}
        self._pending_migrations: dict[bytes, MigrationRecord] = {}
        self._pending_recoveries: dict[bytes, RecoveryRecord] = {}

    @property
    def current(self) -> StateCheckpoint:
        with self._lock:
            return self._current

    @property
    def history(self) -> tuple[StateCheckpoint, ...]:
        with self._lock:
            return self._history

    def _publish_checkpoint(self, checkpoint: StateCheckpoint) -> None:
        self._current = checkpoint
        self._history = self._history + (checkpoint,)
        self._known[checkpoint.checkpoint_digest_512] = checkpoint

    def prepare_composition_publication(
        self,
        composition: AtomicComposition,
        batch,
        result,
        opening,
        adapters: dict[str, object],
    ) -> StatePublication:
        _synthetic()
        try:
            independently_verify_composition(composition, batch, result, opening, adapters)
        except (AtomicCompositionError, ValueError) as exc:
            raise MigrationRecoveryError("s5_composition_verification_rejected") from exc
        transition = composition.transition
        expected_layout = derive_state_layout_identity(composition)
        with self._lock:
            current = self._current
            if current.profile_id != composition.profile_id:
                raise MigrationRecoveryError("s5_publication_profile_mismatch")
            if current.layout_id_512 != expected_layout:
                raise MigrationRecoveryError("s5_publication_layout_mismatch")
            if current.parameter_identity != transition.parameter_identity:
                raise MigrationRecoveryError("s5_publication_parameter_mismatch")
            if current.verifier_identity_512 != composition.verifier_identity_512:
                raise MigrationRecoveryError("s5_publication_verifier_mismatch")
            if current.epoch != transition.epoch or current.sequence != transition.sequence_before:
                raise MigrationRecoveryError("s5_publication_stale_epoch_or_sequence")
            if current.state_root_512 != transition.old_root:
                raise MigrationRecoveryError("s5_publication_old_root_mismatch")
            if current.state_manifest_digest_512 != transition.manifest_digest:
                raise MigrationRecoveryError("s5_publication_manifest_mismatch")
            new_checkpoint = StateCheckpoint(
                current.profile_id,
                current.layout_id_512,
                current.parameter_identity,
                current.verifier_identity_512,
                current.epoch,
                transition.sequence_after,
                transition.new_root,
                current.state_manifest_digest_512,
            )
            publication = StatePublication(
                current,
                new_checkpoint,
                transition,
                composition.attempt_id_512,
                _transition_digest(transition),
            )
            self._pending_publications[publication.publication_digest_512] = publication
            return publication

    def publish_prepared_composition(self, publication: StatePublication) -> StatePublication:
        _synthetic()
        if type(publication) is not StatePublication:
            raise MigrationRecoveryError("s5_publication_type_invalid")
        _validate_publication(publication)
        if publication.status != "PREPARED":
            raise MigrationRecoveryError("s5_publication_not_prepared")
        with self._lock:
            if self._pending_publications.get(publication.publication_digest_512) != publication:
                raise MigrationRecoveryError("s5_publication_unknown_pending_record")
            if self._current.checkpoint_digest_512 != publication.old_checkpoint.checkpoint_digest_512:
                raise MigrationRecoveryError("s5_publication_compare_and_swap_failed")
            self._publish_checkpoint(publication.new_checkpoint)
            self._pending_publications.pop(publication.publication_digest_512, None)
        return replace(publication, status="PUBLISHED", publication_digest_512=b"")

    def publish_composition(
        self,
        composition: AtomicComposition,
        batch,
        result,
        opening,
        adapters: dict[str, object],
    ) -> StatePublication:
        publication = self.prepare_composition_publication(
            composition, batch, result, opening, adapters
        )
        return self.publish_prepared_composition(publication)

    def prepare_migration(
        self,
        *,
        new_layout_id_512: bytes,
        new_parameter_identity: str,
        new_verifier_identity_512: bytes,
        migration_version: str,
    ) -> MigrationRecord:
        _synthetic()
        with self._lock:
            current = self._current
            history = self._history
        new_layout = _bytes(new_layout_id_512, "migration_new_layout", nonzero=True)
        new_parameter = _text(new_parameter_identity, "migration_new_parameter", 96)
        new_verifier = _bytes(new_verifier_identity_512, "migration_new_verifier", nonzero=True)
        _text(migration_version, "migration_version", 96)
        for prior in history[:-1]:
            if (
                new_layout == prior.layout_id_512
                or new_parameter_identity == prior.parameter_identity
                or new_verifier == prior.verifier_identity_512
            ):
                raise MigrationRecoveryError("s5_migration_downgrade_rejected")
        with self._lock:
            if self._current.checkpoint_digest_512 != current.checkpoint_digest_512:
                raise MigrationRecoveryError("s5_migration_compare_and_swap_failed")
            new_checkpoint = StateCheckpoint(
                current.profile_id,
                new_layout,
                new_parameter_identity,
                new_verifier,
                current.epoch + 1,
                current.sequence,
                current.state_root_512,
                current.state_manifest_digest_512,
            )
            record = MigrationRecord(
                current,
                new_checkpoint,
                migration_version,
            )
            self._pending_migrations[record.migration_digest_512] = record
            return record

    def publish_migration(self, record: MigrationRecord) -> MigrationRecord:
        _synthetic()
        if type(record) is not MigrationRecord:
            raise MigrationRecoveryError("s5_migration_type_invalid")
        _validate_migration(record)
        if record.status != "PREPARED":
            raise MigrationRecoveryError("s5_migration_not_prepared")
        with self._lock:
            if self._pending_migrations.get(record.migration_digest_512) != record:
                raise MigrationRecoveryError("s5_migration_unknown_pending_record")
            if self._current.checkpoint_digest_512 != record.old_checkpoint.checkpoint_digest_512:
                raise MigrationRecoveryError("s5_migration_compare_and_swap_failed")
            if any(
                record.new_checkpoint.layout_id_512 == prior.layout_id_512
                or record.new_checkpoint.parameter_identity == prior.parameter_identity
                or record.new_checkpoint.verifier_identity_512 == prior.verifier_identity_512
                for prior in self._history[:-1]
            ):
                raise MigrationRecoveryError("s5_migration_downgrade_rejected")
            self._publish_checkpoint(record.new_checkpoint)
            self._pending_migrations.pop(record.migration_digest_512, None)
        return replace(record, status="PUBLISHED", migration_digest_512=b"")

    def migrate(
        self,
        *,
        new_layout_id_512: bytes,
        new_parameter_identity: str,
        new_verifier_identity_512: bytes,
        migration_version: str,
    ) -> MigrationRecord:
        record = self.prepare_migration(
            new_layout_id_512=new_layout_id_512,
            new_parameter_identity=new_parameter_identity,
            new_verifier_identity_512=new_verifier_identity_512,
            migration_version=migration_version,
        )
        return self.publish_migration(record)

    def _prepare_recovery(
        self,
        target_checkpoint: StateCheckpoint,
        *,
        expected_current_digest_512: bytes,
        recovery_epoch: int,
        recovery_kind: str,
    ) -> RecoveryRecord:
        _synthetic()
        if type(target_checkpoint) is not StateCheckpoint:
            raise MigrationRecoveryError("s5_recovery_target_type_invalid")
        _bytes(expected_current_digest_512, "recovery_expected_current", nonzero=True)
        _u64(recovery_epoch, "recovery_epoch")
        with self._lock:
            current = self._current
            known = self._known.get(target_checkpoint.checkpoint_digest_512)
        if known != target_checkpoint:
            raise MigrationRecoveryError("s5_recovery_checkpoint_not_known")
        if current.checkpoint_digest_512 != expected_current_digest_512:
            raise MigrationRecoveryError("s5_recovery_compare_and_swap_failed")
        if target_checkpoint.profile_id != current.profile_id:
            raise MigrationRecoveryError("s5_recovery_profile_mismatch")
        if target_checkpoint.state_manifest_digest_512 != current.state_manifest_digest_512:
            raise MigrationRecoveryError("s5_recovery_manifest_mismatch")
        if target_checkpoint.epoch > current.epoch:
            raise MigrationRecoveryError("s5_recovery_target_from_future")
        if recovery_epoch <= current.epoch:
            raise MigrationRecoveryError("s5_recovery_epoch_not_newer")
        new_checkpoint = StateCheckpoint(
            target_checkpoint.profile_id,
            target_checkpoint.layout_id_512,
            target_checkpoint.parameter_identity,
            target_checkpoint.verifier_identity_512,
            recovery_epoch,
            target_checkpoint.sequence,
            target_checkpoint.state_root_512,
            target_checkpoint.state_manifest_digest_512,
        )
        record = RecoveryRecord(
            current,
            target_checkpoint,
            new_checkpoint,
            recovery_kind,
            recovery_epoch,
        )
        with self._lock:
            if self._current.checkpoint_digest_512 != current.checkpoint_digest_512:
                raise MigrationRecoveryError("s5_recovery_compare_and_swap_failed")
            self._pending_recoveries[record.recovery_digest_512] = record
        return record

    def prepare_rollback(
        self,
        target_checkpoint: StateCheckpoint,
        *,
        expected_current_digest_512: bytes,
        recovery_epoch: int,
    ) -> RecoveryRecord:
        return self._prepare_recovery(
            target_checkpoint,
            expected_current_digest_512=expected_current_digest_512,
            recovery_epoch=recovery_epoch,
            recovery_kind="ROLLBACK",
        )

    def prepare_recovery(
        self,
        target_checkpoint: StateCheckpoint,
        *,
        expected_current_digest_512: bytes,
        recovery_epoch: int,
    ) -> RecoveryRecord:
        return self._prepare_recovery(
            target_checkpoint,
            expected_current_digest_512=expected_current_digest_512,
            recovery_epoch=recovery_epoch,
            recovery_kind="RECOVERY",
        )

    def publish_recovery(self, record: RecoveryRecord) -> RecoveryRecord:
        _synthetic()
        if type(record) is not RecoveryRecord:
            raise MigrationRecoveryError("s5_recovery_type_invalid")
        _validate_recovery(record)
        if record.status != "PREPARED":
            raise MigrationRecoveryError("s5_recovery_not_prepared")
        with self._lock:
            if self._pending_recoveries.get(record.recovery_digest_512) != record:
                raise MigrationRecoveryError("s5_recovery_unknown_pending_record")
            if self._current.checkpoint_digest_512 != record.old_checkpoint.checkpoint_digest_512:
                raise MigrationRecoveryError("s5_recovery_compare_and_swap_failed")
            if self._known.get(record.target_checkpoint.checkpoint_digest_512) != record.target_checkpoint:
                raise MigrationRecoveryError("s5_recovery_checkpoint_not_known")
            self._publish_checkpoint(record.new_checkpoint)
            self._pending_recoveries.pop(record.recovery_digest_512, None)
        return replace(record, status="PUBLISHED", recovery_digest_512=b"")

    def rollback(
        self,
        target_checkpoint: StateCheckpoint,
        *,
        expected_current_digest_512: bytes,
        recovery_epoch: int,
    ) -> RecoveryRecord:
        record = self.prepare_rollback(
            target_checkpoint,
            expected_current_digest_512=expected_current_digest_512,
            recovery_epoch=recovery_epoch,
        )
        return self.publish_recovery(record)

    def recover(
        self,
        target_checkpoint: StateCheckpoint,
        *,
        expected_current_digest_512: bytes,
        recovery_epoch: int,
    ) -> RecoveryRecord:
        record = self.prepare_recovery(
            target_checkpoint,
            expected_current_digest_512=expected_current_digest_512,
            recovery_epoch=recovery_epoch,
        )
        return self.publish_recovery(record)


__all__ = (
    "ACTIVATION_ALLOWED",
    "CHECKPOINT_VERSION",
    "MIGRATION_EQUIVALENCE_STATUS",
    "PROOF_SUITE_ID",
    "STATUS",
    "AtomicStateStore",
    "MigrationRecord",
    "MigrationRecoveryError",
    "RecoveryRecord",
    "StateCheckpoint",
    "StatePublication",
    "checkpoint_from_composition",
    "derive_state_layout_identity",
)
