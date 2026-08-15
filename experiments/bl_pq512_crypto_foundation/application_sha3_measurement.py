"""Reproducible dynamic measurement for the scoped application SHA3 ports."""

from __future__ import annotations

import ast
from collections import Counter
from contextlib import AbstractContextManager
from dataclasses import dataclass
from hashlib import sha3_512 as _real_sha3_512
import importlib
import inspect
from pathlib import Path
from types import ModuleType
from typing import Final, Sequence

from .application_sha3_port_inventory import (
    CALLSITE_DISPOSITIONS,
    RECONCILED_ADDITION_WIDTHS,
    SCANNED_PATHS,
    CallsiteId,
    RuntimeObservation,
    require_inventory_consistent,
)


STATUS: Final[str] = "WAVE1B_APPLICATION_SHA3_DYNAMIC_MEASUREMENT_INSTRUMENT_V1"

@dataclass(frozen=True, slots=True)
class _SourceCall:
    callsite: CallsiteId
    first_line: int
    last_line: int


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.stack: list[str] = []
        self.counts: Counter[str] = Counter()
        self.calls: list[_SourceCall] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        function = node.func
        is_sha3 = (isinstance(function, ast.Name) and function.id == "sha3_512") or (
            isinstance(function, ast.Attribute) and function.attr == "sha3_512"
        )
        if is_sha3:
            qualified = ".".join(self.stack) or "<module>"
            ordinal = self.counts[qualified]
            self.counts[qualified] += 1
            self.calls.append(
                _SourceCall(
                    CallsiteId(self.path, qualified, ordinal),
                    node.lineno,
                    node.end_lineno or node.lineno,
                )
            )
        self.generic_visit(node)


def _source_calls(repository_root: Path) -> tuple[_SourceCall, ...]:
    require_inventory_consistent(repository_root)
    calls: list[_SourceCall] = []
    for relative in SCANNED_PATHS:
        source = (repository_root / relative).read_text(encoding="utf-8")
        visitor = _CallVisitor(relative)
        visitor.visit(ast.parse(source, filename=relative))
        calls.extend(visitor.calls)
    observed = {value.callsite for value in calls}
    if observed != set(CALLSITE_DISPOSITIONS):
        raise ValueError("sha3_measurement_static_inventory_drift")
    return tuple(calls)


def _module_name(relative_path: str) -> str:
    if not relative_path.endswith(".py"):
        raise ValueError("sha3_measurement_module_path_invalid")
    return relative_path[:-3].replace("/", ".").replace("\\", ".")


class ApplicationSha3Measurement(AbstractContextManager["ApplicationSha3Measurement"]):
    """Patch only governed module globals and count exact input lengths."""

    def __init__(self, repository_root: Path):
        if not isinstance(repository_root, Path):
            raise TypeError("sha3_measurement_repository_root_path_required")
        self.repository_root = repository_root.resolve()
        self._calls = _source_calls(self.repository_root)
        self._lookup: dict[tuple[str, str], tuple[_SourceCall, ...]] = {}
        for source_call in self._calls:
            key = (source_call.callsite.path, source_call.callsite.qualified_name)
            self._lookup[key] = (*self._lookup.get(key, ()), source_call)
        self._counts: Counter[tuple[CallsiteId, int]] = Counter()
        self._originals: dict[ModuleType, object] = {}
        self._resolution_cache: dict[tuple[object, int], CallsiteId] = {}
        self._active = False

    def _relative_caller_path(self, filename: str) -> str:
        path = Path(filename).resolve()
        try:
            relative = path.relative_to(self.repository_root)
        except ValueError as exc:
            raise RuntimeError("sha3_measurement_caller_outside_repository") from exc
        return relative.as_posix()

    def _resolve_callsite(self, frame: object) -> CallsiteId:
        if frame is None or not inspect.isframe(frame):
            raise RuntimeError("sha3_measurement_caller_frame_missing")
        cache_key = (frame.f_code, frame.f_lineno)
        cached = self._resolution_cache.get(cache_key)
        if cached is not None:
            return cached
        path = self._relative_caller_path(frame.f_code.co_filename)
        qualified = frame.f_code.co_qualname.replace(".<locals>.", ".")
        if qualified == "<module>":
            qualified = "<module>"
        candidates = self._lookup.get((path, qualified), ())
        matching = tuple(
            value
            for value in candidates
            if value.first_line <= frame.f_lineno <= value.last_line
        )
        if len(matching) != 1:
            raise RuntimeError(
                "sha3_measurement_callsite_resolution_failed:"
                f"path={path}:qualified={qualified}:line={frame.f_lineno}:"
                f"matches={len(matching)}"
            )
        resolved = matching[0].callsite
        self._resolution_cache[cache_key] = resolved
        return resolved

    def _measured_sha3_512(self, data: object = b"", *args: object, **kwargs: object):
        try:
            preimage_bytes = len(data)  # type: ignore[arg-type]
        except TypeError as exc:
            raise TypeError("sha3_measurement_input_has_no_length") from exc
        if type(preimage_bytes) is not int or preimage_bytes < 0:
            raise ValueError("sha3_measurement_input_length_invalid")
        frame = inspect.currentframe()
        try:
            callsite = self._resolve_callsite(frame.f_back if frame is not None else None)
        finally:
            del frame
        self._counts[(callsite, preimage_bytes)] += 1
        return _real_sha3_512(data, *args, **kwargs)

    def __enter__(self) -> "ApplicationSha3Measurement":
        if self._active:
            raise RuntimeError("sha3_measurement_context_already_active")
        for relative in SCANNED_PATHS:
            module = importlib.import_module(_module_name(relative))
            if hasattr(module, "sha3_512"):
                self._originals[module] = getattr(module, "sha3_512")
                setattr(module, "sha3_512", self._measured_sha3_512)
        self._active = True
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        for module, original in self._originals.items():
            setattr(module, "sha3_512", original)
        self._originals.clear()
        self._active = False
        return None

    def clear(self) -> None:
        self._counts.clear()

    def observations(self) -> tuple[RuntimeObservation, ...]:
        return tuple(
            RuntimeObservation(callsite, preimage_bytes, invocations)
            for (callsite, preimage_bytes), invocations in sorted(
                self._counts.items(),
                key=lambda item: (
                    item[0][0].path,
                    item[0][0].qualified_name,
                    item[0][0].ordinal,
                    item[0][1],
                ),
            )
        )


def measure_reconciled_additions(
    repository_root: Path,
) -> tuple[RuntimeObservation, ...]:
    """Exercise every H0 addition once and return its exact SHA3 observation.

    This is deliberately an isolated classification measurement.  It prevents
    a helper that is absent from one mixed fixture from being classified by
    analogy alone.  The retired exact-K128 phase driver is not part of the
    active repository.
    """

    from app.batch.pq_nullifier_derivation import (  # noqa: PLC0415
        CoverReplayContextV2,
        derive_cover_nullifiers_v2,
    )
    from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (  # noqa: PLC0415,E501
        BenefitScopeV1,
        _dummy_key,
        member_benefit_key,
        provider_obligation_key,
        provider_payable_key,
    )
    from experiments.fixed_shape_claim_air.semantics import (  # noqa: PLC0415
        ClaimSlot,
        RevisionKind,
        SlotKind,
    )

    digest = _real_sha3_512
    context = CoverReplayContextV2(
        "K128_CALIBRATION",
        digest(b"BL/H0/SETTLEMENT-DOMAIN").digest(),
        7,
        digest(b"BL/H0/BATCH-NONCE").digest(),
        127,
    )
    nonce = digest(b"BL/H0/COVER-NONCE").digest()
    benefit_scope = BenefitScopeV1("SYNTH-PAYER-001", "SYNTH-PLAN-001", 20_000, 20_365)
    real_slot = ClaimSlot(
        slot_index=0,
        slot_kind=SlotKind.REAL,
        source_authority_id="BL-SYNTH-GOV-INTAKE-V1",
        source_sequence=1,
        claim_id="BL-SYNTH-CLAIM-0001",
        member_id="SYNTH-MEMBER-001",
        provider_npi="1999999984",
        attempt_version=1,
        revision_kind=RevisionKind.ORIGINAL,
        parent_attempt_version=0,
        diagnoses=(),
        service_lines=(),
        eligibility_active=True,
        provider_enrolled=True,
        provider_not_suspended=True,
        not_deceased=True,
        duplicate_claim=False,
        program_integrity_hold=False,
        total_charge_cents=0,
        patient_responsibility_cents=0,
        claimed_decision=0,
        claimed_failure_code=0,
        claimed_allowed_cents=0,
        claimed_payment_cents=0,
    )
    settlement_domain = digest(b"BL/H0/PAYMENT-DOMAIN").digest()
    scope_commitment = benefit_scope.commitment_512()

    with ApplicationSha3Measurement(repository_root) as measurement:
        derive_cover_nullifiers_v2(context, nonce)
        member_benefit_key(real_slot.member_id, benefit_scope=benefit_scope)
        provider_obligation_key(real_slot)
        provider_payable_key(real_slot.provider_npi)
        _dummy_key(b"BENEFIT", settlement_domain, 7, scope_commitment)
        observations = measurement.observations()

    selected = tuple(
        value
        for value in observations
        if value.callsite.stable_id in RECONCILED_ADDITION_WIDTHS
    )
    observed = {
        value.callsite.stable_id: value.preimage_bytes for value in selected
    }
    if observed != RECONCILED_ADDITION_WIDTHS or any(
        value.invocations != 1 for value in selected
    ):
        raise ValueError("sha3_measurement_reconciled_addition_mismatch")
    return selected


__all__: Sequence[str] = (
    "ApplicationSha3Measurement",
    "RECONCILED_ADDITION_WIDTHS",
    "STATUS",
    "measure_reconciled_additions",
)
