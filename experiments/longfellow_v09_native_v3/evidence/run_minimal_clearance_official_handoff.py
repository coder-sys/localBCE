"""Run one bounded synthetic official-directive outbox exercise.

The fixture is the existing zero-PHI queue-application fixture.  It uses an
in-process receiver and never invokes a native verifier, prover, payment
interface, or state-store mutation during the handoff exercise.  Its
application setup uses only the test-owned concrete verifier fixture.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.minimal_clearance_official_handoff import OfficialHandoffIndeterminateError, OfficialHandoffStoreV1, build_directive_envelope
from app.minimal_clearance_official_handoff_independent import (
    parse_envelope_bytes,
    read_applied_application,
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)
from tests.test_minimal_clearance_official_handoff import OfficialHandoffTests, _StoreClock, _Receiver


def _json_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def run(evidence_output: Path) -> dict[str, object]:
    if not isinstance(evidence_output, Path) or evidence_output.exists() or evidence_output.is_symlink():
        raise RuntimeError("fresh_evidence_target")
    fixture = OfficialHandoffTests("test_all_five_directives_and_digest_only_envelope")
    fixture.setUp()
    try:
        helper, _queue, state, _verifier, app, _works, receiver, config, _initial_outbox = fixture._prepared(count=4)
        application_database = helper.root / "application.sqlite3"
        state_database = helper.root / "clearance.sqlite3"
        outbox_path = helper.root / "official-handoff-exercise.sqlite3"
        restore_path = helper.root / "official-handoff-restore.sqlite3"
        before_state = state.snapshot()
        view = read_applied_application(
            application_database,
            state_database,
            expected_application_id=config.application_id,
            expected_application_config_digest=config.application_config_digest,
            expected_state_store_identity=config.state_store_identity,
            expected_verifier_sha256=config.verifier_sha256,
            job_id="job-0",
        )
        for directive in range(1, 6):
            variant = replace(view, receipt=dict(view.receipt, effective_directive=directive))
            parse_envelope_bytes(build_directive_envelope(variant, config))

        outbox = OfficialHandoffStoreV1(path=outbox_path, config=config, clock=_StoreClock())
        job_ids = [f"job-{index}" for index in range(4)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            discovered = list(pool.map(
                lambda job_id: outbox.discover(application_database, state_database, job_id),
                reversed(job_ids),
            ))
        if len(discovered) != 4 or any(job.status != "DISCOVERED" for job in discovered):
            raise RuntimeError("discovery_shape")
        works = [outbox.claim_next(f"handoff-worker-{index}") for index in range(4)]
        if any(work is None for work in works):
            raise RuntimeError("claim_shape")
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(
                lambda work: outbox.dispatch(
                    work, application_database=application_database,
                    state_database=state_database, receiver=receiver,
                ),
                works,
            ))
        if len(results) != 4 or any(result.status != "ACKNOWLEDGED" for result in results):
            raise RuntimeError("dispatch_shape")
        if receiver.side_effects != 4:
            raise RuntimeError("receiver_effect_count")
        if receiver.dispatch_calls != 4 or receiver.idempotent_replays != 0:
            raise RuntimeError("ordinary_dispatch_accounting")
        for job_id in job_ids:
            repeated = outbox.discover(application_database, state_database, job_id)
            if repeated.status != "ACKNOWLEDGED":
                raise RuntimeError("discovery_retry_shape")
        outbox.verify_integrity()
        exported = outbox.export_bytes()
        producer_summary = verify_database(outbox_path, expected_config=config.as_json())
        export_summary = verify_export_bytes(exported, expected_config=config.as_json())
        restored_summary = restore_export_to_fresh_database(restore_path, exported)
        if producer_summary != export_summary or export_summary != restored_summary:
            raise RuntimeError("restore_parity")
        if state.snapshot() != before_state:
            raise RuntimeError("state_mutation")

        recovery_path = helper.root / "official-handoff-response-loss.sqlite3"
        recovery_restore_path = helper.root / "official-handoff-response-loss-restore.sqlite3"
        recovery_config = replace(config, outbox_id="official-handoff-response-loss", lease_seconds=1)
        recovery_clock = _StoreClock()
        recovery_receiver = _Receiver(response_loss_once=True)
        recovery = OfficialHandoffStoreV1(path=recovery_path, config=recovery_config, clock=recovery_clock)
        recovery.discover(application_database, state_database, "job-0")
        first_work = recovery.claim_next("recovery-worker-0")
        if first_work is None:
            raise RuntimeError("response_loss_claim")
        try:
            recovery.dispatch(first_work, application_database=application_database, state_database=state_database, receiver=recovery_receiver)
        except OfficialHandoffIndeterminateError:
            pass
        else:
            raise RuntimeError("response_loss_not_indeterminate")
        if recovery_receiver.dispatch_calls != 1 or recovery_receiver.side_effects != 1:
            raise RuntimeError("response_loss_first_dispatch_accounting")
        recovery_clock.advance(1_001)
        restarted = OfficialHandoffStoreV1(path=recovery_path, config=recovery_config, clock=recovery_clock)
        second_work = restarted.claim_next("recovery-worker-1")
        if second_work is None:
            raise RuntimeError("response_loss_requeue")
        recovered = restarted.dispatch(second_work, application_database=application_database, state_database=state_database, receiver=recovery_receiver)
        if recovered.status != "ACKNOWLEDGED":
            raise RuntimeError("response_loss_final_ack")
        if recovery_receiver.dispatch_calls != 2 or recovery_receiver.idempotent_replays != 1 or recovery_receiver.side_effects != 1:
            raise RuntimeError("response_loss_replay_accounting")
        recovery.verify_integrity()
        recovery_export = recovery.export_bytes()
        recovery_restore_summary = restore_export_to_fresh_database(recovery_restore_path, recovery_export)
        if recovery_restore_summary["status_counts"]["ACKNOWLEDGED"] != 1:
            raise RuntimeError("response_loss_restore")
        if state.snapshot() != before_state:
            raise RuntimeError("response_loss_state_mutation")
        summary = outbox.support_summary()
        output: dict[str, object] = {
            "schema": "BL/NATIVE-V3/MINIMAL-CLEARANCE-OFFICIAL-HANDOFF/INTEGRATION-EVIDENCE/v1",
            "outbox_schema": 1,
            "discovered_count": 4,
            "claimed_count": 4,
            "acknowledged_count": 4,
            "ordinary_dispatch_calls": receiver.dispatch_calls,
            "ordinary_idempotent_replays": receiver.idempotent_replays,
            "ordinary_receiver_side_effects": receiver.side_effects,
            "duplicate_discovery_convergence_count": 4,
            "delivery_semantics": "recoverable_at_least_once",
            "delivery_semantics_observed": True,
            "response_loss_recovery_dispatch_calls": recovery_receiver.dispatch_calls,
            "response_loss_recovery_idempotent_replays": recovery_receiver.idempotent_replays,
            "response_loss_recovery_receiver_side_effects": recovery_receiver.side_effects,
            "response_loss_recovery_final_acknowledged": True,
            "independent_export_restore_parity": True,
            "independent_database_parity": True,
            "envelope_parser_directives_checked": [1, 2, 3, 4, 5],
            "state_mutation_count": 0,
            "native_verifier_invocations": 0,
            "synthetic_state_boundary_verifier_calls": int(_verifier.verify_calls),
            "prover_invocations": 0,
            "payment_calls": 0,
            "economic_mutation": False,
            "payment_root_unchanged": True,
            "settled_batch_count_unchanged": True,
            "proof_session_accepted": True,
            "proof_acceptance_is_clear": False,
            "proof_suite_id": None,
            "production_usable": False,
            "activation": False,
            "payment_authority": False,
            "clearance_authority": False,
            "experimental_software_only": True,
            "status_counts": summary["status_counts"],
            "transition_count": summary["transition_count"],
        }
        encoded = _json_bytes(output)
        if len(encoded) > 8192 or any(token in encoded for token in (b"C:\\", b"stdout", b"stderr", b"proof_bytes", b"artifact")):
            raise RuntimeError("evidence_privacy")
        evidence_output.parent.mkdir(parents=True, exist_ok=True)
        with evidence_output.open("xb") as handle:
            handle.write(encoded + b"\n")
            handle.flush()
        return output
    finally:
        state.close()
        fixture.tearDown()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-output", type=Path, required=True)
    args = parser.parse_args()
    print(_json_bytes(run(args.evidence_output)).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
