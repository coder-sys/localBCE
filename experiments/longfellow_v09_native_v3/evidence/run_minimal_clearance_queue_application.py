"""One bounded queue-to-state application exercise; no native verifier call."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.minimal_clearance_proof_state import MinimalClearanceStateStoreV1, MinimalProofAcceptanceV1, parse_acceptance_bytes
from app.minimal_clearance_queue_application import QueueApplicationConfigV1, QueueApplicationStoreV1
from app.minimal_clearance_queue_application_independent import restore_export_to_fresh_database, verify_database, verify_export_bytes, read_application_job


ARTIFACT_BYTES = 411_672
ARTIFACT_SHA256 = "69F653130822D15977BC14E450B62A5A20FF7CF12512C7BBBC79714B5A5BB38E"
ARTIFACT_SHA3_512 = "A2D3DDBA8C6ECAABC70147793185318FA7910E8EBBA0675D614E95885DAC23331C3F2FE3689F30748B030C9A26D55D704DB244C5DC36136896F6B87F42045BE1"
VERIFIER_SHA256 = "E2BD096389E7D9CB3F8D83314747CA3D493DF6C30D86A57041F74B84F0023F3E"


class _AcceptedStateVerifier:
    """Test-owned state adapter: expected statement only, never proof verify."""

    def __init__(self, acceptance: MinimalProofAcceptanceV1) -> None:
        self.acceptance = acceptance
        self.verify_calls = 0

    def identity_sha256(self) -> bytes:
        return bytes.fromhex(VERIFIER_SHA256)

    def expected_statement(self) -> bytes:
        return self.acceptance.statement.statement_bytes

    def verify(self, artifact_path: Path):
        self.verify_calls += 1
        raise RuntimeError("application_native_verifier_forbidden")


def _identity(path: Path) -> tuple[bytes, str, bool]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("identity_source")
    raw = path.read_bytes()
    return raw, hashlib.sha256(raw).hexdigest().upper(), not bool(path.stat().st_mode & stat.S_IWRITE)


def _json_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def run(*, queue_database: Path, application_database: Path, state_database: Path, restore_database: Path, artifact: Path, verifier: Path, evidence_output: Path, job_ids: list[str]) -> dict[str, object]:
    targets = (application_database, state_database, restore_database, evidence_output)
    if any(path.exists() or path.is_symlink() for path in targets) or len(job_ids) != 4 or len(set(job_ids)) != 4:
        raise RuntimeError("fresh_target_or_job_set")
    artifact_raw, artifact_hash, artifact_readonly = _identity(artifact)
    _, verifier_hash, _ = _identity(verifier)
    if len(artifact_raw) != ARTIFACT_BYTES or artifact_hash != ARTIFACT_SHA256 or hashlib.sha3_512(artifact_raw).hexdigest().upper() != ARTIFACT_SHA3_512 or not artifact_readonly or verifier_hash != VERIFIER_SHA256:
        raise RuntimeError("source_identity")
    queue_jobs = [read_application_job(queue_database, job_id) for job_id in job_ids]
    first = queue_jobs[0]
    if any(
        item.queue_id != first.queue_id or item.config_digest != first.config_digest or item.verifier_sha256 != first.verifier_sha256
        or item.acceptance_bytes != first.acceptance_bytes or item.receipt_bytes == b""
        for item in queue_jobs
    ):
        raise RuntimeError("queue_binding")
    acceptance = parse_acceptance_bytes(first.acceptance_bytes)
    state_verifier = _AcceptedStateVerifier(acceptance)
    state = MinimalClearanceStateStoreV1(path=state_database, verifier=state_verifier)
    before_state = state.snapshot()
    fault_mode = {"name": "after_state_commit_before_coordinator"}

    def fault(name: str) -> None:
        if name == fault_mode["name"]:
            fault_mode["name"] = "none"
            raise RuntimeError("synthetic_coordinator_fault")

    config = QueueApplicationConfigV1(
        application_id="minimal-clearance-queue-application-exercise",
        queue_id=first.queue_id,
        queue_config_digest=first.config_digest,
        verifier_sha256=first.verifier_sha256,
        state_store_identity=state.state_store_identity(),
        capacity=16,
    )
    app = QueueApplicationStoreV1(path=application_database, config=config, before_fault=fault)
    for job_id in job_ids:
        app.discover(queue_database, job_id)
    works = [app.claim_next(f"application-worker-{index}") for index in range(4)]
    if any(work is None for work in works):
        raise RuntimeError("application_claim_count")
    results = []
    recovery_count = 0
    for index, work in enumerate(works):
        try:
            result = app.apply(work, queue_database=queue_database, state_store=state)
        except RuntimeError as exc:
            if str(exc) != "synthetic_coordinator_fault":
                raise
            recovery_count += 1
            if index == 0:
                fault_mode["name"] = "none"
            elif index == 1:
                fault_mode["name"] = "none"
            result = app.apply(work, queue_database=queue_database, state_store=state)
            if index == 0:
                fault_mode["name"] = "before_application_commit"
        results.append(result)
    if len(results) != 4 or any(result.status != "APPLIED" for result in results) or sum(not result.duplicate_convergence for result in results) != 1 or sum(result.duplicate_convergence for result in results) != 3:
        raise RuntimeError("application_result_shape")
    after_state = state.snapshot()
    if after_state.sequence != before_state.sequence + 1 or after_state.payment_root != before_state.payment_root or after_state.settled_batch_count != before_state.settled_batch_count:
        raise RuntimeError("state_mutation_shape")
    if len({result.state_receipt_bytes for result in results}) != 1 or state_verifier.verify_calls != 0:
        raise RuntimeError("state_receipt_or_native_call")
    app.verify_integrity()
    exported = app.export_bytes()
    producer_summary = verify_database(application_database, expected_config=config.as_json())
    export_summary = verify_export_bytes(exported, expected_config=config.as_json())
    restored_summary = restore_export_to_fresh_database(restore_database, exported)
    if producer_summary != export_summary or export_summary != restored_summary:
        raise RuntimeError("application_reconstruction_parity")
    state.close()
    restarted = MinimalClearanceStateStoreV1(path=state_database, verifier=_AcceptedStateVerifier(acceptance))
    restarted.verify_integrity()
    restarted_after = restarted.snapshot()
    if restarted_after != after_state:
        raise RuntimeError("state_restart_parity")
    restarted.close()
    artifact_after, artifact_hash_after, artifact_readonly_after = _identity(artifact)
    _, verifier_hash_after, _ = _identity(verifier)
    if artifact_after != artifact_raw or artifact_hash_after != ARTIFACT_SHA256 or not artifact_readonly_after or verifier_hash_after != VERIFIER_SHA256:
        raise RuntimeError("source_identity_changed")
    receipt = json.loads(results[0].state_receipt_bytes.decode("ascii"))
    output = {
        "schema": "BL/NATIVE-V3/MINIMAL-CLEARANCE-QUEUE-APPLICATION/INTEGRATION-EVIDENCE/v1",
        "application_schema": 1,
        "queue_verified_job_count": 4,
        "application_applied_count": 4,
        "application_duplicate_convergence_count": 3,
        "application_recovery_count": recovery_count,
        "state_transition_count": 1,
        "state_schema": restarted_after.schema_version,
        "policy_result": receipt["policy_result"],
        "effective_directive": receipt["effective_directive"],
        "proof_acceptance_is_clear": False,
        "economic_mutation": False,
        "payment_root_unchanged": True,
        "settled_batch_count_unchanged": True,
        "artifact_bytes": ARTIFACT_BYTES,
        "artifact_sha256": ARTIFACT_SHA256,
        "artifact_sha3_512": ARTIFACT_SHA3_512,
        "artifact_readonly_before": artifact_readonly,
        "artifact_readonly_after": artifact_readonly_after,
        "verifier_sha256": VERIFIER_SHA256,
        "queue_reconstruction_parity": True,
        "application_reconstruction_parity": True,
        "state_restart_integrity": True,
        "state_store_verifier_calls": 0,
        "application_native_verifier_invocations": 0,
        "prover_invocation_count": 0,
        "proof_suite_id": None,
        "production_usable": False,
        "activation": False,
        "payment_authority": False,
        "clearance_authority": False,
        "experimental_software_only": True,
    }
    encoded = _json_bytes(output)
    if len(encoded) > 8192 or b"C:\\" in encoded or b"stdout" in encoded or b"stderr" in encoded or b"proof_bytes" in encoded:
        raise RuntimeError("evidence_privacy")
    evidence_output.parent.mkdir(parents=True, exist_ok=True)
    with evidence_output.open("xb") as handle:
        handle.write(encoded)
        handle.flush()
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-database", type=Path, required=True)
    parser.add_argument("--application-database", type=Path, required=True)
    parser.add_argument("--state-database", type=Path, required=True)
    parser.add_argument("--restore-database", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    parser.add_argument("--job-id", action="append", required=True)
    args = parser.parse_args()
    values = vars(args)
    values["job_ids"] = values.pop("job_id")
    output = run(**values)
    print(json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
