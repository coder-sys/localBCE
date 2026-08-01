"""Print a fresh-process, phase-separated corrected K128 SHA3 measurement."""

from __future__ import annotations

import json
import os
from pathlib import Path

from experiments.bl_pq512_crypto_foundation.application_sha3_measurement import (
    ApplicationSha3Measurement,
    STATUS,
)
from experiments.bl_pq512_crypto_foundation.application_sha3_port_inventory import (
    CALLSITE_DISPOSITIONS,
    PortDisposition,
)
from experiments.fixed_shape_claim_air.claim_truth_reference import (
    build_claim_truth_reference,
)
from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_relation_trace,
)
from experiments.fixed_shape_claim_air.wave1a_relation_reference import (
    build_wave1a_reference_relation,
)
from tests import test_wave1a_relation_reference as fixture


ROOT = Path(__file__).resolve().parents[2]


def _phase(measurement: ApplicationSha3Measurement) -> dict[str, object]:
    observations = measurement.observations()
    by_disposition = {
        disposition.value: sum(
            value.invocations
            for value in observations
            if CALLSITE_DISPOSITIONS[value.callsite] is disposition
        )
        for disposition in PortDisposition
    }
    permutations_by_disposition = {
        disposition.value: sum(
            value.total_permutations
            for value in observations
            if CALLSITE_DISPOSITIONS[value.callsite] is disposition
        )
        for disposition in PortDisposition
    }
    return {
        "invocations": sum(value.invocations for value in observations),
        "permutations": sum(value.total_permutations for value in observations),
        "byDisposition": by_disposition,
        "permutationsByDisposition": permutations_by_disposition,
        "observations": [
            {
                "id": value.callsite.stable_id,
                "preimageBytes": value.preimage_bytes,
                "invocations": value.invocations,
                "permutationsPerInvocation": value.permutations_per_invocation,
            }
            for value in observations
        ],
    }


def main() -> None:
    os.environ.update(
        BL_ENV="test",
        BL_DEV="1",
        BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE="1",
    )
    profile = fixture.profile.__wrapped__()
    phases: dict[str, object] = {}
    with ApplicationSha3Measurement(ROOT) as measurement:
        slots = fixture.slots.__wrapped__(profile)
        replay = fixture.replay.__wrapped__(profile)
        context = fixture.context.__wrapped__()
        phases["fixtureAndContext"] = _phase(measurement)

        measurement.clear()
        truth = build_claim_truth_reference(profile, slots)
        relation = build_wave1a_reference_relation(
            profile,
            slots,
            truth.governed_roots(),
            truth.authentication,
            replay,
            context,
        )
        phases["relationBuild"] = _phase(measurement)

        measurement.clear()
        build_wave1a_physical_relation_trace(profile, relation)
        phases["physicalTraceBuild"] = _phase(measurement)

    print(
        json.dumps(
            {
                "status": STATUS,
                "profileId": profile.profile_id,
                "oracleRecords": len(truth.oracle_tree.canonical_records),
                "phases": phases,
                "proofSuiteId": None,
                "activationAllowed": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
