from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.air_binary_ir import encode_air_program
from experiments.fixed_shape_claim_air.air_composition import (
    build_boolean_application_sha3_program,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.sha3_512_boolean_executable_air import (
    build_sha3_boolean_sponge_program,
)
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)
from experiments.fixed_shape_claim_air.wave1a_global_sha3_schedule import (
    build_wave1a_global_sha3_schedule,
)


@pytest.mark.parametrize(
    (
        "profile_id",
        "calls",
        "permutations",
        "shards",
        "padded",
        "commitment",
        "descriptor",
    ),
    (
        (
            "K128_CALIBRATION",
            46_858,
            113_730,
            1,
            131_072,
            "2422aa275787b8dd44e4ca8be711a44721e77f9e0a48834afea7be26ada9144ed"
            "9899e6031948b7ae28e7b73ed4d578e6bacb01ddc3d9bb58a59a6fb76d492ff",
            "d7b979425eee9ac48804c27f0d90e1e67083a9f85c038f4b735067c57d23b6d"
            "859841f4f97470168d6f48079fa788e4b8e2b0abe63ac51819975cd64996e80dd",
        ),
        (
            "K256_DESIGN_POINT",
            88_198,
            216_366,
            2,
            262_144,
            "e94c46b29cf051083a91c0dfd32dcad7055022bac651d71ae66ccacc2194b114a"
            "a296b59e17c0b1c981764797e4bff8cddd32c0a36e6de6f9ba8d339e3f07ed9",
            "8a18c4ee2015470d5cec98c9b41fa92e8c6d5c9a88a6c7278cf1e28e82e5249d"
            "544bb94c38dea183ba5c36cc04aa740910e12bd1ff59c548e9f55d122833b220",
        ),
        (
            "K512_CALIBRATION",
            165_762,
            411_406,
            4,
            524_288,
            "2f9f836cd9af695b5760e1680453f68bcbe16d3ed0eb8e2c25177b16387c81c6"
            "417d86e1dc530afc0f77d6b7192709aac385fb418eacaf2f752ce434cdd59328",
            "c8328a2c76c3c2c4fbedbc723a2250dcf6ee0b9f198f15241113860a628788cea"
            "d865b1372b4877101f56023e47deb5f372fa6d54e0ccd5352c25332e325eb91",
        ),
    ),
)
def test_capacity_schedule_reconciles_calls_and_exact_permutations(
    profile_id: str,
    calls: int,
    permutations: int,
    shards: int,
    padded: int,
    commitment: str,
    descriptor: str,
) -> None:
    profile = get_profile(profile_id)
    schedule = build_wave1a_global_sha3_capacity_schedule(profile)

    assert schedule.total_calls == build_wave1a_global_sha3_schedule(profile).total_calls == calls
    assert len(schedule.capacities) == calls
    assert schedule.total_permutations == permutations
    assert schedule.coprocessor_shards == shards
    assert schedule.padded_permutations == padded
    assert schedule.commitment_512.hex() == commitment
    assert schedule.descriptor_commitment_512.hex() == descriptor


def test_complete_k128_sha3_verifier_program_is_physically_buildable() -> None:
    schedule = build_wave1a_global_sha3_capacity_schedule(
        get_profile("K128_CALIBRATION")
    )
    program = build_sha3_boolean_sponge_program(schedule.capacities)
    encoded = encode_air_program(program)

    assert tuple(
        (table.name, table.rows, len(table.columns), len(table.identities))
        for table in program.tables
    ) == (
        ("sha3_boolean_round", 2_843_250, 1_995, 3_527),
        ("sha3_boolean_absorb", 113_730, 2_337, 2_480),
        ("sha3_boolean_digest", 46_858, 577, 576),
    )
    assert len(program.lookups) == 3
    assert program.maximum_degree == 11
    assert len(program.canonical_bytes()) == 13_747_652
    assert len(encoded) == 9_309_495
    assert program.commitment().hex() == (
        "9485e48c30c17f3e8b6e8ae66d9fddf97a8e18a82ccea0c8a072e920da64a45"
        "e4257f6b548289ae298b63f753c79bd23ea80d786f13155aa8b2e835df76c7da7"
    )


def test_complete_k128_application_sha3_ports_bind_to_boolean_engine() -> None:
    schedule = build_wave1a_global_sha3_capacity_schedule(
        get_profile("K128_CALIBRATION")
    )
    program = build_boolean_application_sha3_program(schedule.capacities)
    encoded = encode_air_program(program)

    assert tuple(table.name for table in program.tables) == (
        "sha3_message_batch",
        "sha3_digest_batch",
        "sha3_digest_byte_batch",
        "sha3_boolean_round",
        "sha3_boolean_absorb",
        "sha3_boolean_digest",
    )
    assert program.tables[0].rows == 8_188_560
    assert len(program.tables[0].columns) == 6
    assert len(program.lookups) == 6
    assert program.maximum_degree == 11
    assert len(program.canonical_bytes()) == 16_607_233
    assert len(encoded) == 11_942_817
    assert program.commitment().hex() == (
        "24eb5b14f2084fc1707396b76ad96c662f0ea9850ccca517cf9b034509c283035"
        "3d41a8679a4d1115a59860d3d6dbe0912e3a32d1dd21e7ced9008161f9a321e"
    )
