from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.wave1a_global_sha3_schedule import (
    COMPONENTS,
    build_wave1a_global_sha3_schedule,
)


def test_all_profiles_have_exact_contiguous_global_sha3_offsets() -> None:
    expected_totals = {
        "K128_CALIBRATION": 46_858,
        "K256_DESIGN_POINT": 88_198,
        "K512_CALIBRATION": 165_762,
    }
    observed = {}
    for profile_id, profile in PROFILES.items():
        schedule = build_wave1a_global_sha3_schedule(profile)
        assert tuple(segment.component for segment in schedule.segments) == COMPONENTS
        assert tuple(segment.call_offset for segment in schedule.segments) == tuple(
            sum(value.call_count for value in schedule.segments[:index])
            for index in range(len(schedule.segments))
        )
        assert schedule.total_calls == sum(
            segment.call_count for segment in schedule.segments
        )
        assert schedule.total_calls == expected_totals[profile_id]
        observed[profile_id] = schedule.commitment_512.hex()
    assert observed == {
        "K128_CALIBRATION": (
            "2d2792d30f838618190a95817f44204308e2a0e7f460b71e48da779ccd2472cb"
            "11ae3342a2df9a52f01561c80aaa3d3fafa2d77271fd9eb4f6ee6270006e3aa6"
        ),
        "K256_DESIGN_POINT": (
            "a8eb2fcd3a7f80fabded6665cbd04fce4d7dbc5ce748f24d81c11b086d402fe3"
            "ffed9331df49f46f869be49f9d0c541f9f1c303c90b97ec4719b3713f83e9300"
        ),
        "K512_CALIBRATION": (
            "419d20a6525b95e9ac0d6764a4fbe8d7422b1735509d79761005d24637a49b29"
            "58dfa7ce69592a977d44719060d44c5d335efdde9fe933a7241911df61ebd1cd"
        ),
    }
