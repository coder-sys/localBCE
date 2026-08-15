import cuda_semantic_h4_bridge_gkr_worker as worker


class _K128Source:
    profile = 1


def test_zero_output_claim_does_not_materialize_padded_relation():
    engine = object.__new__(worker.ProductionBridgeEngine)
    engine.source = _K128Source()
    engine._materialize = lambda *args: (_ for _ in ()).throw(
        AssertionError("output claim must not materialize the relation")
    )

    cases = (
        (worker.CIRCUIT_RATE, 23),
        (worker.CIRCUIT_INACTIVE, 30),
        (worker.CIRCUIT_CAPACITY, 29),
        (worker.CIRCUIT_DIGEST, 24),
    )
    for circuit, point_length in cases:
        assert engine.output_claim(circuit, (worker._fp16_zero(),) * point_length) == worker._fp16_zero()


def test_retained_accumulator_fold_hand_fixture():
    # Two suffixes, two wires. Each record is
    # [left(bit=0), right(bit=0), left(bit=1), right(bit=1)].
    records = (
        (2, 3, 4, 5), (7, 11, 13, 17),
        (19, 23, 29, 31), (37, 41, 43, 47),
    )
    challenge = 3
    actual = []
    for suffix in range(1):
        for wire in range(2):
            slots = []
            for next_bit in range(2):
                record = records[(2 * suffix + next_bit) * 2 + wire]
                slots.extend(
                    record[side] + challenge * (record[side + 2] - record[side])
                    for side in range(2)
                )
            actual.append(tuple(value % worker.M31 for value in slots))
    assert actual == [(8, 9, 49, 47), (25, 29, 55, 59)]
