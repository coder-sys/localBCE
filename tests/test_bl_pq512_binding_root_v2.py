from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.binding_root_v2 import (
    BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES,
    BINDING_MERKLE_MULTIPROOF_V2_MAGIC,
    BINDING_MERKLE_MULTIPROOF_V2_VERSION,
    BINDING_V2_BYTES,
    BINDING_V2_LANE_BYTES,
    BINDING_V2_LEFT_DOMAIN,
    BINDING_V2_MAGIC,
    BINDING_V2_RIGHT_DOMAIN,
    BINDING_V2_VERSION,
    MAX_BINDING_MERKLE_FRONTIER_V2,
    MAX_BINDING_MERKLE_LEAVES_V2,
    MAX_BINDING_MERKLE_MULTIPROOF_V2_BYTES,
    MAX_BINDING_MERKLE_OPENINGS_V2,
    BindingDigestV2,
    BindingMerkleLeafV2,
    BindingMerkleMultiProofV2,
    BindingMerkleNodeV2,
    BindingMerklePositionV2,
    BindingMerkleTreeV2,
    BindingRoleV2,
    BindingRootV2,
    BindingRootV2Error,
    canonical_binding_frontier_positions_v2,
)


RUST_DIGEST_KAT = bytes.fromhex(
    "43d5603c7bbbba85ab0e9feb18ceee8ad70eb21da7c02da2fd830be7bed559a5"
    "93900167d5031ae78bca1151f88baa7a42e5cbc8e06beb940aa0330d59a203b5"
    "8914b636d5915b42c2079ff1843d9be1907416d1bafca0ffd2f11ad4054d395d"
    "6620d2de0574aed22b2a691af140656b21d1e58c50e3be238e5e03030a25f2ab"
)
RUST_FOUR_LEAF_ROOT_KAT = bytes.fromhex(
    "7d09eb42262ccc25543083285f4b6894f72526c8b0636cf388a8e0c45eeb40e"
    "c3b9393590185f1ea527e4d963595681330f5b98aba0e708fd877956f6b84f91"
    "3ce25eb0360388ca72283907729c8caff971ffe36b8a79d24350c0c2915bdc43"
    "618a5f0c54d2eeec0cb0520c40229ec2d007f862f88cfc9bf6d7d4fdb3cf9a3ff"
)
RUST_FOUR_LEAF_PROOF_KAT = bytes.fromhex(
    "424c42324d503032000200000000000000000004000000020000000200000000"
    "0000000100000000000000037152aec000c7aa5b706803da188ac4b91e28d052"
    "ae6f4f6552e554ee320a6bdfafe20eaafa3da78d6cb86524560dcf33a9aab3d"
    "fadcf8f2cd4f76e286e75af8890d08e0555c0cc45e116307abc4beef6608ef7"
    "e271427dc7ecb62f8dafc0a29a8a9d39a7133d48889a36bfc2e11b2678569e"
    "11068d3694240e018b14cecf8ba25786eef1c4330741a8bffaabb7f565e8ac02"
    "8bd3cbaa008ec0229cad966fbed6e59ee424fa19892af4beea240799db55bde5"
    "74a92cecf209c6b7e903d8726cbaae221a491a57da800266edb86ba072cce2f"
    "32d6a3a701b49cef1598207f54167233dc0620bd0920347be5fb39237e3ffd95"
    "5709dfd900480f4830d4f75e9f128"
)
RUST_SINGLE_LEAF_ROOT_KAT = bytes.fromhex(
    "3026eefb04563fc704f621dc15c30229039cf9e6139a1b3cbdec51482be49eea"
    "c5ad8f9cefa429c3d9117a4b680a60053af042ee0f4388af7bbf05e04f45f8b"
    "a722494d06ae47191556b402d6bf911e358721e236cd0da4698ab39fa0063984"
    "a9f06daeb73f7dab01fd68296f1cf3c170521bb35ae5602281ed979e64c1f9fc6"
)


def _four_leaf_fixture() -> tuple[tuple[bytes, ...], BindingMerkleTreeV2]:
    payloads = (b"alpha", b"beta", b"gamma", b"delta")
    return payloads, BindingMerkleTreeV2.from_payloads(payloads)


def _assert_error(code: str, call) -> None:
    with pytest.raises(BindingRootV2Error) as caught:
        call()
    assert caught.value.code == code


def test_frozen_frame_constants_and_independent_dual_lane_rust_kat() -> None:
    assert BINDING_V2_BYTES == 128
    assert BINDING_V2_LANE_BYTES == 64
    assert BINDING_V2_MAGIC == b"BLBIND02"
    assert BINDING_V2_VERSION == 2
    assert BINDING_V2_LEFT_DOMAIN == b"BL/PQ512/WAVE2/BINDING/LEFT/v2\x00"
    assert BINDING_V2_RIGHT_DOMAIN == b"BL/PQ512/WAVE2/BINDING/RIGHT/v2\x00"
    assert int(BindingRoleV2.PAYLOAD) == 0x0001
    assert int(BindingRoleV2.MERKLE_LEAF) == 0x0101
    assert int(BindingRoleV2.MERKLE_NODE) == 0x0102
    assert int(BindingRoleV2.MERKLE_ROOT) == 0x0103

    payload = b"binding-root-v2-kat"
    frame = b"".join(
        (
            BINDING_V2_MAGIC,
            BINDING_V2_VERSION.to_bytes(2, "big"),
            int(BindingRoleV2.PAYLOAD).to_bytes(2, "big"),
            len(payload).to_bytes(8, "big"),
            payload,
        )
    )
    independently_derived = (
        sha3_512(BINDING_V2_LEFT_DOMAIN + frame).digest()
        + sha3_512(BINDING_V2_RIGHT_DOMAIN + frame).digest()
    )
    actual = BindingDigestV2.hash(BindingRoleV2.PAYLOAD, payload)
    assert independently_derived == RUST_DIGEST_KAT
    assert actual.to_bytes() == RUST_DIGEST_KAT
    assert RUST_DIGEST_KAT[:64] != RUST_DIGEST_KAT[64:]
    assert actual != BindingDigestV2.hash(BindingRoleV2.MERKLE_LEAF, payload)
    assert actual != BindingDigestV2.hash(BindingRoleV2.PAYLOAD, payload + b"\x00")


def test_exact_rust_tree_root_and_canonical_multiproof_kat_roundtrip() -> None:
    payloads, tree = _four_leaf_fixture()
    assert tree.leaf_count == 4
    assert tree.root.to_bytes() == RUST_FOUR_LEAF_ROOT_KAT
    assert canonical_binding_frontier_positions_v2(4, (1, 3)) == (
        BindingMerklePositionV2(level=0, index=0),
        BindingMerklePositionV2(level=0, index=2),
    )

    proof = tree.prove((1, 3))
    assert len(RUST_FOUR_LEAF_PROOF_KAT) == 300
    assert proof.encode() == RUST_FOUR_LEAF_PROOF_KAT
    decoded = BindingMerkleMultiProofV2.decode(RUST_FOUR_LEAF_PROOF_KAT)
    assert decoded == proof
    assert decoded.leaf_count == 4
    assert decoded.selected_indices == (1, 3)
    assert len(decoded.frontier_digests) == 2
    decoded.verify_payloads((payloads[1], payloads[3]), tree.root)


def test_single_leaf_root_wrapper_and_empty_frontier_match_rust() -> None:
    payloads = (b"only",)
    tree = BindingMerkleTreeV2.from_payloads(payloads)
    assert tree.root.to_bytes() == RUST_SINGLE_LEAF_ROOT_KAT
    proof = tree.prove((0,))
    assert proof.frontier_digests == ()
    assert len(proof.encode()) == BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES + 8
    assert proof.encode() == bytes.fromhex(
        "424c42324d5030320002000000000000000000010000000100000000"
        "0000000000000000"
    )
    BindingMerkleMultiProofV2.decode(proof.encode()).verify_payloads(
        payloads, tree.root
    )


def test_every_nonempty_subset_of_eight_roundtrips_canonically() -> None:
    payloads = (
        b"zero",
        b"one",
        b"two",
        b"three",
        b"four",
        b"five",
        b"six",
        b"seven",
    )
    tree = BindingMerkleTreeV2.from_payloads(payloads)
    checked = 0
    for selection_mask in range(1, 1 << len(payloads)):
        indices = tuple(
            index
            for index in range(len(payloads))
            if selection_mask & (1 << index)
        )
        opened = tuple(payloads[index] for index in indices)
        proof = tree.prove(indices)
        encoded = proof.encode()
        decoded = BindingMerkleMultiProofV2.decode(encoded)
        assert decoded == proof
        assert decoded.encode() == encoded
        decoded.verify_payloads(opened, tree.root)
        checked += 1
    assert checked == 255


def test_both_lanes_leaf_frontier_root_and_lane_swaps_reject() -> None:
    payloads, tree = _four_leaf_fixture()
    proof = tree.prove((1, 3))
    opened = (payloads[1], payloads[3])
    leaves = (
        BindingMerkleLeafV2.hash(1, opened[0]),
        BindingMerkleLeafV2.hash(3, opened[1]),
    )
    first_frontier = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES + 2 * 8

    for lane_offset in (0, BINDING_V2_LANE_BYTES):
        mutated_leaf_bytes = bytearray(leaves[0].as_bytes)
        mutated_leaf_bytes[lane_offset] ^= 1
        mutated_leaves = (
            BindingMerkleLeafV2.decode(bytes(mutated_leaf_bytes)),
            leaves[1],
        )
        _assert_error(
            "RootMismatch",
            lambda: proof.verify_leaf_hashes(mutated_leaves, tree.root),
        )

        mutated_proof = bytearray(proof.encode())
        mutated_proof[first_frontier + lane_offset] ^= 1
        decoded = BindingMerkleMultiProofV2.decode(bytes(mutated_proof))
        _assert_error("RootMismatch", lambda: decoded.verify_payloads(opened, tree.root))

        mutated_root = bytearray(tree.root.to_bytes())
        mutated_root[lane_offset] ^= 1
        decoded_root = BindingRootV2.decode(bytes(mutated_root))
        _assert_error(
            "RootMismatch", lambda: proof.verify_payloads(opened, decoded_root)
        )

    lane_swapped = bytearray(proof.encode())
    digest = lane_swapped[first_frontier : first_frontier + BINDING_V2_BYTES]
    lane_swapped[first_frontier : first_frontier + BINDING_V2_BYTES] = (
        digest[64:] + digest[:64]
    )
    swapped_proof = BindingMerkleMultiProofV2.decode(bytes(lane_swapped))
    _assert_error(
        "RootMismatch", lambda: swapped_proof.verify_payloads(opened, tree.root)
    )

    swapped_root = BindingRootV2.decode(
        tree.root.to_bytes()[64:] + tree.root.to_bytes()[:64]
    )
    _assert_error("RootMismatch", lambda: proof.verify_payloads(opened, swapped_root))

    reordered = bytearray(proof.encode())
    first = bytes(reordered[first_frontier : first_frontier + BINDING_V2_BYTES])
    second_start = first_frontier + BINDING_V2_BYTES
    second = bytes(reordered[second_start : second_start + BINDING_V2_BYTES])
    reordered[first_frontier : first_frontier + BINDING_V2_BYTES] = second
    reordered[second_start : second_start + BINDING_V2_BYTES] = first
    reordered_proof = BindingMerkleMultiProofV2.decode(bytes(reordered))
    _assert_error(
        "RootMismatch", lambda: reordered_proof.verify_payloads(opened, tree.root)
    )


def test_noncanonical_indices_frontier_and_payload_positions_reject() -> None:
    payloads, tree = _four_leaf_fixture()
    encoded = tree.prove((1, 3)).encode()
    first_index = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
    second_index = first_index + 8

    duplicate = bytearray(encoded)
    duplicate[second_index : second_index + 8] = (1).to_bytes(8, "big")
    _assert_error(
        "IndicesNotStrictlyIncreasing",
        lambda: BindingMerkleMultiProofV2.decode(bytes(duplicate)),
    )

    reversed_indices = bytearray(encoded)
    reversed_indices[first_index : first_index + 8] = (3).to_bytes(8, "big")
    reversed_indices[second_index : second_index + 8] = (1).to_bytes(8, "big")
    _assert_error(
        "IndicesNotStrictlyIncreasing",
        lambda: BindingMerkleMultiProofV2.decode(bytes(reversed_indices)),
    )

    out_of_range = bytearray(encoded)
    out_of_range[second_index : second_index + 8] = (4).to_bytes(8, "big")
    _assert_error(
        "IndexOutOfRange",
        lambda: BindingMerkleMultiProofV2.decode(bytes(out_of_range)),
    )
    _assert_error("TooManyOpenings", lambda: tree.prove(()))
    _assert_error("IndicesNotStrictlyIncreasing", lambda: tree.prove((1, 1)))
    _assert_error("IndexOutOfRange", lambda: tree.prove((4,)))

    wrong_frontier_count = bytearray(encoded)
    wrong_frontier_count[24:28] = (1).to_bytes(4, "big")
    del wrong_frontier_count[-BINDING_V2_BYTES:]
    _assert_error(
        "FrontierLength",
        lambda: BindingMerkleMultiProofV2.decode(bytes(wrong_frontier_count)),
    )

    proof = tree.prove((1, 3))
    _assert_error(
        "RootMismatch",
        lambda: proof.verify_payloads((payloads[3], payloads[1]), tree.root),
    )
    _assert_error(
        "PayloadCount", lambda: proof.verify_payloads((payloads[1],), tree.root)
    )
    assert BindingMerkleLeafV2.hash(1, b"same") != BindingMerkleLeafV2.hash(
        3, b"same"
    )


def test_parser_is_exact_bounded_and_rejects_header_and_trailing_mutations() -> None:
    _, tree = _four_leaf_fixture()
    encoded = tree.prove((1, 3)).encode()
    assert BINDING_MERKLE_MULTIPROOF_V2_MAGIC == b"BLB2MP02"
    assert BINDING_MERKLE_MULTIPROOF_V2_VERSION == 2
    assert MAX_BINDING_MERKLE_LEAVES_V2 == 1 << 32
    assert MAX_BINDING_MERKLE_OPENINGS_V2 == 4_096
    assert MAX_BINDING_MERKLE_FRONTIER_V2 == 131_072
    assert MAX_BINDING_MERKLE_MULTIPROOF_V2_BYTES == 16_810_012

    for truncated_length in (0, 1, 27, len(encoded) - 1):
        _assert_error(
            "ProofLength",
            lambda length=truncated_length: BindingMerkleMultiProofV2.decode(
                encoded[:length]
            ),
        )
    _assert_error(
        "ProofLength", lambda: BindingMerkleMultiProofV2.decode(encoded + b"\x00")
    )

    wrong_magic = bytearray(encoded)
    wrong_magic[0] ^= 1
    _assert_error(
        "ProofMagic", lambda: BindingMerkleMultiProofV2.decode(bytes(wrong_magic))
    )
    wrong_version = bytearray(encoded)
    wrong_version[9] ^= 1
    _assert_error(
        "ProofVersion", lambda: BindingMerkleMultiProofV2.decode(bytes(wrong_version))
    )
    flags = bytearray(encoded)
    flags[11] = 1
    _assert_error(
        "ProofFlags", lambda: BindingMerkleMultiProofV2.decode(bytes(flags))
    )

    for leaf_count, error in (
        (0, "EmptyTree"),
        (3, "NonPowerOfTwo"),
        (1 << 33, "TooManyLeaves"),
    ):
        changed = bytearray(encoded)
        changed[12:20] = leaf_count.to_bytes(8, "big")
        _assert_error(
            error,
            lambda value=bytes(changed): BindingMerkleMultiProofV2.decode(value),
        )

    malicious_header = bytearray(BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES)
    malicious_header[:8] = BINDING_MERKLE_MULTIPROOF_V2_MAGIC
    malicious_header[8:10] = BINDING_MERKLE_MULTIPROOF_V2_VERSION.to_bytes(2, "big")
    malicious_header[12:20] = (4).to_bytes(8, "big")
    malicious_header[20:24] = (0xFFFFFFFF).to_bytes(4, "big")
    _assert_error(
        "TooManyOpenings",
        lambda: BindingMerkleMultiProofV2.decode(bytes(malicious_header)),
    )
    malicious_header[20:24] = (1).to_bytes(4, "big")
    malicious_header[24:28] = (0xFFFFFFFF).to_bytes(4, "big")
    _assert_error(
        "TooManyFrontierDigests",
        lambda: BindingMerkleMultiProofV2.decode(bytes(malicious_header)),
    )


def test_geometry_node_level_root_and_legacy64_reject() -> None:
    _assert_error("EmptyTree", lambda: BindingMerkleTreeV2.from_payloads(()))
    _assert_error(
        "NonPowerOfTwo",
        lambda: BindingMerkleTreeV2.from_payloads((b"a", b"b", b"c")),
    )
    digest = BindingDigestV2.hash(BindingRoleV2.PAYLOAD, b"node")
    _assert_error(
        "InvalidNodeLevel", lambda: BindingMerkleNodeV2.hash(0, 0, digest, digest)
    )
    assert BindingMerkleNodeV2.hash(1, 0, digest, digest) != BindingMerkleNodeV2.hash(
        1, 1, digest, digest
    )
    assert BindingMerkleNodeV2.hash(1, 0, digest, digest) != BindingMerkleNodeV2.hash(
        2, 0, digest, digest
    )

    legacy_root = bytes([0x5A]) * 64
    for decoder in (
        BindingDigestV2.decode,
        BindingMerkleLeafV2.decode,
        BindingRootV2.decode,
    ):
        _assert_error("DigestLength", lambda decoder=decoder: decoder(legacy_root))
    _assert_error("DigestLength", lambda: BindingRootV2.decode(bytes(127)))
    _assert_error("DigestLength", lambda: BindingRootV2.decode(bytes(129)))
