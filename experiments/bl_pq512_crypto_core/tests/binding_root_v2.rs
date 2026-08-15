use core::mem::size_of;

use bl_pq512_crypto_core::binding_root_v2::{
    BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES, BINDING_MERKLE_MULTIPROOF_V2_MAGIC,
    BINDING_MERKLE_MULTIPROOF_V2_VERSION, BINDING_V2_BYTES, BINDING_V2_LEFT_DOMAIN,
    BINDING_V2_MAGIC, BINDING_V2_RIGHT_DOMAIN, BINDING_V2_VERSION, BindingDigestV2,
    BindingMerkleLeafV2, BindingMerkleMultiProofV2, BindingMerkleNodeV2, BindingMerklePositionV2,
    BindingMerkleTreeV2, BindingRoleV2, BindingRootV2, BindingRootV2Error,
    canonical_binding_frontier_positions_v2,
};

#[cfg(feature = "std")]
use bl_pq512_crypto_core::binding_root_v2::BindingRootV2StreamError;

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal test vector"),
    }
}

fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
    assert_eq!(encoded.len(), N * 2);
    let mut output = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn four_leaf_fixture() -> ([&'static [u8]; 4], BindingMerkleTreeV2) {
    let payloads: [&[u8]; 4] = [b"alpha", b"beta", b"gamma", b"delta"];
    let tree = BindingMerkleTreeV2::from_payloads(&payloads).expect("valid fixture tree");
    (payloads, tree)
}

#[test]
fn frozen_frame_constants_and_independent_dual_lane_kat() {
    assert_eq!(BINDING_V2_MAGIC, b"BLBIND02");
    assert_eq!(BINDING_V2_VERSION, 2);
    assert_eq!(BINDING_V2_LEFT_DOMAIN, b"BL/PQ512/WAVE2/BINDING/LEFT/v2\0");
    assert_eq!(
        BINDING_V2_RIGHT_DOMAIN,
        b"BL/PQ512/WAVE2/BINDING/RIGHT/v2\0"
    );
    assert_eq!(BindingRoleV2::Payload.code(), 0x0001);
    assert_eq!(BindingRoleV2::MerkleLeaf.code(), 0x0101);
    assert_eq!(BindingRoleV2::MerkleNode.code(), 0x0102);
    assert_eq!(BindingRoleV2::MerkleRoot.code(), 0x0103);

    // Independently generated from the frozen byte preimage using Python's
    // hashlib.sha3_512, then embedded here as immutable Rust test data.
    let expected = decode_hex::<128>(concat!(
        "43d5603c7bbbba85ab0e9feb18ceee8ad70eb21da7c02da2fd830be7bed559a5",
        "93900167d5031ae78bca1151f88baa7a42e5cbc8e06beb940aa0330d59a203b5",
        "8914b636d5915b42c2079ff1843d9be1907416d1bafca0ffd2f11ad4054d395d",
        "6620d2de0574aed22b2a691af140656b21d1e58c50e3be238e5e03030a25f2ab"
    ));
    let actual = BindingDigestV2::hash(BindingRoleV2::Payload, b"binding-root-v2-kat")
        .expect("fixed input length fits u64");
    assert_eq!(actual.to_bytes(), expected);
    assert_ne!(&expected[..64], &expected[64..]);
    assert_ne!(
        actual,
        BindingDigestV2::hash(BindingRoleV2::MerkleLeaf, b"binding-root-v2-kat").unwrap()
    );
    assert_ne!(
        actual,
        BindingDigestV2::hash(BindingRoleV2::Payload, b"binding-root-v2-kat\0").unwrap()
    );
}

#[cfg(feature = "std")]
#[test]
fn streaming_payload_hash_is_byte_identical_and_exact_length() {
    use std::io::{Cursor, Read};

    let payload = (0..(2 * 1024 * 1024 + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    for role in [
        BindingRoleV2::Payload,
        BindingRoleV2::MerkleLeaf,
        BindingRoleV2::MerkleNode,
        BindingRoleV2::MerkleRoot,
    ] {
        let expected = BindingDigestV2::hash(role, &payload).unwrap();
        let mut reader = Cursor::new(&payload);
        let actual = BindingDigestV2::hash_reader_exact(
            role,
            u64::try_from(payload.len()).unwrap(),
            &mut reader,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    let expected = BindingDigestV2::hash(BindingRoleV2::Payload, b"bounded").unwrap();
    let mut enclosing = Cursor::new(b"boundedfollowing-section".as_slice());
    let mut bounded = enclosing.by_ref().take(7);
    assert_eq!(
        BindingDigestV2::hash_reader_exact(BindingRoleV2::Payload, 7, &mut bounded).unwrap(),
        expected
    );
    drop(bounded);
    assert_eq!(enclosing.position(), 7);

    let mut short = Cursor::new(b"short".as_slice());
    assert!(matches!(
        BindingDigestV2::hash_reader_exact(BindingRoleV2::Payload, 6, &mut short),
        Err(BindingRootV2StreamError::ShortPayload {
            declared: 6,
            actual: 5
        })
    ));

    let mut trailing = Cursor::new(b"exact!".as_slice());
    assert!(matches!(
        BindingDigestV2::hash_reader_exact(BindingRoleV2::Payload, 5, &mut trailing),
        Err(BindingRootV2StreamError::TrailingPayload)
    ));

    let mut empty = Cursor::new([0_u8; 0]);
    assert_eq!(
        BindingDigestV2::hash_reader_exact(BindingRoleV2::Payload, 0, &mut empty).unwrap(),
        BindingDigestV2::hash(BindingRoleV2::Payload, b"").unwrap()
    );
}

#[test]
fn exact_tree_root_and_canonical_multiproof_kat_roundtrip() {
    let (payloads, tree) = four_leaf_fixture();
    let expected_root = decode_hex::<128>(concat!(
        "7d09eb42262ccc25543083285f4b6894f72526c8b0636cf388a8e0c45eeb40e",
        "c3b9393590185f1ea527e4d963595681330f5b98aba0e708fd877956f6b84f91",
        "3ce25eb0360388ca72283907729c8caff971ffe36b8a79d24350c0c2915bdc43",
        "618a5f0c54d2eeec0cb0520c40229ec2d007f862f88cfc9bf6d7d4fdb3cf9a3ff"
    ));
    assert_eq!(tree.root().to_bytes(), expected_root);
    assert_eq!(tree.leaf_count(), 4);

    let positions = canonical_binding_frontier_positions_v2(4, &[1, 3]).unwrap();
    assert_eq!(
        positions,
        [
            BindingMerklePositionV2 { level: 0, index: 0 },
            BindingMerklePositionV2 { level: 0, index: 2 },
        ]
    );
    let proof = tree.prove(&[1, 3]).unwrap();
    let encoded = proof.encode().unwrap();
    let expected_proof = decode_hex::<300>(concat!(
        "424c42324d503032000200000000000000000004000000020000000200000000",
        "0000000100000000000000037152aec000c7aa5b706803da188ac4b91e28d052",
        "ae6f4f6552e554ee320a6bdfafe20eaafa3da78d6cb86524560dcf33a9aab3d",
        "fadcf8f2cd4f76e286e75af8890d08e0555c0cc45e116307abc4beef6608ef7",
        "e271427dc7ecb62f8dafc0a29a8a9d39a7133d48889a36bfc2e11b2678569e",
        "11068d3694240e018b14cecf8ba25786eef1c4330741a8bffaabb7f565e8ac02",
        "8bd3cbaa008ec0229cad966fbed6e59ee424fa19892af4beea240799db55bde5",
        "74a92cecf209c6b7e903d8726cbaae221a491a57da800266edb86ba072cce2f",
        "32d6a3a701b49cef1598207f54167233dc0620bd0920347be5fb39237e3ffd95",
        "5709dfd900480f4830d4f75e9f128"
    ));
    assert_eq!(encoded, expected_proof);

    let decoded = BindingMerkleMultiProofV2::decode(&expected_proof).unwrap();
    assert_eq!(decoded, proof);
    assert_eq!(decoded.leaf_count(), 4);
    assert_eq!(decoded.selected_indices(), [1, 3]);
    assert_eq!(decoded.frontier_digests().len(), 2);
    decoded
        .verify_payloads(&[payloads[1], payloads[3]], &tree.root())
        .unwrap();
}

#[test]
fn both_lanes_are_authenticated_for_leaf_frontier_and_root() {
    let (payloads, tree) = four_leaf_fixture();
    let proof = tree.prove(&[1, 3]).unwrap();
    let opened_payloads = [payloads[1], payloads[3]];
    let leaves = [
        BindingMerkleLeafV2::hash(1, opened_payloads[0]).unwrap(),
        BindingMerkleLeafV2::hash(3, opened_payloads[1]).unwrap(),
    ];

    for lane_offset in [0, 64] {
        let mut mutated_leaf = leaves;
        let mut bytes = mutated_leaf[0].as_bytes().to_owned();
        bytes[lane_offset] ^= 1;
        mutated_leaf[0] = BindingMerkleLeafV2::decode(&bytes).unwrap();
        assert_eq!(
            proof.verify_leaf_hashes(&mutated_leaf, &tree.root()),
            Err(BindingRootV2Error::RootMismatch)
        );

        let mut encoded = proof.encode().unwrap();
        let first_frontier = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES + 2 * 8;
        encoded[first_frontier + lane_offset] ^= 1;
        let mutated_frontier = BindingMerkleMultiProofV2::decode(&encoded).unwrap();
        assert_eq!(
            mutated_frontier.verify_payloads(&opened_payloads, &tree.root()),
            Err(BindingRootV2Error::RootMismatch)
        );

        let mut root_bytes = tree.root().to_bytes();
        root_bytes[lane_offset] ^= 1;
        let mutated_root = BindingRootV2::decode(&root_bytes).unwrap();
        assert_eq!(
            proof.verify_payloads(&opened_payloads, &mutated_root),
            Err(BindingRootV2Error::RootMismatch)
        );
    }

    let mut reordered_frontier = proof.encode().unwrap();
    let frontier = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES + 2 * 8;
    let (prefix, digests) = reordered_frontier.split_at_mut(frontier);
    assert_eq!(prefix.len(), frontier);
    let (first, second) = digests.split_at_mut(BINDING_V2_BYTES);
    first.swap_with_slice(&mut second[..BINDING_V2_BYTES]);
    let reordered = BindingMerkleMultiProofV2::decode(&reordered_frontier).unwrap();
    assert_eq!(
        reordered.verify_payloads(&opened_payloads, &tree.root()),
        Err(BindingRootV2Error::RootMismatch)
    );
}

#[test]
fn parser_rejects_index_mutations_and_noncanonical_sequences() {
    let (_, tree) = four_leaf_fixture();
    let encoded = tree.prove(&[1, 3]).unwrap().encode().unwrap();
    let first_index = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES;
    let second_index = first_index + 8;

    let mut duplicate = encoded.clone();
    duplicate[second_index..second_index + 8].copy_from_slice(&1_u64.to_be_bytes());
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&duplicate),
        Err(BindingRootV2Error::IndicesNotStrictlyIncreasing)
    );

    let mut reordered = encoded.clone();
    reordered[first_index..first_index + 8].copy_from_slice(&3_u64.to_be_bytes());
    reordered[second_index..second_index + 8].copy_from_slice(&1_u64.to_be_bytes());
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&reordered),
        Err(BindingRootV2Error::IndicesNotStrictlyIncreasing)
    );

    let mut out_of_range = encoded;
    out_of_range[second_index..second_index + 8].copy_from_slice(&4_u64.to_be_bytes());
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&out_of_range),
        Err(BindingRootV2Error::IndexOutOfRange)
    );

    assert_eq!(tree.prove(&[]), Err(BindingRootV2Error::TooManyOpenings));
    assert_eq!(
        tree.prove(&[1, 1]),
        Err(BindingRootV2Error::IndicesNotStrictlyIncreasing)
    );
    assert_eq!(tree.prove(&[4]), Err(BindingRootV2Error::IndexOutOfRange));
}

#[test]
fn parser_is_exact_bounded_and_validates_before_allocation() {
    let (_, tree) = four_leaf_fixture();
    let encoded = tree.prove(&[1, 3]).unwrap().encode().unwrap();

    for truncated_length in [0, 1, 27, encoded.len() - 1] {
        assert_eq!(
            BindingMerkleMultiProofV2::decode(&encoded[..truncated_length]),
            Err(BindingRootV2Error::ProofLength)
        );
    }
    let mut extended = encoded.clone();
    extended.push(0);
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&extended),
        Err(BindingRootV2Error::ProofLength)
    );

    let mut wrong_magic = encoded.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&wrong_magic),
        Err(BindingRootV2Error::ProofMagic)
    );
    let mut wrong_version = encoded.clone();
    wrong_version[9] ^= 1;
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&wrong_version),
        Err(BindingRootV2Error::ProofVersion)
    );
    let mut flags = encoded.clone();
    flags[11] = 1;
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&flags),
        Err(BindingRootV2Error::ProofFlags)
    );

    let mut empty_tree = encoded.clone();
    empty_tree[12..20].copy_from_slice(&0_u64.to_be_bytes());
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&empty_tree),
        Err(BindingRootV2Error::EmptyTree)
    );
    let mut non_power_of_two = encoded.clone();
    non_power_of_two[12..20].copy_from_slice(&3_u64.to_be_bytes());
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&non_power_of_two),
        Err(BindingRootV2Error::NonPowerOfTwo)
    );
    let mut too_many_leaves = encoded.clone();
    too_many_leaves[12..20].copy_from_slice(&(1_u64 << 33).to_be_bytes());
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&too_many_leaves),
        Err(BindingRootV2Error::TooManyLeaves)
    );

    // These malicious counts are rejected from the fixed 28-byte header,
    // before an exact-length check could justify allocating their vectors.
    let mut malicious_header = [0_u8; BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES];
    malicious_header[..8].copy_from_slice(BINDING_MERKLE_MULTIPROOF_V2_MAGIC);
    malicious_header[8..10].copy_from_slice(&BINDING_MERKLE_MULTIPROOF_V2_VERSION.to_be_bytes());
    malicious_header[12..20].copy_from_slice(&4_u64.to_be_bytes());
    malicious_header[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&malicious_header),
        Err(BindingRootV2Error::TooManyOpenings)
    );
    malicious_header[20..24].copy_from_slice(&1_u32.to_be_bytes());
    malicious_header[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&malicious_header),
        Err(BindingRootV2Error::TooManyFrontierDigests)
    );

    let mut wrong_frontier_count = encoded;
    wrong_frontier_count[24..28].copy_from_slice(&1_u32.to_be_bytes());
    wrong_frontier_count.truncate(wrong_frontier_count.len() - BINDING_V2_BYTES);
    assert_eq!(
        BindingMerkleMultiProofV2::decode(&wrong_frontier_count),
        Err(BindingRootV2Error::FrontierLength)
    );
}

#[test]
fn geometry_payload_position_and_node_level_are_enforced() {
    let empty: [&[u8]; 0] = [];
    assert_eq!(
        BindingMerkleTreeV2::from_payloads(&empty),
        Err(BindingRootV2Error::EmptyTree)
    );
    let non_power: [&[u8]; 3] = [b"a", b"b", b"c"];
    assert_eq!(
        BindingMerkleTreeV2::from_payloads(&non_power),
        Err(BindingRootV2Error::NonPowerOfTwo)
    );

    let (payloads, tree) = four_leaf_fixture();
    let proof = tree.prove(&[1, 3]).unwrap();
    assert_eq!(
        proof.verify_payloads(&[payloads[3], payloads[1]], &tree.root()),
        Err(BindingRootV2Error::RootMismatch)
    );
    assert_eq!(
        proof.verify_payloads(&[payloads[1]], &tree.root()),
        Err(BindingRootV2Error::PayloadCount)
    );

    let digest = BindingDigestV2::hash(BindingRoleV2::Payload, b"node").unwrap();
    assert_eq!(
        BindingMerkleNodeV2::hash(0, 0, digest, digest),
        Err(BindingRootV2Error::InvalidNodeLevel)
    );
}

#[test]
fn single_leaf_proof_is_canonical_and_has_no_frontier() {
    let payloads: [&[u8]; 1] = [b"only"];
    let tree = BindingMerkleTreeV2::from_payloads(&payloads).unwrap();
    let expected_root = decode_hex::<128>(concat!(
        "3026eefb04563fc704f621dc15c30229039cf9e6139a1b3cbdec51482be49eea",
        "c5ad8f9cefa429c3d9117a4b680a60053af042ee0f4388af7bbf05e04f45f8b",
        "a722494d06ae47191556b402d6bf911e358721e236cd0da4698ab39fa0063984",
        "a9f06daeb73f7dab01fd68296f1cf3c170521bb35ae5602281ed979e64c1f9fc6"
    ));
    assert_eq!(tree.root().to_bytes(), expected_root);
    let proof = tree.prove(&[0]).unwrap();
    assert!(proof.frontier_digests().is_empty());
    assert_eq!(
        proof.encode().unwrap().len(),
        BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES + 8
    );
    let decoded = BindingMerkleMultiProofV2::decode(&proof.encode().unwrap()).unwrap();
    decoded.verify_payloads(&payloads, &tree.root()).unwrap();
}

#[test]
fn every_nonempty_subset_of_eight_roundtrips_canonically() {
    let payloads: [&[u8]; 8] = [
        b"zero", b"one", b"two", b"three", b"four", b"five", b"six", b"seven",
    ];
    let tree = BindingMerkleTreeV2::from_payloads(&payloads).unwrap();
    for selection_mask in 1_u16..(1_u16 << payloads.len()) {
        let indices = (0..payloads.len())
            .filter(|index| selection_mask & (1_u16 << index) != 0)
            .map(|index| u64::try_from(index).unwrap())
            .collect::<Vec<_>>();
        let opened = indices
            .iter()
            .map(|&index| payloads[usize::try_from(index).unwrap()])
            .collect::<Vec<_>>();
        let proof = tree.prove(&indices).unwrap();
        let encoded = proof.encode().unwrap();
        let decoded = BindingMerkleMultiProofV2::decode(&encoded).unwrap();
        assert_eq!(decoded, proof);
        decoded.verify_payloads(&opened, &tree.root()).unwrap();
    }
}

#[test]
fn legacy_sixty_four_byte_roots_cannot_enter_v2_types() {
    let legacy_root = [0x5a_u8; 64];
    assert_eq!(
        BindingDigestV2::decode(&legacy_root),
        Err(BindingRootV2Error::DigestLength)
    );
    assert_eq!(
        BindingMerkleLeafV2::decode(&legacy_root),
        Err(BindingRootV2Error::DigestLength)
    );
    assert_eq!(
        BindingRootV2::decode(&legacy_root),
        Err(BindingRootV2Error::DigestLength)
    );
    assert_eq!(
        BindingRootV2::decode(&[0_u8; BINDING_V2_BYTES - 1]),
        Err(BindingRootV2Error::DigestLength)
    );
    assert_eq!(
        BindingRootV2::decode(&[0_u8; BINDING_V2_BYTES + 1]),
        Err(BindingRootV2Error::DigestLength)
    );

    assert_eq!(size_of::<BindingDigestV2>(), BINDING_V2_BYTES);
    assert_eq!(size_of::<BindingMerkleLeafV2>(), BINDING_V2_BYTES);
    assert_eq!(size_of::<BindingMerkleNodeV2>(), BINDING_V2_BYTES);
    assert_eq!(size_of::<BindingRootV2>(), BINDING_V2_BYTES);
}
