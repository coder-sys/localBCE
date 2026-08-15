use bl_pq512_crypto_core::{
    binding_root_v2::{BindingDigestV2, BindingMerkleTreeV2, BindingRoleV2, BindingRootV2},
    field::Fp16,
    h4_proof_package_v2::{
        H4_ANSWER_COEFFICIENT_BYTES, H4_BLSQAB03_BYTES, H4_GLOBAL_FRAME_V2_MAX_BYTES,
        H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES, H4_KIND801_MAX_SHARD_MESSAGE_BYTES,
        H4_PROOF_PACKAGE_V2_ACCEPTING, H4_PROOF_PACKAGE_V2_BYTES, H4_PROOF_PACKAGE_V2_HEADER_BYTES,
        H4_PROOF_PACKAGE_V2_MAGIC, H4_PROOF_PACKAGE_V2_VERSION, H4_RS_SEGMENT_V2_HEADER_BYTES,
        H4AggregatePackageV2WriteInput, H4ProofPackageV2Error, H4ProofProfileV2,
        H4RsSegmentDescriptorV2, encode_h4_global_round_frame_v2,
        h4_aggregate_package_v2_max_bytes, h4_public_view_v2_max_bytes,
        h4_rs_multiproof_v2_max_bytes, h4_rs_segment_leaf_payload_v2,
        h4_shard_compact_core_v2_max_bytes, h4_strict_pq_schedule_v2, max_canonical_frontier_nodes,
        parse_h4_aggregate_header_v2, parse_h4_global_round_frame_v2, parse_h4_shard_header_v2,
        verify_h4_rs_segment_v2, write_h4_aggregate_package_v2,
    },
    strict_pq_public_coin_v2::{
        STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2, StrictPqFp16PolicyV2, StrictPqRoundDescriptorV2,
    },
};

fn binding(byte: u8) -> BindingDigestV2 {
    BindingDigestV2::hash(BindingRoleV2::Payload, &[byte]).unwrap()
}

fn aggregate_header(profile: H4ProofProfileV2) -> [u8; 768] {
    let mut encoded = [0_u8; 768];
    encoded[..8].copy_from_slice(b"BLH4AG02");
    encoded[8..10].copy_from_slice(&2_u16.to_be_bytes());
    encoded[10] = profile.code();
    encoded[11] = profile.shard_count();
    encoded[12..14].copy_from_slice(&1_u16.to_be_bytes());
    let strict = STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2;
    let raw = H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES;
    encoded[16..24].copy_from_slice(&(strict as u64).to_be_bytes());
    encoded[24..32].copy_from_slice(&(raw as u64).to_be_bytes());
    encoded[32..40].copy_from_slice(&(H4_PROOF_PACKAGE_V2_BYTES as u64).to_be_bytes());
    let total = 768 + strict + raw + profile.shard_count() as usize * H4_PROOF_PACKAGE_V2_BYTES;
    encoded[40..48].copy_from_slice(&(total as u64).to_be_bytes());
    encoded[48..52].copy_from_slice(&profile.transcript_rounds().to_be_bytes());
    encoded[52..54].copy_from_slice(&2_u16.to_be_bytes());
    for (index, range) in [
        (1_u8, 128..192),
        (2, 192..256),
        (3, 256..320),
        (4, 320..384),
    ] {
        encoded[range].fill(index);
    }
    encoded[384..512].copy_from_slice(binding(5).as_bytes());
    encoded[512..640].copy_from_slice(binding(6).as_bytes());
    encoded[640..768].copy_from_slice(binding(7).as_bytes());
    encoded
}

fn shard_header(
    profile: H4ProofProfileV2,
    source: BindingRootV2,
    mask: BindingRootV2,
    bridge_base: BindingRootV2,
) -> [u8; H4_PROOF_PACKAGE_V2_HEADER_BYTES] {
    let mut encoded = [0_u8; H4_PROOF_PACKAGE_V2_HEADER_BYTES];
    encoded[..8].copy_from_slice(H4_PROOF_PACKAGE_V2_MAGIC);
    encoded[8..10].copy_from_slice(&H4_PROOF_PACKAGE_V2_VERSION.to_be_bytes());
    encoded[10] = profile.code();
    encoded[11] = 0;
    encoded[12] = profile.shard_count();
    let public_view = h4_public_view_v2_max_bytes(profile);
    let compact = H4_PROOF_PACKAGE_V2_HEADER_BYTES
        + public_view
        + H4_ANSWER_COEFFICIENT_BYTES
        + H4_BLSQAB03_BYTES;
    encoded[16..24].copy_from_slice(&(compact as u64).to_be_bytes());
    encoded[32..40].copy_from_slice(&(public_view as u64).to_be_bytes());
    encoded[40..48].copy_from_slice(&(H4_ANSWER_COEFFICIENT_BYTES as u64).to_be_bytes());
    encoded[48..52].copy_from_slice(&(H4_BLSQAB03_BYTES as u32).to_be_bytes());
    encoded[52..54].copy_from_slice(&1_u16.to_be_bytes());
    encoded[128..192].fill(1);
    encoded[192..256].fill(2);
    encoded[256..320].fill(3);
    encoded[320..384].fill(4);
    encoded[384..512].copy_from_slice(source.as_bytes());
    encoded[512..640].copy_from_slice(mask.as_bytes());
    encoded[640..768].copy_from_slice(bridge_base.as_bytes());
    encoded
}

fn segment_fixture() -> (H4RsSegmentDescriptorV2, Vec<u32>, BindingRootV2, Vec<u8>) {
    let descriptor = H4RsSegmentDescriptorV2 {
        boundary: 2,
        kind: 67,
        data_bytes: 8 * 64,
        leaf_count: 8,
        leaf_bytes: 64,
    };
    let payloads = (0_u32..8)
        .map(|value| {
            Fp16::from_m31(bl_pq512_crypto_core::field::M31::from_canonical(value).unwrap())
                .encode()
        })
        .collect::<Vec<_>>();
    let framed = payloads
        .iter()
        .map(|payload| h4_rs_segment_leaf_payload_v2(descriptor, payload).unwrap())
        .collect::<Vec<_>>();
    let tree = BindingMerkleTreeV2::from_payloads(&framed).unwrap();
    let indices = vec![1_u32, 3, 6];
    let proof = tree
        .prove(
            &indices
                .iter()
                .map(|&value| u64::from(value))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&descriptor.boundary.to_be_bytes());
    encoded.extend_from_slice(&descriptor.kind.to_be_bytes());
    encoded.extend_from_slice(&descriptor.data_bytes.to_be_bytes());
    encoded.extend_from_slice(&descriptor.leaf_count.to_be_bytes());
    encoded.extend_from_slice(&descriptor.leaf_bytes.to_be_bytes());
    encoded.extend_from_slice(&(indices.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(proof.frontier_digests().len() as u32).to_be_bytes());
    encoded.extend_from_slice(tree.root().as_bytes());
    for index in &indices {
        encoded.extend_from_slice(&index.to_be_bytes());
    }
    for &index in &indices {
        encoded.extend_from_slice(&payloads[index as usize]);
    }
    for digest in proof.frontier_digests() {
        encoded.extend_from_slice(digest.as_bytes());
    }
    (descriptor, indices, tree.root(), encoded)
}

#[test]
fn exact_v2_geometry_and_cap_arithmetic() {
    assert!(H4_PROOF_PACKAGE_V2_ACCEPTING);
    assert_eq!(max_canonical_frontier_nodes(1 << 17, 1_600), Some(10_048));
    assert_eq!(max_canonical_frontier_nodes(1 << 13, 1_218), Some(3_266));
    assert_eq!(max_canonical_frontier_nodes(1 << 20, 1_218), Some(11_792));
    assert_eq!(
        h4_rs_multiproof_v2_max_bytes(H4ProofProfileV2::K128),
        60_706_700
    );
    assert_eq!(
        h4_rs_multiproof_v2_max_bytes(H4ProofProfileV2::K512),
        60_706_700
    );
    assert_eq!(
        h4_shard_compact_core_v2_max_bytes(H4ProofProfileV2::K128),
        181_049_628
    );
    assert_eq!(
        h4_shard_compact_core_v2_max_bytes(H4ProofProfileV2::K512),
        181_049_628
    );
    assert_eq!(
        H4_PROOF_PACKAGE_V2_BYTES - h4_shard_compact_core_v2_max_bytes(H4ProofProfileV2::K128),
        20_276_964
    );
    assert_eq!(
        H4_PROOF_PACKAGE_V2_BYTES - h4_shard_compact_core_v2_max_bytes(H4ProofProfileV2::K512),
        20_276_964
    );
    assert_eq!(
        h4_aggregate_package_v2_max_bytes(H4ProofProfileV2::K128),
        221_413_264
    );
    assert_eq!(
        h4_aggregate_package_v2_max_bytes(H4ProofProfileV2::K512),
        825_393_040
    );
}

#[test]
fn exact_global_schedule_ordinals_policies_and_frame_cap() {
    for (profile, expected_rounds, expected_nonzero, expected_uniform) in [
        (H4ProofProfileV2::K128, 6_791_usize, 379_usize, 6_351_usize),
        (H4ProofProfileV2::K512, 7_059, 403, 6_595),
    ] {
        let (descriptors, policies) = h4_strict_pq_schedule_v2(profile).unwrap();
        assert_eq!(descriptors.len(), expected_rounds);
        assert_eq!(policies.len(), expected_rounds);
        assert!(
            descriptors
                .iter()
                .enumerate()
                .all(|(ordinal, descriptor)| descriptor.ordinal() == ordinal as u32)
        );
        assert_eq!(
            policies
                .iter()
                .filter(|policy| **policy == StrictPqFp16PolicyV2::Nonzero)
                .count(),
            expected_nonzero
        );
        assert_eq!(
            policies
                .iter()
                .filter(|policy| **policy == StrictPqFp16PolicyV2::NonzeroNonone)
                .count(),
            61
        );
        assert_eq!(
            policies
                .iter()
                .filter(|policy| **policy == StrictPqFp16PolicyV2::Uniform)
                .count(),
            expected_uniform
        );
        let tail = descriptors
            .iter()
            .rev()
            .take(13)
            .map(|descriptor| descriptor.kind())
            .collect::<Vec<_>>();
        assert_eq!(
            tail,
            [
                803, 802, 801, 801, 801, 801, 801, 801, 801, 801, 801, 800, 799
            ]
        );
    }

    let exact_k512_kind801_frame = 16 + 4 * (5 + H4_KIND801_MAX_SHARD_MESSAGE_BYTES);
    assert_eq!(exact_k512_kind801_frame, 524_388);
    assert!(exact_k512_kind801_frame <= H4_GLOBAL_FRAME_V2_MAX_BYTES);
}

#[test]
fn global_frame_is_canonical_and_rejects_reorder_length_kind_and_trailing() {
    let descriptor = StrictPqRoundDescriptorV2::new(801, 6_700, 1).unwrap();
    let messages = [b"shard-0".as_slice(), b"shard-1", b"shard-2", b"shard-3"];
    let encoded =
        encode_h4_global_round_frame_v2(H4ProofProfileV2::K512, descriptor, &messages).unwrap();
    let parsed =
        parse_h4_global_round_frame_v2(&encoded, H4ProofProfileV2::K512, descriptor).unwrap();
    assert_eq!(parsed.shard_messages(), messages);

    let mut reordered = encoded.clone();
    reordered[16] = 1;
    assert_eq!(
        parse_h4_global_round_frame_v2(&reordered, H4ProofProfileV2::K512, descriptor),
        Err(H4ProofPackageV2Error::GlobalFrame)
    );

    let mut wrong_length = encoded.clone();
    wrong_length[17..21].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        parse_h4_global_round_frame_v2(&wrong_length, H4ProofProfileV2::K512, descriptor),
        Err(H4ProofPackageV2Error::GlobalFrame)
    );

    let wrong_kind = StrictPqRoundDescriptorV2::new(802, 6_700, 1).unwrap();
    assert_eq!(
        parse_h4_global_round_frame_v2(&encoded, H4ProofProfileV2::K512, wrong_kind),
        Err(H4ProofPackageV2Error::GlobalFrame)
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        parse_h4_global_round_frame_v2(&trailing, H4ProofProfileV2::K512, descriptor),
        Err(H4ProofPackageV2Error::GlobalFrame)
    );
}

#[test]
fn aggregate_and_shard_headers_are_exact_and_reject_legacy_widths() {
    for profile in [H4ProofProfileV2::K128, H4ProofProfileV2::K512] {
        let aggregate = aggregate_header(profile);
        let parsed = parse_h4_aggregate_header_v2(&aggregate).unwrap();
        assert_eq!(parsed.profile, profile);
        assert_eq!(
            parsed.aggregate_bytes,
            h4_aggregate_package_v2_max_bytes(profile)
        );

        let framed = (0..8)
            .map(|index| {
                h4_rs_segment_leaf_payload_v2(
                    H4RsSegmentDescriptorV2 {
                        boundary: 2,
                        kind: 67,
                        data_bytes: 512,
                        leaf_count: 8,
                        leaf_bytes: 64,
                    },
                    &Fp16::from_m31(
                        bl_pq512_crypto_core::field::M31::from_canonical(index).unwrap(),
                    )
                    .encode(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mask = BindingMerkleTreeV2::from_payloads(&framed).unwrap().root();
        let shard = shard_header(
            profile,
            BindingRootV2::decode(binding(9).as_bytes()).unwrap(),
            mask,
            BindingRootV2::decode(binding(10).as_bytes()).unwrap(),
        );
        let parsed = parse_h4_shard_header_v2(&shard).unwrap();
        assert_eq!(parsed.profile, profile);
        assert_eq!(parsed.gkr_mask_tensor_root, mask);

        assert_eq!(
            parse_h4_shard_header_v2(&shard[..576]),
            Err(H4ProofPackageV2Error::Length)
        );
        let mut old_root_shape = shard;
        old_root_shape[704..768].fill(0);
        assert_eq!(
            parse_h4_shard_header_v2(&old_root_shape),
            Err(H4ProofPackageV2Error::LegacyRootWidth)
        );
    }
}

#[test]
fn aggregate_writer_rejects_invalid_input_before_emitting_bytes() {
    let shard_bodies: [&[u8]; 1] = [&[]];
    let input = H4AggregatePackageV2WriteInput {
        profile: H4ProofProfileV2::K128,
        attempt: 0,
        profile_identity: [1_u8; 64],
        program_commitment: [2_u8; 64],
        schedule_commitment: [3_u8; 64],
        session_id: [4_u8; 64],
        governed_key_binding: binding(11),
        statement_binding: binding(12),
        state_relation_source_binding: binding(13),
        strict_bundle: &[0_u8],
        raw_frames: &[0_u8],
        shard_bodies: &shard_bodies,
    };
    let mut output = Vec::new();
    assert!(write_h4_aggregate_package_v2(&mut output, &input).is_err());
    assert!(output.is_empty());
}

#[test]
fn aggregate_writer_rejects_wrong_shard_arity_before_decoding_bundle() {
    let shard_bodies: [&[u8]; 0] = [];
    let input = H4AggregatePackageV2WriteInput {
        profile: H4ProofProfileV2::K128,
        attempt: 0,
        profile_identity: [1_u8; 64],
        program_commitment: [2_u8; 64],
        schedule_commitment: [3_u8; 64],
        session_id: [4_u8; 64],
        governed_key_binding: binding(14),
        statement_binding: binding(15),
        state_relation_source_binding: binding(16),
        strict_bundle: &[0_u8],
        raw_frames: &[0_u8],
        shard_bodies: &shard_bodies,
    };
    let mut output = Vec::new();
    assert!(write_h4_aggregate_package_v2(&mut output, &input).is_err());
    assert!(output.is_empty());
}

#[test]
fn native_segment_roundtrip_and_both_lane_mutations() {
    let (descriptor, indices, root, encoded) = segment_fixture();
    let parsed = verify_h4_rs_segment_v2(&encoded, descriptor, &indices, root).unwrap();
    assert_eq!(parsed.descriptor, descriptor);
    assert_eq!(parsed.opened_payloads.len(), indices.len() * 64);

    for lane in [0, 64] {
        let mut root_mutation = encoded.clone();
        root_mutation[48 + lane] ^= 1;
        assert!(matches!(
            verify_h4_rs_segment_v2(&root_mutation, descriptor, &indices, root),
            Err(H4ProofPackageV2Error::RootMismatch) | Err(H4ProofPackageV2Error::Binding(_))
        ));

        let mut frontier_mutation = encoded.clone();
        let frontier = H4_RS_SEGMENT_V2_HEADER_BYTES + indices.len() * 4 + indices.len() * 64;
        frontier_mutation[frontier + lane] ^= 1;
        assert!(matches!(
            verify_h4_rs_segment_v2(&frontier_mutation, descriptor, &indices, root),
            Err(H4ProofPackageV2Error::RootMismatch)
        ));
    }
}

#[test]
fn segment_rejects_leaf_index_noncanonical_field_and_trailing_mutations() {
    let (descriptor, indices, root, encoded) = segment_fixture();
    let mut index = encoded.clone();
    index[H4_RS_SEGMENT_V2_HEADER_BYTES..H4_RS_SEGMENT_V2_HEADER_BYTES + 4]
        .copy_from_slice(&3_u32.to_be_bytes());
    assert!(verify_h4_rs_segment_v2(&index, descriptor, &indices, root).is_err());

    let mut leaf = encoded.clone();
    let leaf_start = H4_RS_SEGMENT_V2_HEADER_BYTES + indices.len() * 4;
    leaf[leaf_start] ^= 1;
    assert!(matches!(
        verify_h4_rs_segment_v2(&leaf, descriptor, &indices, root),
        Err(H4ProofPackageV2Error::RootMismatch)
    ));

    let mut noncanonical = encoded.clone();
    noncanonical[leaf_start..leaf_start + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        verify_h4_rs_segment_v2(&noncanonical, descriptor, &indices, root),
        Err(H4ProofPackageV2Error::NonCanonicalField)
    ));

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        verify_h4_rs_segment_v2(&trailing, descriptor, &indices, root),
        Err(H4ProofPackageV2Error::Length)
    );
}
