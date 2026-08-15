extern crate alloc;

#[allow(dead_code)]
#[path = "../src/v3_composite_envelope.rs"]
mod v3_composite_envelope;

use std::io::Cursor;

use v3_composite_envelope::{
    K128_PROFILE_CODE, K512_PROFILE_CODE, V3_ABSOLUTE_MAX_BYTES, V3_DESCRIPTOR_BYTES,
    V3_ENVELOPE_COMMITMENT_DOMAIN, V3_HEADER_BYTES, V3_LAYOUT_BYTES, V3_STATUS, V3ComponentKind,
    V3ComponentLayout, V3EnvelopeError, V3ProfileLayout, build_composite_transcript_slot,
    encode_v3_envelope, parse_v3_envelope, verify_v3_composite,
};

const DESCRIPTOR_START: usize = 1_348;
const SIDECAR_START: usize = 600;

fn wide(value: u8) -> [u8; 64] {
    [value; 64]
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn make_layout(profile: [u8; 64], candidate: [u8; 64]) -> V3ProfileLayout {
    make_layout_with_code(profile, K128_PROFILE_CODE, candidate)
}

fn make_layout_with_code(
    profile: [u8; 64],
    profile_code: u8,
    candidate: [u8; 64],
) -> V3ProfileLayout {
    let lengths = [31_u64, 37, 41, 64];
    let components = V3ComponentKind::ORDER.map(|kind| {
        let index = usize::from(kind as u16 - 1);
        V3ComponentLayout {
            kind,
            grammar: 1,
            exact_length: lengths[index],
            maximum_length: lengths[index],
            expected_program_commitment: wide(21 + kind as u8 - 1),
            expected_schedule_commitment: wide(31 + kind as u8 - 1),
        }
    });
    V3ProfileLayout::new(
        profile,
        profile_code,
        candidate,
        u64::try_from(V3_HEADER_BYTES).unwrap() + lengths.iter().sum::<u64>(),
        components,
    )
    .unwrap()
}

fn sidecar(profile: [u8; 64]) -> [u8; 744] {
    let mut encoded = [0_u8; 744];
    encoded[..8].copy_from_slice(b"BLPQSC01");
    encoded[8..10].copy_from_slice(&1_u16.to_be_bytes());
    encoded[10..12].copy_from_slice(&0_u16.to_be_bytes());
    encoded[12..16].copy_from_slice(&744_u32.to_be_bytes());
    encoded[16..80].copy_from_slice(&profile);
    for (ordinal, start) in [144, 208, 272].into_iter().enumerate() {
        encoded[start..start + 64].copy_from_slice(&wide(ordinal as u8 + 3));
    }
    encoded[336..344].copy_from_slice(&7_u64.to_be_bytes());
    encoded[344..352].copy_from_slice(&11_u64.to_be_bytes());
    encoded[352..360].copy_from_slice(&12_u64.to_be_bytes());
    for (ordinal, start) in [360, 424, 488, 552, 616, 680].into_iter().enumerate() {
        encoded[start..start + 64].copy_from_slice(&wide(ordinal as u8 + 6));
    }
    encoded
}

fn fixture() -> (V3ProfileLayout, Vec<u8>) {
    let layout = make_layout(wide(1), wide(2));
    let public_fields = core::array::from_fn(|index| [index as u8; 32]);
    let components = [
        vec![b'S'; 31],
        vec![b'H'; 37],
        vec![b'T'; 41],
        build_composite_transcript_slot(b"coin", 64).unwrap(),
    ];
    let encoded = encode_v3_envelope(
        &layout,
        &public_fields,
        &sidecar(layout.profile_id),
        &components,
    )
    .unwrap();
    (layout, encoded)
}

fn changed(encoded: &[u8], offset: usize, replacement: &[u8]) -> Vec<u8> {
    let mut result = encoded.to_vec();
    result[offset..offset + replacement.len()].copy_from_slice(replacement);
    result
}

#[test]
fn v3_layout_and_envelope_roundtrip_is_parse_only() {
    let (layout, encoded) = fixture();
    let layout_encoded = layout.encode().unwrap();
    assert_eq!(layout_encoded.len(), V3_LAYOUT_BYTES);
    assert_eq!(
        V3ProfileLayout::decode_trusted(&layout_encoded).unwrap(),
        layout
    );

    let parsed = parse_v3_envelope(&mut Cursor::new(&encoded), &layout).unwrap();
    assert_eq!(parsed.status, V3_STATUS);
    assert!(!parsed.production_usable);
    assert!(!parsed.activation_allowed);
    assert_eq!(parsed.profile_code, K128_PROFILE_CODE);
    assert_eq!(
        parsed.component_offsets,
        [
            V3_HEADER_BYTES as u64,
            V3_HEADER_BYTES as u64 + 31,
            V3_HEADER_BYTES as u64 + 31 + 37,
            V3_HEADER_BYTES as u64 + 31 + 37 + 41,
        ]
    );
    let mut expected = sha3::Sha3_512::new();
    use sha3::Digest;
    expected.update(V3_ENVELOPE_COMMITMENT_DOMAIN);
    expected.update((encoded.len() as u64).to_be_bytes());
    expected.update(&encoded);
    assert_eq!(
        parsed.envelope_commitment,
        <[u8; 64]>::from(expected.finalize())
    );
    assert_eq!(
        hex(&layout.layout_commitment),
        "2ed0dea51624551e878baf09b72785c20b249d4b52302ab2ad39958f6cbd12390cdeeecb2b533bcbaabde79a5c0cc36ba0f0969777c0a9e15c4985114319c3df"
    );
    assert_eq!(
        hex(&parsed.envelope_commitment),
        "099cd6e8489c7dc0274cb121c8f974cad13ceb6d083cac279c606da8f77d61c75216531a55aac015eef9058959bf3559d467110806c07ed0943685c86cdcb24c"
    );
    assert_eq!(
        verify_v3_composite(&mut Cursor::new(&encoded), &layout),
        Err(V3EnvelopeError::AggregateVerificationUnavailable)
    );
}

#[test]
fn v3_truncation_extension_version_flags_and_overflow_fail_closed() {
    let (layout, encoded) = fixture();
    assert_eq!(
        parse_v3_envelope(&mut Cursor::new(&encoded[..encoded.len() - 1]), &layout),
        Err(V3EnvelopeError::TotalLength)
    );
    let mut extended = encoded.clone();
    extended.push(0);
    assert_eq!(
        parse_v3_envelope(&mut Cursor::new(&extended), &layout),
        Err(V3EnvelopeError::TotalLength)
    );
    assert_eq!(
        parse_v3_envelope(
            &mut Cursor::new(changed(&encoded, 8, &2_u16.to_be_bytes())),
            &layout
        ),
        Err(V3EnvelopeError::Version)
    );
    assert_eq!(
        parse_v3_envelope(
            &mut Cursor::new(changed(&encoded, 10, &1_u16.to_be_bytes())),
            &layout
        ),
        Err(V3EnvelopeError::Flags)
    );
    assert_eq!(
        parse_v3_envelope(
            &mut Cursor::new(changed(&encoded, 16, &u64::MAX.to_be_bytes())),
            &layout
        ),
        Err(V3EnvelopeError::TotalLength)
    );
}

#[test]
fn v3_profile_candidate_layout_and_header_length_swaps_fail_closed() {
    let (layout, encoded) = fixture();
    for (offset, value, error) in [
        (
            12,
            1_651_u32.to_be_bytes().to_vec(),
            V3EnvelopeError::HeaderLength,
        ),
        (24, wide(90).to_vec(), V3EnvelopeError::Profile),
        (88, wide(91).to_vec(), V3EnvelopeError::CandidateDescriptor),
        (152, wide(92).to_vec(), V3EnvelopeError::Layout),
    ] {
        assert_eq!(
            parse_v3_envelope(&mut Cursor::new(changed(&encoded, offset, &value)), &layout),
            Err(error)
        );
    }
    assert_eq!(
        parse_v3_envelope(&mut Cursor::new(&encoded), &make_layout(wide(70), wide(2))),
        Err(V3EnvelopeError::Profile)
    );
    assert_eq!(
        parse_v3_envelope(&mut Cursor::new(&encoded), &make_layout(wide(1), wide(71))),
        Err(V3EnvelopeError::CandidateDescriptor)
    );
}

#[test]
fn v3_profile_code_is_trusted_and_not_inferred_from_the_opaque_profile_id() {
    let (layout, encoded) = fixture();
    let swapped = make_layout_with_code(layout.profile_id, K512_PROFILE_CODE, wide(2));
    assert_eq!(
        parse_v3_envelope(&mut Cursor::new(&encoded), &swapped),
        Err(V3EnvelopeError::Layout)
    );
    assert_eq!(
        V3ProfileLayout::new(
            layout.profile_id,
            2,
            layout.candidate_descriptor_identity,
            layout.maximum_total_length,
            layout.components,
        ),
        Err(V3EnvelopeError::Profile)
    );
}

#[test]
fn v3_descriptor_order_duplicate_unknown_grammar_and_length_fail_closed() {
    let (layout, encoded) = fixture();
    let second = DESCRIPTOR_START + V3_DESCRIPTOR_BYTES;
    for (offset, replacement, error) in [
        (
            DESCRIPTOR_START,
            2_u16.to_be_bytes().to_vec(),
            V3EnvelopeError::ComponentOrder,
        ),
        (
            second,
            1_u16.to_be_bytes().to_vec(),
            V3EnvelopeError::ComponentOrder,
        ),
        (
            second,
            99_u16.to_be_bytes().to_vec(),
            V3EnvelopeError::ComponentOrder,
        ),
        (
            DESCRIPTOR_START + 2,
            2_u16.to_be_bytes().to_vec(),
            V3EnvelopeError::ComponentGrammar,
        ),
        (
            DESCRIPTOR_START + 4,
            32_u64.to_be_bytes().to_vec(),
            V3EnvelopeError::ComponentLength,
        ),
    ] {
        assert_eq!(
            parse_v3_envelope(
                &mut Cursor::new(changed(&encoded, offset, &replacement)),
                &layout
            ),
            Err(error)
        );
    }
}

#[test]
fn v3_commitment_component_and_transcript_padding_mutations_fail_closed() {
    let (layout, encoded) = fixture();
    assert_eq!(
        parse_v3_envelope(
            &mut Cursor::new(changed(&encoded, DESCRIPTOR_START + 12, &wide(93))),
            &layout
        ),
        Err(V3EnvelopeError::ComponentDigest)
    );
    assert_eq!(
        parse_v3_envelope(
            &mut Cursor::new(changed(&encoded, V3_HEADER_BYTES + 5, b"X")),
            &layout
        ),
        Err(V3EnvelopeError::ComponentDigest)
    );
    let transcript_padding = V3_HEADER_BYTES + 31 + 37 + 41 + 20 + 4;
    assert_eq!(
        parse_v3_envelope(
            &mut Cursor::new(changed(&encoded, transcript_padding, &[1])),
            &layout
        ),
        Err(V3EnvelopeError::TranscriptPadding)
    );
}

#[test]
fn v3_global_suite_is_null_by_schema() {
    let (layout, encoded) = fixture();
    assert_eq!(
        parse_v3_envelope(
            &mut Cursor::new(changed(&encoded, SIDECAR_START + 80, &wide(72))),
            &layout
        ),
        Err(V3EnvelopeError::Sidecar)
    );
}

#[test]
fn v3_streaming_ceiling_can_hold_four_fixed_h4_shards() {
    let lengths = [
        84_u64 * 1024 * 1024,
        4 * (192_u64 * 1024 * 1024) + 16 * 1024 * 1024,
        84_u64 * 1024 * 1024,
        16_u64 * 1024 * 1024,
    ];
    let components = V3ComponentKind::ORDER.map(|kind| {
        let index = usize::from(kind as u16 - 1);
        V3ComponentLayout {
            kind,
            grammar: 1,
            exact_length: lengths[index],
            maximum_length: lengths[index],
            expected_program_commitment: wide(41 + kind as u8 - 1),
            expected_schedule_commitment: wide(51 + kind as u8 - 1),
        }
    });
    let total = V3_HEADER_BYTES as u64 + lengths.iter().sum::<u64>();
    let layout =
        V3ProfileLayout::new(wide(60), K512_PROFILE_CODE, wide(61), total, components).unwrap();
    assert!(layout.total_length > 512 * 1024 * 1024);
    assert!(layout.total_length < V3_ABSOLUTE_MAX_BYTES);
}
