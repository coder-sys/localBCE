//! Standalone fail-closed parser for the nonactivating v3 composite envelope.

use std::convert::Infallible;
use std::env;
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::ExitCode;

use bl_pq512_crypto_core::h4_verification_key_v2::{
    H4_VERIFICATION_KEY_V2_BYTES, decode_h4_verification_key_v2,
};
use bl_pq512_crypto_core::strict_pq_public_coin_v2::StrictPqRootUseRegistryV2;
use bl_pq512_crypto_core::v3_component_preflight::{
    verify_composite_transcript_component, verify_h4_component_from_v3_envelope,
    verify_typed_state_component_from_v3_envelope,
};
use bl_pq512_crypto_core::v3_composite_envelope::{
    V3_LAYOUT_BYTES, V3_STATUS, V3ProfileLayout, governed_profile_label, parse_v3_envelope,
};

fn hex(encoded: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(encoded.len() * 2);
    for byte in encoded {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn run() -> Result<Infallible, String> {
    let mut args = env::args_os();
    let _program = args.next();
    let trusted_layout = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: v3_composite_verify <trusted-layout> <envelope>".to_owned())?;
    let envelope = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: v3_composite_verify <trusted-layout> <envelope>".to_owned())?;
    let h4_key = args.next().map(PathBuf::from);
    if args.next().is_some() {
        return Err(
            "usage: v3_composite_verify <trusted-layout> <envelope> [h4-verification-key]"
                .to_owned(),
        );
    }
    let layout_metadata = fs::metadata(&trusted_layout)
        .map_err(|error| format!("trusted_layout_metadata:{:?}", error.kind()))?;
    if !layout_metadata.is_file()
        || layout_metadata.len() != u64::try_from(V3_LAYOUT_BYTES).map_err(|_| "layout_size")?
    {
        return Err("trusted_layout_shape".to_owned());
    }
    let layout_bytes = fs::read(&trusted_layout)
        .map_err(|error| format!("trusted_layout_read:{:?}", error.kind()))?;
    let layout = V3ProfileLayout::decode_trusted(&layout_bytes)
        .map_err(|error| format!("trusted_layout_invalid:{error:?}"))?;
    let mut envelope_file =
        File::open(&envelope).map_err(|error| format!("envelope_open:{:?}", error.kind()))?;
    let parsed = parse_v3_envelope(&mut envelope_file, &layout)
        .map_err(|error| format!("envelope_invalid:{error:?}"))?;
    let transcript_replay =
        verify_composite_transcript_component(&mut envelope_file, &layout, &parsed)
            .map_err(|error| format!("composite_transcript_invalid:{error:?}"))?;
    let typed_state =
        verify_typed_state_component_from_v3_envelope(&mut envelope_file, &layout, &parsed)
            .map_err(|error| format!("typed_state_component_invalid:{error:?}"))?;
    let h4_pre_alpha = if let Some(path) = h4_key {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("h4_verification_key_metadata:{:?}", error.kind()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len()
                != u64::try_from(H4_VERIFICATION_KEY_V2_BYTES)
                    .map_err(|_| "h4_verification_key_size")?
        {
            return Err("h4_verification_key_shape".to_owned());
        }
        let encoded = fs::read(&path)
            .map_err(|error| format!("h4_verification_key_read:{:?}", error.kind()))?;
        let after = fs::symlink_metadata(&path)
            .map_err(|error| format!("h4_verification_key_metadata_after:{:?}", error.kind()))?;
        if after.len() != metadata.len() || after.file_type().is_symlink() {
            return Err("h4_verification_key_changed_during_read".to_owned());
        }
        let key = decode_h4_verification_key_v2(&encoded)
            .map_err(|error| format!("h4_verification_key_invalid:{error:?}"))?;
        let mut registry = StrictPqRootUseRegistryV2::new();
        Some(
            verify_h4_component_from_v3_envelope(
                &mut envelope_file,
                &layout,
                &parsed,
                &key,
                &mut registry,
            )
            .map_err(|error| format!("h4_pre_alpha_invalid:{error:?}"))?,
        )
    } else {
        None
    };
    let profile_label = governed_profile_label(parsed.profile_code)
        .map_err(|error| format!("trusted_profile_invalid:{error:?}"))?;
    let profile_label = std::str::from_utf8(profile_label)
        .map_err(|_| "trusted_profile_label_invalid".to_owned())?;
    let h4_evidence = h4_pre_alpha.as_ref().map_or_else(
        || "h4_pre_alpha_binding=none h4_final_transcript_root=none".to_owned(),
        |receipt| {
            format!(
                "h4_pre_alpha_binding={} h4_final_transcript_root={}",
                hex(receipt.aggregate_binding().as_bytes()),
                hex(receipt.final_transcript_root()),
            )
        },
    );
    println!(
        "ERR status={} profile_code={} profile_label={} envelope_commitment={} semantic_verifier=UNAVAILABLE h4_pre_alpha_verifier={} {} h4_complete_verifier=UNAVAILABLE composite_transcript_replay=ACCEPTED_UNQUALIFIED composite_transcript_round_900_root={} composite_transcript_round_901_root={} composite_transcript_final_root={} typed_state_verifier=ACCEPTED typed_state_receipt_binding={} aggregate=AGGREGATE_UNQUALIFIED production_usable=false activation_allowed=false",
        V3_STATUS,
        parsed.profile_code,
        profile_label,
        hex(&parsed.envelope_commitment),
        if h4_pre_alpha.is_some() {
            "ACCEPTED_UNQUALIFIED"
        } else {
            "NOT_REQUESTED"
        },
        h4_evidence,
        hex(transcript_replay.round_900_transcript_root()),
        hex(transcript_replay.round_901_transcript_root()),
        hex(transcript_replay.final_transcript_root()),
        hex(typed_state.receipt_binding().as_bytes()),
    );
    Err("aggregate_verification_unavailable".to_owned())
}

fn main() -> ExitCode {
    let arguments = env::args_os().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[1] == "--capabilities" {
        println!("status={V3_STATUS}");
        println!("typed_state_component_verification=available");
        println!("h4_pre_alpha_verification=available");
        println!("h4_complete_verification=unavailable");
        println!("composite_transcript_replay=available_unqualified");
        println!("aggregate_verification=unavailable");
        println!("production_usable=false");
        println!("activation_allowed=false");
        return ExitCode::SUCCESS;
    }
    match run() {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("ERR {error}");
            ExitCode::from(3)
        }
    }
}
