//! Produce the fixed-shape v3 parent transcript component.
//!
//! The chained public-coin bundle is wrapped in the `BLV3TR01` component
//! grammar expected by the outer envelope.  This command owns transcript
//! production only.  It does not mint a post-Z receipt, complete the parent,
//! accept an aggregate, or activate a proof suite.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::composite_parent_public_coin::{
    COMPOSITE_PARENT_FINAL_BYTES, COMPOSITE_PARENT_PRE_ALPHA_BYTES,
    COMPOSITE_PARENT_QUOTIENT_BYTES, produce_composite_parent_bundle,
};
use bl_pq512_crypto_core::v3_composite_envelope::build_composite_transcript_slot;

const USAGE: &str = "usage: composite_parent_transcript_produce <chained-public-coin-service> <pre-alpha> <quotient-template> <final-template> <fixed-transcript-bytes> <output>";

fn absolute_regular_file(value: &OsString, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label}_not_regular"));
    }
    Ok(path)
}

fn read_exact(path: &Path, expected: usize, label: &str) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(format!("{label}_not_regular"));
    }
    if before.len() != u64::try_from(expected).map_err(|_| format!("{label}_size"))? {
        return Err(format!("{label}_length"));
    }
    let bytes = fs::read(path).map_err(|error| format!("{label}_read:{:?}", error.kind()))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("{label}_metadata_after:{:?}", error.kind()))?;
    if before.len() != after.len() || bytes.len() != expected || after.file_type().is_symlink() {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(bytes)
}

fn run(args: &[OsString]) -> Result<(), String> {
    if args.len() != 7 {
        return Err(USAGE.to_owned());
    }
    let service = absolute_regular_file(&args[1], "service")?;
    let pre_alpha_path = absolute_regular_file(&args[2], "pre_alpha")?;
    let quotient_path = absolute_regular_file(&args[3], "quotient_template")?;
    let final_path = absolute_regular_file(&args[4], "final_template")?;
    let fixed_length = args[5]
        .to_str()
        .ok_or_else(|| "fixed_transcript_bytes_utf8".to_owned())?
        .parse::<u64>()
        .map_err(|_| "fixed_transcript_bytes_invalid".to_owned())?;
    let output = PathBuf::from(&args[6]);
    if !output.is_absolute() {
        return Err("output_path_not_absolute".to_owned());
    }
    if output.exists() {
        return Err("output_exists".to_owned());
    }
    let pre_alpha = read_exact(
        &pre_alpha_path,
        COMPOSITE_PARENT_PRE_ALPHA_BYTES,
        "pre_alpha",
    )?;
    let quotient = read_exact(
        &quotient_path,
        COMPOSITE_PARENT_QUOTIENT_BYTES,
        "quotient_template",
    )?;
    let final_message = read_exact(&final_path, COMPOSITE_PARENT_FINAL_BYTES, "final_template")?;
    let bundle = produce_composite_parent_bundle(&service, &pre_alpha, &quotient, &final_message)
        .map_err(|error| format!("produce:{error:?}"))?;
    let transcript = build_composite_transcript_slot(&bundle, fixed_length)
        .map_err(|error| format!("transcript:{error:?}"))?;

    let parent = output.parent().ok_or_else(|| "output_parent".to_owned())?;
    if !parent.is_dir() {
        return Err("output_parent_not_directory".to_owned());
    }
    let partial = PathBuf::from(format!("{}.partial", output.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    if let Err(error) = file.write_all(&transcript).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&partial);
        return Err(format!("partial_output_write:{:?}", error.kind()));
    }
    drop(file);
    let readback = fs::read(&partial)
        .map_err(|error| format!("partial_output_readback:{:?}", error.kind()))?;
    if readback != transcript {
        let _ = fs::remove_file(&partial);
        return Err("partial_output_readback_mismatch".to_owned());
    }
    if output.exists() {
        let _ = fs::remove_file(&partial);
        return Err("output_created_during_production".to_owned());
    }
    if let Err(error) = fs::rename(&partial, &output) {
        let _ = fs::remove_file(&partial);
        return Err(format!("output_publish:{:?}", error.kind()));
    }
    println!("status=PARENT_TRANSCRIPT_PRODUCED_UNQUALIFIED");
    println!("round_count=3");
    println!("bundle_bytes={}", bundle.len());
    println!("transcript_bytes={}", transcript.len());
    println!("post_z_completion=false");
    println!("aggregate_verification=false");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=PARENT_TRANSCRIPT_PRODUCER_AVAILABLE");
        println!("parent_chain_production=true");
        println!("transcript_component_production=true");
        println!("post_z_completion=false");
        println!("aggregate_verification=false");
        println!("production_usable=false");
        println!("activation_allowed=false");
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERR {error}");
            ExitCode::from(2)
        }
    }
}
