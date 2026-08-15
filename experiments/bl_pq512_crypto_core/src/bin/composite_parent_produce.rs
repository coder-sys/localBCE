//! Produce the authenticated parent 900/901/902 public-coin bundle.
//!
//! This command owns only the chained parent transcript. It does not create a
//! post-z bridge proof, a decisive-composition receipt, or an activation claim.

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

const USAGE: &str = "usage: composite_parent_produce <chained-public-coin-service> <pre-alpha> <quotient-template> <final-template> <output>";

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
    if before.len() != after.len() || bytes.len() != expected {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(bytes)
}

fn run(args: &[OsString]) -> Result<(), String> {
    if args.len() != 6 {
        return Err(USAGE.to_owned());
    }
    let service = absolute_regular_file(&args[1], "service")?;
    let pre_alpha_path = absolute_regular_file(&args[2], "pre_alpha")?;
    let quotient_path = absolute_regular_file(&args[3], "quotient_template")?;
    let final_path = absolute_regular_file(&args[4], "final_template")?;
    let output = PathBuf::from(&args[5]);
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
    let encoded = produce_composite_parent_bundle(&service, &pre_alpha, &quotient, &final_message)
        .map_err(|error| format!("produce:{error:?}"))?;

    let parent = output.parent().ok_or_else(|| "output_parent".to_owned())?;
    if !parent.is_dir() {
        return Err("output_parent_not_directory".to_owned());
    }
    let partial_path = PathBuf::from(format!("{}.partial", output.display()));
    if partial_path.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut partial = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial_path)
    {
        Ok(file) => file,
        Err(error) => return Err(format!("partial_output_open:{:?}", error.kind())),
    };
    if let Err(error) = partial.write_all(&encoded).and_then(|_| partial.sync_all()) {
        drop(partial);
        let _ = fs::remove_file(&partial_path);
        return Err(format!("partial_output_write:{:?}", error.kind()));
    }
    drop(partial);
    if output.exists() {
        let _ = fs::remove_file(&partial_path);
        return Err("output_created_during_production".to_owned());
    }
    if let Err(error) = fs::rename(&partial_path, &output) {
        let _ = fs::remove_file(&partial_path);
        return Err(format!("output_publish:{:?}", error.kind()));
    }
    println!("status=PARENT_900_901_902_PRODUCED_UNQUALIFIED");
    println!("round_count=3");
    println!("bundle_bytes={}", encoded.len());
    println!("post_z_verification=unavailable");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=PARENT_CHAIN_PRODUCER_AVAILABLE");
        println!("parent_chain_production=true");
        println!("post_z_completion_verification=false");
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
