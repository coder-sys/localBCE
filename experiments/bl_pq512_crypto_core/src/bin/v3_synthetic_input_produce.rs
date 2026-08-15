//! Produce one fixed-shape synthetic input for the nonactivating integration lane.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::v3_synthetic_major::{SyntheticProfile, synthetic_input_bytes};

const USAGE: &str =
    "usage: v3_synthetic_input_produce <K128_CALIBRATION|K512_CALIBRATION> <absolute-output>";

fn output_path(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("output_path_not_absolute".to_owned());
    }
    if path.exists() {
        return Err("output_exists".to_owned());
    }
    let parent = path.parent().ok_or_else(|| "output_parent".to_owned())?;
    if !parent.is_dir() {
        return Err("output_parent_not_directory".to_owned());
    }
    Ok(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let partial = PathBuf::from(format!("{}.partial", path.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&partial);
        return Err(format!("partial_output_write:{:?}", error.kind()));
    }
    drop(file);
    if path.exists() {
        let _ = fs::remove_file(&partial);
        return Err("output_created_during_production".to_owned());
    }
    fs::rename(&partial, path).map_err(|error| {
        let _ = fs::remove_file(&partial);
        format!("output_publish:{:?}", error.kind())
    })
}

fn run(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(USAGE.to_owned());
    }
    let profile = SyntheticProfile::from_label(&args[1]).map_err(|_| "profile_invalid")?;
    let output = output_path(&args[2])?;
    let input = synthetic_input_bytes(profile);
    write_new(&output, &input)?;
    println!("status=SYNTHETIC_INPUT_PRODUCED");
    println!("profile={}", profile.label());
    println!("record_count={}", profile.record_count());
    println!("input_bytes={}", input.len());
    println!("real_phi_or_payments=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=SYNTHETIC_INPUT_PRODUCER_AVAILABLE");
        println!("synthetic_only=true");
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
