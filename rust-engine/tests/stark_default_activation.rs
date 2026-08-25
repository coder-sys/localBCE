use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("localbce-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn base_config() -> Value {
    json!({
        "claims_registry_address": "0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e",
        "private_key": "NOT_USED_FOR_DENIED_MANUAL_ROLLBACK_TEST",
        "rpc_url": "http://127.0.0.1:8545",
        "transaction_value": "0.001ether"
    })
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).expect("write JSON fixture");
}

#[test]
fn explicit_stark_fails_before_claim_or_state_side_effects_without_activation_evidence() {
    let directory = temporary_directory("explicit-stark-fail-closed");
    let state_path = directory.join("state/nullifier_state.json");
    let artifact_path = directory.join("artifacts");
    let mut config = base_config();
    config["proof_backend"] = json!("stark_attested");
    config["stark_runtime_mode"] = json!("production");
    config["stark_release_profile_path"] = json!(directory.join("missing-release.json"));
    config["stark_deployment_pin_path"] = json!(directory.join("missing-pin.json"));
    config["stark_nullifier_state_path"] = json!(&state_path);
    config["stark_artifacts_directory"] = json!(&artifact_path);
    write_json(&directory.join("config.json"), &config);

    let output = Command::new(env!("CARGO_BIN_EXE_rust-engine"))
        .current_dir(&directory)
        .output()
        .expect("execute rust-engine");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not read STARK release profile")
    );
    for path in [
        directory.join("stark_bridge_input.json"),
        directory.join("adjudication_result.json"),
        directory.join("stark_adjudication_result.json"),
        state_path,
    ] {
        assert!(!path.exists(), "unexpected side effect: {}", path.display());
    }
    assert!(!artifact_path.exists());

    fs::remove_dir_all(directory).expect("remove temporary test directory");
}

#[test]
fn absent_backend_preserves_groth16_default() {
    let directory = temporary_directory("default-groth16");
    let config = base_config();
    write_json(&directory.join("config.json"), &config);

    let claim_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("claim_input.json");
    let mut claim: Value =
        serde_json::from_slice(&fs::read(claim_path).expect("read claim fixture")).unwrap();
    claim["claim_id"] = json!(format!("GROTH16-ROLLBACK-{}", std::process::id()));
    claim["eligibility_active"] = json!(0);
    write_json(&directory.join("claim_input.json"), &claim);

    let output = Command::new(env!("CARGO_BIN_EXE_rust-engine"))
        .current_dir(&directory)
        .output()
        .expect("execute rust-engine");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(
        &fs::read(directory.join("adjudication_result.json")).expect("read adjudication result"),
    )
    .unwrap();
    assert_eq!(result["status"], "DENIED");
    assert_eq!(result["tx_submitted"], false);
    assert!(!directory.join("stark_bridge_input.json").exists());

    fs::remove_dir_all(directory).expect("remove temporary test directory");
}
