use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct ClaimInput {
    claim_id: String,
    claim_amount: u64,

    eligibility_active: u8,
    aid_code: u64,
    benefit_level_exists: u8,

    date_of_service_from: u64,
    eligibility_period_from: u64,
    eligibility_period_thru: u64,

    soc_amount: u64,
    soc_met: u8,

    provider_enrolled: u8,
    provider_type_valid: u8,

    billing_code_valid: u8,
    units_valid: u8,

    is_duplicate: u8,
}

fn run(cmd: &str) {
    let status = Command::new("bash")
        .arg("-lc")
        .arg(cmd)
        .status()
        .expect("failed to run command");

    if !status.success() {
        panic!("command failed: {}", cmd);
    }
}

fn run_output(cmd: &str) -> String {
    let output = Command::new("bash")
        .arg("-lc")
        .arg(cmd)
        .output()
        .expect("failed to run command");

    if !output.status.success() {
        panic!("command failed: {}", cmd);
    }

    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn claim_hash_32(claim_id: &str, claim_amount: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(claim_id.as_bytes());
    hasher.update(claim_amount.to_be_bytes());

    format!("0x{}", hex::encode(hasher.finalize()))
}

fn split_calldata(calldata: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;

    for (i, ch) in calldata.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(calldata[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }

    parts.push(calldata[start..].trim().to_string());
    parts
}

fn main() {
let contract = "0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8";
    let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    let claim_json = fs::read_to_string("claim_input.json")
        .expect("could not read claim_input.json");

    let claim: ClaimInput = serde_json::from_str(&claim_json)
        .expect("invalid claim_input.json");

    let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

    println!("Claim ID: {}", claim.claim_id);
    println!("Claim Hash: {}", claim_hash);

   let zk_input = format!(
    r#"{{
  "eligibility_active": {},
  "aid_code": {},
  "benefit_level_exists": {},
  "date_of_service_from": {},
  "eligibility_period_from": {},
  "eligibility_period_thru": {},
  "soc_amount": {},
  "soc_met": {},
  "provider_enrolled": {},
  "provider_type_valid": {},
  "billing_code_valid": {},
  "units_valid": {},
  "is_duplicate": {}
}}"#,
    claim.eligibility_active,
    claim.aid_code,
    claim.benefit_level_exists,
    claim.date_of_service_from,
    claim.eligibility_period_from,
    claim.eligibility_period_thru,
    claim.soc_amount,
    claim.soc_met,
    claim.provider_enrolled,
    claim.provider_type_valid,
    claim.billing_code_valid,
    claim.units_valid,
    claim.is_duplicate
);
    fs::write("../zk/input.json", zk_input).unwrap();

    run("node ../zk/claim_js/generate_witness.js ../zk/claim_js/claim.wasm ../zk/input.json ../zk/witness.wtns");

    run("snarkjs groth16 prove ../zk/claim_final.zkey ../zk/witness.wtns ../zk/proof.json ../zk/public.json");

    let calldata = run_output("cd ../zk && snarkjs zkey export soliditycalldata public.json proof.json")
        .replace("\"", "")
        .replace(" ", "");

    let parts = split_calldata(&calldata);

    let a = &parts[0];
    let b = &parts[1];
    let c = &parts[2];
    let input = &parts[3];

    println!("Proof calldata parsed dynamically.");

    run(&format!(
        r#"cast send {contract} \
"submitVerifiedClaim(bytes32,uint[2],uint[2][2],uint[2],uint[1],uint256)" \
{claim_hash} \
'{a}' \
'{b}' \
'{c}' \
'{input}' \
{} \
--value 0.001ether \
--private-key {private_key} \
--rpc-url http://127.0.0.1:8545"#,
        claim.claim_amount
    ));

    println!("Dynamic proof submitted on-chain.");
}