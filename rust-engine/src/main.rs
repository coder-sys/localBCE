use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

#[derive(Debug, Serialize)]
struct AdjudicationResult {
    claim_id: String,
    claim_hash: String,
    status: String,
    reason: Option<String>,
    tx_submitted: bool,
    tx_hash: Option<String>,
}

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

    disability_determination_valid: u8,
    recipient_not_deceased: u8,
    physician_certification_valid: u8,
}

#[derive(Debug, Serialize)]
struct ZkCircuitInput {
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
    disability_determination_valid: u8,
    recipient_not_deceased: u8,
    physician_certification_valid: u8,
}

impl From<&ClaimInput> for ZkCircuitInput {
    fn from(claim: &ClaimInput) -> Self {
        Self {
            eligibility_active: claim.eligibility_active,
            aid_code: claim.aid_code,
            benefit_level_exists: claim.benefit_level_exists,
            date_of_service_from: claim.date_of_service_from,
            eligibility_period_from: claim.eligibility_period_from,
            eligibility_period_thru: claim.eligibility_period_thru,
            soc_amount: claim.soc_amount,
            soc_met: claim.soc_met,
            provider_enrolled: claim.provider_enrolled,
            provider_type_valid: claim.provider_type_valid,
            billing_code_valid: claim.billing_code_valid,
            units_valid: claim.units_valid,
            is_duplicate: claim.is_duplicate,
            disability_determination_valid: claim.disability_determination_valid,
            recipient_not_deceased: claim.recipient_not_deceased,
            physician_certification_valid: claim.physician_certification_valid,
        }
    }
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
        eprintln!("STDOUT:\n{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("STDERR:\n{}", String::from_utf8_lossy(&output.stderr));
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

fn extract_transaction_hash(cast_output: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<Value>(cast_output) {
        if let Some(tx_hash) = value.get("transactionHash").and_then(Value::as_str) {
            return Some(tx_hash.to_string());
        }
    }

    cast_output.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with("transactionHash") {
            return None;
        }

        trimmed
            .split_whitespace()
            .find(|part| part.starts_with("0x"))
            .map(|part| part.trim_matches('"').to_string())
    })
}

fn denial_reason(claim: &ClaimInput) -> Option<&'static str> {
    if claim.eligibility_active != 1 {
        return Some("G1_IDENTITY_VERIFICATION_FAILED");
    }
    if !matches!(claim.aid_code, 13 | 23 | 53 | 103 | 104) {
        return Some("G2_PROGRAM_ELIGIBILITY_FAILED");
    }
    if claim.benefit_level_exists != 1 {
        return Some("G2_BENEFIT_LEVEL_MISSING");
    }
    if claim.date_of_service_from < claim.eligibility_period_from
        || claim.date_of_service_from > claim.eligibility_period_thru
    {
        return Some("G3_MONTH_OF_SERVICE_FAILED");
    }
    if claim.soc_amount > 0 && claim.soc_met != 1 {
        return Some("G4_SHARE_OF_COST_FAILED");
    }
    if claim.provider_enrolled != 1 {
        return Some("G5_PROVIDER_NOT_ENROLLED");
    }
    if claim.provider_type_valid != 1 {
        return Some("G5_PROVIDER_TYPE_INVALID");
    }
    if claim.billing_code_valid != 1 {
        return Some("G6_BILLING_CODE_INVALID");
    }
    if claim.units_valid != 1 {
        return Some("G6_UNITS_INVALID");
    }
    if claim.is_duplicate != 0 {
        return Some("G7_DUPLICATE_CLAIM");
    }
    if claim.disability_determination_valid != 1 {
        return Some("G8_DISABILITY_DETERMINATION_FAILED");
    }
    if claim.recipient_not_deceased != 1 {
        return Some("G9_RECIPIENT_DECEASED");
    }
    if claim.physician_certification_valid != 1 {
        return Some("G10_PHYSICIAN_CERTIFICATION_FAILED");
    }

    None
}

fn write_result(result: &AdjudicationResult) {
    fs::write(
        "adjudication_result.json",
        serde_json::to_string_pretty(result).unwrap(),
    )
    .unwrap();
}

fn main() {
    let contract = "0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e";
    let private_key =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    let claim_json = fs::read_to_string("claim_input.json")
        .expect("could not read claim_input.json");

    let claim: ClaimInput = serde_json::from_str(&claim_json)
        .expect("invalid claim_input.json");

    let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

    if let Some(reason) = denial_reason(&claim) {
        let result = AdjudicationResult {
            claim_id: claim.claim_id.clone(),
            claim_hash,
            status: "DENIED".to_string(),
            reason: Some(reason.to_string()),
            tx_submitted: false,
            tx_hash: None,
        };

        write_result(&result);

        println!("Claim denied before proof generation: {}", reason);
        println!("Wrote adjudication_result.json");
        return;
    }

    println!("Claim ID: {}", claim.claim_id);
    println!("Claim Hash: {}", claim_hash);

    let zk_input = serde_json::to_string_pretty(&ZkCircuitInput::from(&claim)).unwrap();

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

    let cast_output = run_output(&format!(
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
    let tx_hash = extract_transaction_hash(&cast_output)
        .expect("cast send output did not include transactionHash");

    println!("Dynamic proof submitted on-chain.");

    let result = AdjudicationResult {
        claim_id: claim.claim_id.clone(),
        claim_hash,
        status: "APPROVED".to_string(),
        reason: None,
        tx_submitted: true,
        tx_hash: Some(tx_hash),
    };

    write_result(&result);
    println!("Wrote adjudication_result.json");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_claim() -> ClaimInput {
        ClaimInput {
            claim_id: "CLAIM-TEST-001".to_string(),
            claim_amount: 1000,
            eligibility_active: 1,
            aid_code: 53,
            benefit_level_exists: 1,
            date_of_service_from: 20000,
            eligibility_period_from: 19900,
            eligibility_period_thru: 21000,
            soc_amount: 0,
            soc_met: 1,
            provider_enrolled: 1,
            provider_type_valid: 1,
            billing_code_valid: 1,
            units_valid: 1,
            is_duplicate: 0,
            disability_determination_valid: 1,
            recipient_not_deceased: 1,
            physician_certification_valid: 1,
        }
    }

    #[test]
    fn claim_hash_32_returns_stable_prefixed_32_byte_hex() {
        let hash = claim_hash_32("CLAIM-TEST-001", 1000);

        assert_eq!(hash, claim_hash_32("CLAIM-TEST-001", 1000));
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66);
        assert!(hash[2..].chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn denial_reason_returns_none_for_valid_claim() {
        let claim = valid_claim();

        assert_eq!(denial_reason(&claim), None);
    }

    #[test]
    fn denial_reason_returns_provider_not_enrolled() {
        let mut claim = valid_claim();
        claim.provider_enrolled = 0;

        assert_eq!(denial_reason(&claim), Some("G5_PROVIDER_NOT_ENROLLED"));
    }

    #[test]
    fn denial_reason_returns_duplicate_claim() {
        let mut claim = valid_claim();
        claim.is_duplicate = 1;

        assert_eq!(denial_reason(&claim), Some("G7_DUPLICATE_CLAIM"));
    }

    #[test]
    fn denial_reason_returns_recipient_deceased() {
        let mut claim = valid_claim();
        claim.recipient_not_deceased = 0;

        assert_eq!(denial_reason(&claim), Some("G9_RECIPIENT_DECEASED"));
    }
}
