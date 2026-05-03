#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

#[derive(Debug)]
struct ClaimContext {
    eligibility_active: bool,
    aid_code: &'static str,
    benefit_level_exists: bool,

    date_of_service_from: i32,
    date_of_service_thru: i32,
    eligibility_period_from: i32,
    eligibility_period_thru: i32,

    soc_amount: u64,
    soc_met: bool,
}

fn claim_hash_32(claim_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(claim_id.as_bytes());

    let result = hasher.finalize();
    result.into()
}

pub fn main() {
    let claim_id = "CLAIM-001";

    let claim = ClaimContext {
        eligibility_active: true,
        aid_code: "53",
        benefit_level_exists: true,

        date_of_service_from: 20000,
        date_of_service_thru: 20005,
        eligibility_period_from: 19900,
        eligibility_period_thru: 21000,

        soc_amount: 0,
        soc_met: true,
    };

    let valid_aid_codes = ["13", "23", "53", "D3", "D4"];

    let g1 = claim.eligibility_active;

    let g2 =
        valid_aid_codes.contains(&claim.aid_code) && claim.benefit_level_exists;

    let g3 = claim.date_of_service_from >= claim.eligibility_period_from
        && claim.date_of_service_thru <= claim.eligibility_period_thru;

    let g4 = if claim.soc_amount > 0 {
        claim.soc_met
    } else {
        true
    };

    let decision_pass = g1 && g2 && g3 && g4;
    let claim_hash = claim_hash_32(claim_id);

    sp1_zkvm::io::commit(&decision_pass);
    sp1_zkvm::io::commit(&claim_hash);
}