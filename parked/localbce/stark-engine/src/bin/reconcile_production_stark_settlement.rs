use std::{env, path::PathBuf, process, time::Duration};

use serde_json::json;
use stark_engine::production_stark_settlement::{
    ProductionStarkSettlementReconciliationRequest, SettlementFinalityMode,
    reconcile_production_stark_settlement,
};

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 7 {
        eprintln!(
            "usage: reconcile_production_stark_settlement <journal.json> <transition.json> <nullifier_state.json> <report.json> <registry_address> <rpc_url>"
        );
        process::exit(2);
    }
    let journal_path = PathBuf::from(&args[1]);
    let transition_path = PathBuf::from(&args[2]);
    let state_path = PathBuf::from(&args[3]);
    let report_path = PathBuf::from(&args[4]);
    let timeout = env_u64("STARK_FINALITY_TIMEOUT_SECONDS", 900);
    let poll = env_u64("STARK_FINALITY_POLL_SECONDS", 12);
    let chain_id = env_u64("STARK_CHAIN_ID", 11155111);
    let finality_mode = match env::var("STARK_FINALITY_MODE")
        .unwrap_or_else(|_| "finalized".to_string())
        .as_str()
    {
        "mined" => SettlementFinalityMode::Mined,
        "finalized" => SettlementFinalityMode::Finalized,
        "test_mined" => SettlementFinalityMode::TestMined,
        value => {
            eprintln!(
                "unsupported STARK_FINALITY_MODE '{value}'; expected mined, finalized, or test_mined"
            );
            process::exit(2);
        }
    };
    let request = ProductionStarkSettlementReconciliationRequest {
        journal_path: &journal_path,
        transition_path: &transition_path,
        nullifier_state_path: &state_path,
        report_path: &report_path,
        registry_address: &args[5],
        rpc_url: &args[6],
        chain_id,
        finality_mode,
        finality_timeout: Duration::from_secs(timeout),
        finality_poll_interval: Duration::from_secs(poll),
    };
    match reconcile_production_stark_settlement(&request) {
        Ok(report) => println!(
            "{}",
            json!({
                "event": "stark_production_settlement_reconciliation",
                "status": "ok",
                "transaction_hash": report.transaction_hash,
                "finalized_block_number": report.finalized_block_number,
                "claim_hash": report.claim_hash,
                "batch_root": report.batch_root,
                "local_state_committed_now": report.local_state_committed_now,
                "retry_count": report.retry_count,
                "report": report_path,
            })
        ),
        Err(errors) => {
            eprintln!("{}", json!({"status": "error", "errors": errors}));
            process::exit(1);
        }
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}
