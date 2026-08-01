use blind_ledger_rules_engine::{
    adjudicate, adjudicate_with_fee_schedule, adjudicate_with_policy,
    adjudicate_with_tar_required_codes, SharedContext,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct EngineRequest {
    context: SharedContext,
    tar_required_procedure_codes: Option<Vec<String>>,
    fee_schedule_cents: Option<BTreeMap<String, i64>>,
}

fn main() {
    let arg = std::env::args()
        .nth(1)
        .expect("expected shared-context JSON arg");
    let value: serde_json::Value = serde_json::from_str(&arg).expect("invalid shared-context JSON");
    let result = if value.get("context").is_some() {
        let request: EngineRequest =
            serde_json::from_value(value).expect("invalid engine request JSON");
        match (
            request.tar_required_procedure_codes,
            request.fee_schedule_cents,
        ) {
            (Some(codes), Some(fee_schedule)) => {
                adjudicate_with_policy(&request.context, &codes, &fee_schedule)
            }
            (Some(codes), None) => adjudicate_with_tar_required_codes(&request.context, &codes),
            (None, Some(fee_schedule)) => {
                adjudicate_with_fee_schedule(&request.context, &fee_schedule)
            }
            (None, None) => adjudicate(&request.context),
        }
    } else {
        let ctx: SharedContext =
            serde_json::from_value(value).expect("invalid shared-context JSON");
        adjudicate(&ctx)
    };
    println!(
        "{}",
        serde_json::to_string(&result).expect("serialize result")
    );
}
