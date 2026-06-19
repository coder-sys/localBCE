use blind_ledger_rules_engine::{adjudicate, SharedContext};

fn main() {
    let arg = std::env::args().nth(1).expect("expected shared-context JSON arg");
    let ctx: SharedContext = serde_json::from_str(&arg).expect("invalid shared-context JSON");
    let result = adjudicate(&ctx);
    println!("{}", serde_json::to_string(&result).expect("serialize result"));
}

