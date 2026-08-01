//! Nonactivating concrete soundness ledger for the theorem-shaped K128 PCS.
//!
//! This evaluates Haböck's weighted-correlated-agreement bound and the
//! BaseFold query term. It models five independent algebraic repetitions over
//! one shared proximity-query phase. The repeated product is valid only when
//! every repetition has a fresh hiding polynomial and fresh authenticated
//! algebraic challenges after its commitments.

const FIELD_BITS: i32 = 128;
const LOG_INITIAL_DOMAIN: i32 = 23;
const FOLD_ROUNDS: i32 = 21;
const RATE: f64 = 0.5;
const MULTIPLICITY: f64 = 10.0;
const BATCH_DEGREE: f64 = 1.0;
const QUERY_COUNT: i32 = 640;
const FOLDING_FACTOR: i32 = 3;
const ALGEBRA_REPETITIONS: i32 = 5;
const INTERNAL_SECURITY_FLOOR_BITS: f64 = 272.0;

fn correlated_agreement_error(domain_size: f64, denominator: f64) -> f64 {
    let field_size = 2_f64.powi(FIELD_BITS);
    let list_parameter = MULTIPLICITY + 0.5;
    let quadratic_term = list_parameter.powi(6) / (3.0 * RATE) * domain_size * domain_size;
    let weight_term = 2.0 * (denominator * domain_size + 1.0);
    BATCH_DEGREE / field_size * list_parameter / RATE.sqrt() * quadratic_term.max(weight_term)
}

fn single_algebra_error() -> f64 {
    let field_size = 2_f64.powi(FIELD_BITS);
    let initial = correlated_agreement_error(2_f64.powi(LOG_INITIAL_DOMAIN), 1.0);
    let folds = (1..=FOLD_ROUNDS)
        .map(|round| {
            1.0 / field_size
                + correlated_agreement_error(
                    2_f64.powi(LOG_INITIAL_DOMAIN - round),
                    2_f64.powi(round),
                )
        })
        .sum::<f64>();
    initial + folds
}

fn proximity_parameter() -> f64 {
    1.0 - (1.0 + 1.0 / (2.0 * MULTIPLICITY)) * RATE.sqrt()
}

fn query_error() -> f64 {
    (1.0 - proximity_parameter()).powi(QUERY_COUNT)
}

fn combined_error(repetitions: i32) -> f64 {
    single_algebra_error().powi(repetitions) + query_error()
}

fn security_bits(error: f64) -> f64 {
    -error.log2()
}

fn main() {
    let theta = proximity_parameter();
    let lower = (1.0 - RATE) / 2.0;
    let upper = 1.0 - RATE.sqrt();
    assert!(
        theta > lower && theta < upper,
        "selected proximity parameter is outside the theorem interval"
    );
    let algebra_error = single_algebra_error();
    let repeated_algebra_error = algebra_error.powi(ALGEBRA_REPETITIONS);
    let query_error = query_error();
    let combined_error = combined_error(ALGEBRA_REPETITIONS);
    let combined_bits = security_bits(combined_error);
    assert!(
        combined_bits >= INTERNAL_SECURITY_FLOOR_BITS,
        "selected PCS soundness misses the internal composition floor"
    );

    let random_padding_coefficients = QUERY_COUNT * 2_i32.pow(FOLDING_FACTOR as u32);
    let polynomial_capacity = 2_i32.pow((LOG_INITIAL_DOMAIN - 1) as u32);
    let witness_coefficients = 2_i32.pow(FOLD_ROUNDS as u32);
    assert_eq!(
        FOLD_ROUNDS % FOLDING_FACTOR,
        0,
        "the construction requires the folding factor to divide the witness dimension"
    );
    assert!(
        witness_coefficients + random_padding_coefficients <= polynomial_capacity,
        "zero-knowledge padding exceeds polynomial capacity"
    );

    println!("scope=zk_binary_basefold_concrete_soundness");
    println!("evidence_class=theorem_formula_evaluation");
    println!("field_bits={FIELD_BITS}");
    println!("initial_domain_log={LOG_INITIAL_DOMAIN}");
    println!("fold_rounds={FOLD_ROUNDS}");
    println!("rate={RATE:.6}");
    println!("multiplicity_parameter={MULTIPLICITY:.0}");
    println!("proximity_parameter={theta:.12}");
    println!("query_count={QUERY_COUNT}");
    println!("folding_factor={FOLDING_FACTOR}");
    println!("random_padding_coefficients={random_padding_coefficients}");
    println!("algebra_repetitions={ALGEBRA_REPETITIONS}");
    println!("single_algebra_error={algebra_error:.18e}");
    println!(
        "single_algebra_security_bits={:.6}",
        security_bits(algebra_error)
    );
    println!("repeated_algebra_error={repeated_algebra_error:.18e}");
    println!(
        "repeated_algebra_security_bits={:.6}",
        security_bits(repeated_algebra_error)
    );
    println!("query_error={query_error:.18e}");
    println!("query_security_bits={:.6}", security_bits(query_error));
    println!("combined_error={combined_error:.18e}");
    println!("combined_security_bits={combined_bits:.6}");
    println!("internal_security_floor_bits={INTERNAL_SECURITY_FLOOR_BITS:.6}");
    println!("selected_parameter_gate_passed=true");
    println!("proof_system_qualification=false");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_five_repetitions_clear_internal_floor() {
        assert!(security_bits(combined_error(ALGEBRA_REPETITIONS)) >= INTERNAL_SECURITY_FLOOR_BITS);
    }

    #[test]
    fn four_repetitions_are_rejected() {
        assert!(security_bits(combined_error(4)) < 256.0);
    }
}
