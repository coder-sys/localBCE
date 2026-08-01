//! Nonactivating concrete soundness ledger for the M31/Fp16 PCS candidate.
//!
//! This evaluates the same weighted-correlated-agreement and BaseFold query
//! terms as the binary control, but over the frozen degree-16 M31 tower. One
//! algebraic repetition and one shared query phase are sufficient. A random
//! post-commitment batch scalar combines the main and auxiliary opening claims.

use bl_pq512_crypto_core::field::M31_MODULUS;

const EXTENSION_DEGREE: i32 = 16;
const LOG_INITIAL_DOMAIN: i32 = 23;
const FOLD_ROUNDS: i32 = 21;
const AUXILIARY_LOG_INITIAL_DOMAIN: i32 = 16;
const AUXILIARY_FOLD_ROUNDS: i32 = 15;
const RATE: f64 = 0.5;
const MULTIPLICITY: f64 = 10.0;
const BATCH_DEGREE: f64 = 1.0;
const QUERY_COUNT: i32 = 640;
const INITIAL_LEAF_VALUES: i32 = 8;
const RANDOM_PADDING_COEFFICIENTS: i32 = 8_192;
const FOLDING_FACTOR: i32 = 3;
const INTERNAL_SECURITY_FLOOR_BITS: f64 = 272.0;
// 168 relay-free fan-in-two layers: one degree-30 packed bridge plus
// thirty-five degree-3 sumcheck rounds per layer, with conservative room for
// output and inter-layer batching.
const GKR_DEGREE_UNION_BOUND: f64 = 25_000.0;
const GKR_LAYERS: usize = 168;
const GKR_BRIDGE_MASK_COEFFICIENTS: usize = 31;
const GKR_SUMCHECK_MASK_COEFFICIENTS: usize = 1 + 35 * 3;
const GKR_LAYER_MASK_COEFFICIENTS: usize = 9;

fn field_size() -> f64 {
    f64::from(M31_MODULUS).powi(EXTENSION_DEGREE)
}

fn correlated_agreement_error(domain_size: f64, denominator: f64) -> f64 {
    let list_parameter = MULTIPLICITY + 0.5;
    let quadratic_term = list_parameter.powi(6) / (3.0 * RATE) * domain_size * domain_size;
    let weight_term = 2.0 * (denominator * domain_size + 1.0);
    BATCH_DEGREE / field_size() * list_parameter / RATE.sqrt() * quadratic_term.max(weight_term)
}

fn algebra_error(log_initial_domain: i32, fold_rounds: i32) -> f64 {
    let initial = correlated_agreement_error(2_f64.powi(log_initial_domain), 1.0);
    let folds = (1..=fold_rounds)
        .map(|round| {
            1.0 / field_size()
                + correlated_agreement_error(
                    2_f64.powi(log_initial_domain - round),
                    2_f64.powi(round),
                )
        })
        .sum::<f64>();
    initial + folds + 1.0 / field_size()
}

fn proximity_parameter() -> f64 {
    1.0 - (1.0 + 1.0 / (2.0 * MULTIPLICITY)) * RATE.sqrt()
}

fn query_error() -> f64 {
    (1.0 - proximity_parameter()).powi(QUERY_COUNT)
}

fn gkr_error() -> f64 {
    GKR_DEGREE_UNION_BOUND / field_size()
}

fn composed_error() -> f64 {
    algebra_error(LOG_INITIAL_DOMAIN, FOLD_ROUNDS)
        + algebra_error(AUXILIARY_LOG_INITIAL_DOMAIN, AUXILIARY_FOLD_ROUNDS)
        + 2.0 * query_error()
        + gkr_error()
}

fn security_bits(error: f64) -> f64 {
    -error.log2()
}

fn main() {
    let theta = proximity_parameter();
    let lower = (1.0 - RATE) / 2.0;
    let upper = 1.0 - RATE.sqrt();
    assert!(theta > lower && theta < upper);

    let initially_revealed_evaluations = QUERY_COUNT * INITIAL_LEAF_VALUES;
    let random_padding_coefficients = RANDOM_PADDING_COEFFICIENTS;
    let polynomial_capacity = 2_i32.pow((LOG_INITIAL_DOMAIN - 1) as u32);
    let witness_coefficients = 2_i32.pow(FOLD_ROUNDS as u32);
    assert_eq!(FOLD_ROUNDS % FOLDING_FACTOR, 0);
    assert!(random_padding_coefficients >= initially_revealed_evaluations);
    assert!(witness_coefficients + random_padding_coefficients <= polynomial_capacity);

    let auxiliary_used_coefficients = GKR_LAYERS
        * (GKR_BRIDGE_MASK_COEFFICIENTS
            + GKR_SUMCHECK_MASK_COEFFICIENTS
            + GKR_LAYER_MASK_COEFFICIENTS);
    let auxiliary_padded_coefficients = auxiliary_used_coefficients.next_power_of_two();
    assert_eq!(auxiliary_padded_coefficients, 32_768);
    assert!(
        auxiliary_used_coefficients + random_padding_coefficients as usize
            <= auxiliary_padded_coefficients
    );
    assert_eq!(AUXILIARY_FOLD_ROUNDS % FOLDING_FACTOR, 0);

    let algebra = algebra_error(LOG_INITIAL_DOMAIN, FOLD_ROUNDS);
    let auxiliary_algebra = algebra_error(AUXILIARY_LOG_INITIAL_DOMAIN, AUXILIARY_FOLD_ROUNDS);
    let query = query_error();
    let gkr = gkr_error();
    let composed = composed_error();
    let composed_bits = security_bits(composed);
    assert!(composed_bits >= INTERNAL_SECURITY_FLOOR_BITS);

    println!("scope=fp16_basefold_and_gkr_concrete_soundness");
    println!("evidence_class=theorem_formula_evaluation");
    println!("field_bits={:.9}", field_size().log2());
    println!("initial_domain_log={LOG_INITIAL_DOMAIN}");
    println!("fold_rounds={FOLD_ROUNDS}");
    println!("auxiliary_initial_domain_log={AUXILIARY_LOG_INITIAL_DOMAIN}");
    println!("auxiliary_fold_rounds={AUXILIARY_FOLD_ROUNDS}");
    println!("rate={RATE:.6}");
    println!("multiplicity_parameter={MULTIPLICITY:.0}");
    println!("proximity_parameter={theta:.12}");
    println!("query_count={QUERY_COUNT}");
    println!("folding_factor={FOLDING_FACTOR}");
    println!("initially_revealed_evaluations={initially_revealed_evaluations}");
    println!("random_padding_coefficients={random_padding_coefficients}");
    println!("gkr_mask_used_coefficients={auxiliary_used_coefficients}");
    println!("gkr_mask_padded_coefficients={auxiliary_padded_coefficients}");
    println!("algebra_repetitions=1");
    println!("pcs_instances=2");
    println!("main_sensitive_codewords=2");
    println!("main_random_companion_codewords=1");
    println!("auxiliary_sensitive_codewords=1");
    println!("auxiliary_random_companion_codewords=1");
    println!("algebra_error={algebra:.18e}");
    println!("algebra_security_bits={:.6}", security_bits(algebra));
    println!("auxiliary_algebra_error={auxiliary_algebra:.18e}");
    println!(
        "auxiliary_algebra_security_bits={:.6}",
        security_bits(auxiliary_algebra)
    );
    println!("query_error={query:.18e}");
    println!("query_security_bits={:.6}", security_bits(query));
    println!("gkr_degree_union_bound={GKR_DEGREE_UNION_BOUND:.0}");
    println!("gkr_error={gkr:.18e}");
    println!("gkr_security_bits={:.6}", security_bits(gkr));
    println!("composed_error={composed:.18e}");
    println!("composed_security_bits={composed_bits:.6}");
    println!("internal_security_floor_bits={INTERNAL_SECURITY_FLOOR_BITS:.6}");
    println!("selected_parameter_gate_passed=true");
    println!("proof_system_qualification=false");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_fp16_lane_clears_internal_floor() {
        assert!(security_bits(composed_error()) >= INTERNAL_SECURITY_FLOOR_BITS);
    }

    #[test]
    fn padding_fits_the_rate_half_message_capacity() {
        let padding = RANDOM_PADDING_COEFFICIENTS;
        assert!(padding >= QUERY_COUNT * INITIAL_LEAF_VALUES);
        assert!(2_i32.pow(FOLD_ROUNDS as u32) + padding <= 2_i32.pow(22));
        let used = GKR_LAYERS
            * (GKR_BRIDGE_MASK_COEFFICIENTS
                + GKR_SUMCHECK_MASK_COEFFICIENTS
                + GKR_LAYER_MASK_COEFFICIENTS);
        assert!(used + padding as usize <= 32_768);
    }
}
