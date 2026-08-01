//! Standalone, nonprotocol B=64 first-round measurement spike.
//!
//! This binary is deliberately not wired into the prover. It replaces the
//! impossible flat `2^64` mask/product table with eight 8-bit chunks and
//! evaluates the degree-126 gate relation at 127 public M31 points. Gates are
//! accumulated in M31 by deterministic equality-weight class; Fp16 is touched
//! only during final weighting, interpolation, and query-polynomial assembly.

use std::time::Instant;

use bl_pq512_crypto_core::{Fp16, M31};
use sha3::{Digest, Sha3_512};

const PACK_BITS: usize = 64;
const TENSOR_SIDE: usize = 8;
const BYTE_VALUES: usize = 1 << TENSOR_SIDE;
const WEIGHT_CLASSES: usize = 256;
const RELATION_COEFFICIENTS: usize = 2 * PACK_BITS - 1;
const OUTPUT_COEFFICIENTS: usize = 3 * PACK_BITS;
const K128_PADDED_INSTANCES: usize = 1_024;
const K128_PERMUTATIONS: usize = 782;
const GATES_PER_WORD_GROUP: usize = 44_100;
const K128_WORD_GROUPS: usize = K128_PADDED_INSTANCES / PACK_BITS;
const K128_WORD_GATES: usize = GATES_PER_WORD_GROUP * K128_WORD_GROUPS;
const SELF_CHECK_GATES: usize = 4_097;

fn m31(value: usize) -> M31 {
    M31::from_canonical(value as u32).expect("B=64 interpolation point is canonical")
}

fn lagrange_basis(size: usize) -> Result<Vec<Vec<M31>>, String> {
    let mut basis = Vec::with_capacity(size);
    for point in 0..size {
        let mut polynomial = vec![M31::ZERO; size];
        polynomial[0] = M31::ONE;
        let mut degree = 0;
        let mut denominator = M31::ONE;
        for other in 0..size {
            if other == point {
                continue;
            }
            let root = m31(other);
            for coefficient in (0..=degree).rev() {
                polynomial[coefficient + 1] = polynomial[coefficient + 1] + polynomial[coefficient];
                polynomial[coefficient] = polynomial[coefficient] * -root;
            }
            degree += 1;
            denominator = denominator * (m31(point) - root);
        }
        let inverse = denominator
            .inverse()
            .map_err(|_| "lagrange_denominator_zero".to_string())?;
        for coefficient in &mut polynomial {
            *coefficient = *coefficient * inverse;
        }
        basis.push(polynomial);
    }
    Ok(basis)
}

fn evaluate_m31(coefficients: &[M31], point: M31) -> M31 {
    coefficients
        .iter()
        .copied()
        .rev()
        .fold(M31::ZERO, |value, coefficient| value * point + coefficient)
}

fn evaluate_fp16(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .copied()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| value * point + coefficient)
}

struct TensorTables {
    lane_basis: Vec<Vec<M31>>,
    relation_basis: Vec<Vec<M31>>,
    chunk_evaluations: Vec<M31>,
}

impl TensorTables {
    fn build() -> Result<Self, String> {
        let lane_basis = lagrange_basis(PACK_BITS)?;
        let relation_basis = lagrange_basis(RELATION_COEFFICIENTS)?;
        let mut lane_evaluations = vec![M31::ZERO; PACK_BITS * RELATION_COEFFICIENTS];
        for (lane, polynomial) in lane_basis.iter().enumerate() {
            for point in 0..RELATION_COEFFICIENTS {
                lane_evaluations[point * PACK_BITS + lane] = evaluate_m31(polynomial, m31(point));
            }
        }

        let mut chunk_evaluations =
            vec![M31::ZERO; TENSOR_SIDE * BYTE_VALUES * RELATION_COEFFICIENTS];
        for chunk in 0..TENSOR_SIDE {
            for byte in 0..BYTE_VALUES {
                for point in 0..RELATION_COEFFICIENTS {
                    let mut value = M31::ZERO;
                    for bit in 0..TENSOR_SIDE {
                        if (byte >> bit) & 1 == 1 {
                            value = value
                                + lane_evaluations[point * PACK_BITS + chunk * TENSOR_SIDE + bit];
                        }
                    }
                    chunk_evaluations
                        [(chunk * BYTE_VALUES + byte) * RELATION_COEFFICIENTS + point] = value;
                }
            }
        }
        Ok(Self {
            lane_basis,
            relation_basis,
            chunk_evaluations,
        })
    }

    fn chunk_value(&self, chunk: usize, byte: u8, point: usize) -> M31 {
        self.chunk_evaluations
            [(chunk * BYTE_VALUES + usize::from(byte)) * RELATION_COEFFICIENTS + point]
    }

    fn table_bytes(&self) -> usize {
        self.lane_basis.len() * self.lane_basis[0].len() * size_of::<M31>()
            + self.relation_basis.len() * self.relation_basis[0].len() * size_of::<M31>()
            + self.chunk_evaluations.len() * size_of::<M31>()
    }
}

fn fixture_weights() -> Vec<Fp16> {
    (0..WEIGHT_CLASSES)
        .map(|index| {
            Fp16::from_coefficients(core::array::from_fn(|coefficient| {
                (((index as u64 + 1) * (coefficient as u64 + 3) * 0x9e37_79b9_u64) % 2_147_483_647)
                    as u32
            }))
            .expect("reduced coefficients are canonical")
        })
        .collect()
}

fn fixture_query() -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coefficient| {
        ((coefficient as u64 + 17) * 65_537 % 2_147_483_647) as u32
    }))
    .expect("reduced coefficients are canonical")
}

fn gate_words(index: usize) -> (bool, u64, u64, usize) {
    let mixed = (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (index & 3 == 0, mixed, mixed.rotate_left(29), index & 255)
}

fn query_polynomial(lane_basis: &[Vec<M31>], query: Fp16) -> Result<Vec<Fp16>, String> {
    let mut node_weights = vec![Fp16::ZERO; PACK_BITS];
    for (point, node_weight) in node_weights.iter_mut().enumerate() {
        let mut numerator = Fp16::ONE;
        let mut denominator = M31::ONE;
        for other in 0..PACK_BITS {
            if other == point {
                continue;
            }
            numerator = numerator * (query - Fp16::from_m31(m31(other)));
            denominator = denominator * (m31(point) - m31(other));
        }
        *node_weight = numerator.mul_by_m31(
            denominator
                .inverse()
                .map_err(|_| "query_denominator_zero".to_string())?,
        );
    }

    let mut polynomial = vec![Fp16::ZERO; PACK_BITS];
    for (weight, basis) in node_weights.into_iter().zip(lane_basis) {
        for (coefficient, basis_coefficient) in polynomial.iter_mut().zip(basis) {
            *coefficient = *coefficient + weight.mul_by_m31(*basis_coefficient);
        }
    }
    Ok(polynomial)
}

fn reduce_b64(
    tables: &TensorTables,
    gate_count: usize,
    weights: &[Fp16],
    query: Fp16,
) -> Result<Vec<Fp16>, String> {
    if gate_count == 0 || weights.len() != WEIGHT_CLASSES {
        return Err("shape".to_string());
    }

    let mut class_evaluations = vec![M31::ZERO; WEIGHT_CLASSES * RELATION_COEFFICIENTS];
    for gate in 0..gate_count {
        let (and_gate, left, right, weight_class) = gate_words(gate);
        for point in 0..RELATION_COEFFICIENTS {
            let mut left_value = M31::ZERO;
            let mut right_value = M31::ZERO;
            for chunk in 0..TENSOR_SIDE {
                left_value = left_value
                    + tables.chunk_value(chunk, (left >> (chunk * TENSOR_SIDE)) as u8, point);
                right_value = right_value
                    + tables.chunk_value(chunk, (right >> (chunk * TENSOR_SIDE)) as u8, point);
            }
            let product = left_value * right_value;
            let gate_value = if and_gate {
                product
            } else {
                left_value + right_value - product - product
            };
            let index = weight_class * RELATION_COEFFICIENTS + point;
            class_evaluations[index] = class_evaluations[index] + gate_value;
        }
    }

    let mut relation_evaluations = vec![Fp16::ZERO; RELATION_COEFFICIENTS];
    for weight_class in 0..WEIGHT_CLASSES {
        for point in 0..RELATION_COEFFICIENTS {
            relation_evaluations[point] = relation_evaluations[point]
                + weights[weight_class]
                    .mul_by_m31(class_evaluations[weight_class * RELATION_COEFFICIENTS + point]);
        }
    }

    let mut relation_polynomial = vec![Fp16::ZERO; RELATION_COEFFICIENTS];
    for (evaluation, basis) in relation_evaluations.into_iter().zip(&tables.relation_basis) {
        for (coefficient, basis_coefficient) in relation_polynomial.iter_mut().zip(basis) {
            *coefficient = *coefficient + evaluation.mul_by_m31(*basis_coefficient);
        }
    }

    let query_polynomial = query_polynomial(&tables.lane_basis, query)?;
    let mut output = vec![Fp16::ZERO; OUTPUT_COEFFICIENTS];
    for (left_index, left) in relation_polynomial.into_iter().enumerate() {
        for (right_index, right) in query_polynomial.iter().copied().enumerate() {
            output[left_index + right_index] = output[left_index + right_index] + left * right;
        }
    }
    Ok(output)
}

fn self_check(tables: &TensorTables) -> Result<(), String> {
    let weights = fixture_weights();
    let query = fixture_query();
    let polynomial = reduce_b64(tables, SELF_CHECK_GATES, &weights, query)?;
    if polynomial[OUTPUT_COEFFICIENTS - 2..]
        .iter()
        .any(|value| !value.is_zero())
    {
        return Err("degree".to_string());
    }
    let query_polynomial = query_polynomial(&tables.lane_basis, query)?;
    for lane in 0..PACK_BITS {
        let mut direct = Fp16::ZERO;
        for gate in 0..SELF_CHECK_GATES {
            let (and_gate, left, right, weight_class) = gate_words(gate);
            let left_bit = (left >> lane) & 1;
            let right_bit = (right >> lane) & 1;
            let output_bit = if and_gate {
                left_bit & right_bit
            } else {
                left_bit ^ right_bit
            };
            if output_bit == 1 {
                direct = direct + weights[weight_class];
            }
        }
        let point = Fp16::from_m31(m31(lane));
        if evaluate_fp16(&polynomial, point) != evaluate_fp16(&query_polynomial, point) * direct {
            return Err(format!("lane_parity_{lane}"));
        }
    }
    println!("mode=self_check");
    println!("self_check_gates={SELF_CHECK_GATES}");
    println!("checked_lanes={PACK_BITS}");
    println!("degree_bound=189");
    println!("parity=pass");
    Ok(())
}

fn parse_gate_count() -> Result<Option<usize>, String> {
    match std::env::args().nth(1) {
        Some(value) if value == "--self-check" => Ok(None),
        Some(value) => {
            let gates = value
                .parse::<usize>()
                .map_err(|_| "gate_count_invalid".to_string())?;
            if gates == 0 || gates > K128_WORD_GATES {
                return Err("gate_count_out_of_bounds".to_string());
            }
            Ok(Some(gates))
        }
        None => Ok(Some(K128_WORD_GATES)),
    }
}

fn run() -> Result<(), String> {
    let gate_count = parse_gate_count()?;
    let table_start = Instant::now();
    let tables = TensorTables::build()?;
    let table_elapsed = table_start.elapsed();
    let Some(gate_count) = gate_count else {
        return self_check(&tables);
    };
    let weights = fixture_weights();
    let query = fixture_query();

    let reduction_start = Instant::now();
    let polynomial = reduce_b64(&tables, gate_count, &weights, query)?;
    let reduction_elapsed = reduction_start.elapsed();

    let mut digest = Sha3_512::new();
    for coefficient in polynomial {
        digest.update(coefficient.encode());
    }

    let represented_instance_gates = gate_count * PACK_BITS;
    let xor_gates = gate_count - gate_count.div_ceil(4);
    let point_gate_visits = gate_count * RELATION_COEFFICIENTS;
    println!("mode=measurement_spike_nonprotocol");
    println!("permutations={K128_PERMUTATIONS}");
    println!("padded_instances={K128_PADDED_INSTANCES}");
    println!("pack_bits={PACK_BITS}");
    println!("tensor_shape=8x8");
    println!("flat_2_pow_64_table=false");
    println!("word_gates={gate_count}");
    println!("represented_instance_gates={represented_instance_gates}");
    println!("weight_classes={WEIGHT_CLASSES}");
    println!("output_coefficients={OUTPUT_COEFFICIENTS}");
    println!("table_bytes={}", tables.table_bytes());
    println!(
        "accumulator_bytes={}",
        WEIGHT_CLASSES * RELATION_COEFFICIENTS * size_of::<M31>()
    );
    println!("m31_table_lookups={}", point_gate_visits * 2 * TENSOR_SIDE);
    println!(
        "m31_chunk_accumulator_adds={}",
        point_gate_visits * 2 * TENSOR_SIDE
    );
    println!("m31_relation_multiplies={point_gate_visits}");
    println!(
        "m31_relation_and_accumulator_add_subs={}",
        point_gate_visits + xor_gates * RELATION_COEFFICIENTS * 3
    );
    println!("table_build_ns={}", table_elapsed.as_nanos());
    println!("reduction_ns={}", reduction_elapsed.as_nanos());
    println!(
        "word_gates_per_second={:.3}",
        gate_count as f64 / reduction_elapsed.as_secs_f64()
    );
    println!(
        "represented_instance_gates_per_second={:.3}",
        represented_instance_gates as f64 / reduction_elapsed.as_secs_f64()
    );
    println!("output_sha3_512={:x}", digest.finalize());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("B=64 packed Boolean spike failed: {error}");
        std::process::exit(1);
    }
}
