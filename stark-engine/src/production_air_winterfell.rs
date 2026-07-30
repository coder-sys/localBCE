use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions,
    Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
    crypto::{DefaultRandomCoin, MerkleTree, hashers::Blake3_256},
    math::{FieldElement, ToElements, fields::f128::BaseElement},
    matrix::ColMatrix,
};

use crate::production_air::{
    ProductionAirInputV1, ProductionAirSemanticsTraceV1, evaluate_outcome,
};

pub type ProductionFelt = BaseElement;

pub const TRACE_LENGTH: usize = 16;

const COL_ELIGIBILITY_ACTIVE: usize = 0;
const COL_AID_CODE: usize = 1;
const COL_BENEFIT_LEVEL_EXISTS: usize = 2;
const COL_DATE_OF_SERVICE_FROM: usize = 3;
const COL_ELIGIBILITY_PERIOD_FROM: usize = 4;
const COL_ELIGIBILITY_PERIOD_THRU: usize = 5;
const COL_SOC_AMOUNT: usize = 6;
const COL_SOC_MET: usize = 7;
const COL_PROVIDER_ENROLLED: usize = 8;
const COL_PROVIDER_TYPE_VALID: usize = 9;
const COL_BILLING_CODE_VALID: usize = 10;
const COL_UNITS_VALID: usize = 11;
const COL_IS_DUPLICATE: usize = 12;
const COL_DISABILITY_DETERMINATION_VALID: usize = 13;
const COL_RECIPIENT_NOT_DECEASED: usize = 14;
const COL_PHYSICIAN_CERTIFICATION_VALID: usize = 15;

const CLAIM_HASH_LIMBS_START: usize = 16;
const GATES_START: usize = 20;
const PREFIXES_START: usize = 33;
const COL_DATE_GE_FROM: usize = 46;
const COL_DATE_LE_THRU: usize = 47;
const COL_DATE_GE_DIFF: usize = 48;
const COL_DATE_LE_DIFF: usize = 49;
const COL_SOC_ZERO: usize = 50;
const COL_SOC_INVERSE: usize = 51;
const COL_AID_PRODUCT_INVERSE: usize = 52;
const COL_DECISION: usize = 53;
const COL_FAILURE_CODE: usize = 54;
const DATE_GE_DIFF_BITS_START: usize = 55;
const DATE_LE_DIFF_BITS_START: usize = 119;
const COL_CLOCK: usize = 183;

pub const TRACE_WIDTH: usize = 184;
const GATE_COUNT: usize = 13;
const U64_BITS: usize = 64;
const SEMANTIC_CONSTRAINT_COUNT: usize = 193;

const BOOLEAN_FACT_COLUMNS: [usize; 11] = [
    COL_ELIGIBILITY_ACTIVE,
    COL_BENEFIT_LEVEL_EXISTS,
    COL_SOC_MET,
    COL_PROVIDER_ENROLLED,
    COL_PROVIDER_TYPE_VALID,
    COL_BILLING_CODE_VALID,
    COL_UNITS_VALID,
    COL_IS_DUPLICATE,
    COL_DISABILITY_DETERMINATION_VALID,
    COL_RECIPIENT_NOT_DECEASED,
    COL_PHYSICIAN_CERTIFICATION_VALID,
];

const FAILURE_CODES: [u32; GATE_COUNT] = [1, 201, 202, 3, 4, 501, 502, 601, 602, 7, 8, 9, 10];

#[derive(Clone, Copy, Debug)]
pub struct ProductionAirPublicInputsV1 {
    pub claim_hash_limbs: [ProductionFelt; 4],
    pub decision: ProductionFelt,
    pub failure_code: ProductionFelt,
}

impl ToElements<ProductionFelt> for ProductionAirPublicInputsV1 {
    fn to_elements(&self) -> Vec<ProductionFelt> {
        let mut elements = self.claim_hash_limbs.to_vec();
        elements.push(self.decision);
        elements.push(self.failure_code);
        elements
    }
}

pub struct ProductionG1G10Air {
    context: AirContext<ProductionFelt>,
    public_inputs: ProductionAirPublicInputsV1,
}

impl Air for ProductionG1G10Air {
    type BaseField = ProductionFelt;
    type PublicInputs = ProductionAirPublicInputsV1;

    fn new(
        trace_info: TraceInfo,
        public_inputs: Self::PublicInputs,
        options: ProofOptions,
    ) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width());
        Self {
            context: AirContext::new(trace_info, transition_degrees(), 7, options),
            public_inputs,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let one = E::ONE;
        let mut index = 0;

        for column in boolean_columns() {
            let value = current[column];
            result[index] = value * (value - one);
            index += 1;
        }

        for bits_start in [DATE_GE_DIFF_BITS_START, DATE_LE_DIFF_BITS_START] {
            for bit in 0..U64_BITS {
                let value = current[bits_start + bit];
                result[index] = value * (value - one);
                index += 1;
            }
        }

        let aid_product = supported_aid_product(current[COL_AID_CODE]);
        let aid_gate = current[gate_column(1)];
        result[index] = aid_product * aid_gate;
        index += 1;
        result[index] = aid_product * current[COL_AID_PRODUCT_INVERSE] - (one - aid_gate);
        index += 1;

        let date_ge = current[COL_DATE_GE_FROM];
        let date_le = current[COL_DATE_LE_THRU];
        let date_of_service = current[COL_DATE_OF_SERVICE_FROM];
        let period_from = current[COL_ELIGIBILITY_PERIOD_FROM];
        let period_thru = current[COL_ELIGIBILITY_PERIOD_THRU];
        let ge_diff = current[COL_DATE_GE_DIFF];
        let le_diff = current[COL_DATE_LE_DIFF];

        result[index] = date_ge * (date_of_service - period_from - ge_diff);
        index += 1;
        result[index] = (one - date_ge) * (period_from - date_of_service - one - ge_diff);
        index += 1;
        result[index] = ge_diff - bits_to_value(current, DATE_GE_DIFF_BITS_START);
        index += 1;

        result[index] = date_le * (period_thru - date_of_service - le_diff);
        index += 1;
        result[index] = (one - date_le) * (date_of_service - period_thru - one - le_diff);
        index += 1;
        result[index] = le_diff - bits_to_value(current, DATE_LE_DIFF_BITS_START);
        index += 1;

        let soc_amount = current[COL_SOC_AMOUNT];
        let soc_zero = current[COL_SOC_ZERO];
        result[index] = soc_amount * soc_zero;
        index += 1;
        result[index] = soc_amount * current[COL_SOC_INVERSE] - (one - soc_zero);
        index += 1;

        for (gate, fact) in [
            (0, COL_ELIGIBILITY_ACTIVE),
            (2, COL_BENEFIT_LEVEL_EXISTS),
            (5, COL_PROVIDER_ENROLLED),
            (6, COL_PROVIDER_TYPE_VALID),
            (7, COL_BILLING_CODE_VALID),
            (8, COL_UNITS_VALID),
            (10, COL_DISABILITY_DETERMINATION_VALID),
            (11, COL_RECIPIENT_NOT_DECEASED),
            (12, COL_PHYSICIAN_CERTIFICATION_VALID),
        ] {
            result[index] = current[gate_column(gate)] - current[fact];
            index += 1;
        }
        result[index] = current[gate_column(3)] - date_ge * date_le;
        index += 1;
        result[index] = current[gate_column(4)]
            - (soc_zero + current[COL_SOC_MET] - soc_zero * current[COL_SOC_MET]);
        index += 1;
        result[index] = current[gate_column(9)] - (one - current[COL_IS_DUPLICATE]);
        index += 1;

        result[index] = current[prefix_column(0)] - one;
        index += 1;
        for gate in 1..GATE_COUNT {
            result[index] = current[prefix_column(gate)]
                - current[prefix_column(gate - 1)] * current[gate_column(gate - 1)];
            index += 1;
        }

        result[index] = current[COL_DECISION]
            - current[prefix_column(GATE_COUNT - 1)] * current[gate_column(GATE_COUNT - 1)];
        index += 1;

        let mut expected_failure_code = E::ZERO;
        for (gate, failure_code) in FAILURE_CODES.iter().copied().enumerate() {
            expected_failure_code += E::from(failure_code)
                * (one - current[gate_column(gate)])
                * current[prefix_column(gate)];
        }
        result[index] = current[COL_FAILURE_CODE] - expected_failure_code;
        index += 1;

        debug_assert_eq!(index, SEMANTIC_CONSTRAINT_COUNT);

        // Winterfell's debug prover requires witness-independent exact degree
        // metadata. The constrained clock term is zero on every valid
        // transition while fixing each semantic constraint at degree six.
        let clock_transition = next[COL_CLOCK] - current[COL_CLOCK] - one;
        let mut degree_adjustment = clock_transition;
        for _ in 0..5 {
            degree_adjustment *= current[COL_CLOCK];
        }
        for (constraint_index, value) in result[..index].iter_mut().enumerate() {
            *value += degree_adjustment * E::from((constraint_index + 1) as u32);
        }

        result[index] = clock_transition;
        index += 1;

        debug_assert_eq!(index, result.len());
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(6);
        for (limb, value) in self.public_inputs.claim_hash_limbs.iter().enumerate() {
            assertions.push(Assertion::single(CLAIM_HASH_LIMBS_START + limb, 0, *value));
        }
        assertions.push(Assertion::single(
            COL_DECISION,
            0,
            self.public_inputs.decision,
        ));
        assertions.push(Assertion::single(
            COL_FAILURE_CODE,
            0,
            self.public_inputs.failure_code,
        ));
        assertions.push(Assertion::single(COL_CLOCK, 0, ProductionFelt::ZERO));
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

pub struct ProductionG1G10Prover {
    options: ProofOptions,
}

impl ProductionG1G10Prover {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for ProductionG1G10Prover {
    type BaseField = ProductionFelt;
    type Air = ProductionG1G10Air;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ProductionAirPublicInputsV1 {
        ProductionAirPublicInputsV1 {
            claim_hash_limbs: [
                trace.get(CLAIM_HASH_LIMBS_START, 0),
                trace.get(CLAIM_HASH_LIMBS_START + 1, 0),
                trace.get(CLAIM_HASH_LIMBS_START + 2, 0),
                trace.get(CLAIM_HASH_LIMBS_START + 3, 0),
            ],
            decision: trace.get(COL_DECISION, 0),
            failure_code: trace.get(COL_FAILURE_CODE, 0),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub fn build_production_air_trace(
    input: &ProductionAirInputV1,
) -> Result<TraceTable<ProductionFelt>, Vec<String>> {
    input.validate()?;
    let trace_inputs = trace_inputs(input);
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    for (step, trace_input) in trace_inputs.into_iter().enumerate() {
        let semantics = trace_input.evaluate()?;
        let mut row = build_trace_row(&trace_input, &semantics)?;
        row[COL_CLOCK] = ProductionFelt::from(step as u32);
        rows.push(row);
    }
    let columns = (0..TRACE_WIDTH)
        .map(|column| rows.iter().map(|row| row[column]).collect())
        .collect();
    Ok(TraceTable::init(columns))
}

pub fn prove_production_air(
    input: &ProductionAirInputV1,
) -> Result<(Proof, ProductionAirPublicInputsV1), String> {
    let trace = build_production_air_trace(input).map_err(|errors| errors.join("; "))?;
    let prover = ProductionG1G10Prover::new(default_options());
    let public_inputs = prover.get_pub_inputs(&trace);
    let proof = prover
        .prove(trace)
        .map_err(|error| format!("production G1-G10 proof generation failed: {error}"))?;
    Ok((proof, public_inputs))
}

pub fn verify_production_air(proof: Proof, public_inputs: ProductionAirPublicInputsV1) -> bool {
    winterfell::verify::<
        ProductionG1G10Air,
        Blake3_256<ProductionFelt>,
        DefaultRandomCoin<Blake3_256<ProductionFelt>>,
        MerkleTree<Blake3_256<ProductionFelt>>,
    >(proof, public_inputs, &acceptable_options())
    .is_ok()
}

pub fn default_options() -> ProofOptions {
    ProofOptions::new(
        32,
        16,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn acceptable_options() -> AcceptableOptions {
    AcceptableOptions::MinConjecturedSecurity(80)
}

fn build_trace_row(
    input: &ProductionAirInputV1,
    semantics: &ProductionAirSemanticsTraceV1,
) -> Result<[ProductionFelt; TRACE_WIDTH], Vec<String>> {
    let facts = &input.facts;
    let mut row = [ProductionFelt::ZERO; TRACE_WIDTH];

    row[COL_ELIGIBILITY_ACTIVE] = felt(facts.eligibility_active as u64);
    row[COL_AID_CODE] = felt(facts.aid_code);
    row[COL_BENEFIT_LEVEL_EXISTS] = felt(facts.benefit_level_exists as u64);
    row[COL_DATE_OF_SERVICE_FROM] = felt(facts.date_of_service_from);
    row[COL_ELIGIBILITY_PERIOD_FROM] = felt(facts.eligibility_period_from);
    row[COL_ELIGIBILITY_PERIOD_THRU] = felt(facts.eligibility_period_thru);
    row[COL_SOC_AMOUNT] = felt(facts.soc_amount);
    row[COL_SOC_MET] = felt(facts.soc_met as u64);
    row[COL_PROVIDER_ENROLLED] = felt(facts.provider_enrolled as u64);
    row[COL_PROVIDER_TYPE_VALID] = felt(facts.provider_type_valid as u64);
    row[COL_BILLING_CODE_VALID] = felt(facts.billing_code_valid as u64);
    row[COL_UNITS_VALID] = felt(facts.units_valid as u64);
    row[COL_IS_DUPLICATE] = felt(facts.is_duplicate as u64);
    row[COL_DISABILITY_DETERMINATION_VALID] = felt(facts.disability_determination_valid as u64);
    row[COL_RECIPIENT_NOT_DECEASED] = felt(facts.recipient_not_deceased as u64);
    row[COL_PHYSICIAN_CERTIFICATION_VALID] = felt(facts.physician_certification_valid as u64);

    let claim_hash_limbs = parse_claim_hash_limbs(&input.claim_hash)?;
    for (index, value) in claim_hash_limbs.iter().enumerate() {
        row[CLAIM_HASH_LIMBS_START + index] = *value;
    }

    for (index, gate) in semantics.rows.iter().enumerate() {
        row[gate_column(index)] = ProductionFelt::from(gate.satisfied as u32);
    }

    let mut prefix = 1u8;
    for gate in 0..GATE_COUNT {
        row[prefix_column(gate)] = ProductionFelt::from(prefix as u32);
        prefix *= semantics.rows[gate].satisfied as u8;
    }

    let date_ge = facts.date_of_service_from >= facts.eligibility_period_from;
    let date_ge_diff = if date_ge {
        facts.date_of_service_from - facts.eligibility_period_from
    } else {
        facts.eligibility_period_from - facts.date_of_service_from - 1
    };
    row[COL_DATE_GE_FROM] = ProductionFelt::from(date_ge as u32);
    row[COL_DATE_GE_DIFF] = felt(date_ge_diff);
    set_u64_bits(&mut row, DATE_GE_DIFF_BITS_START, date_ge_diff);

    let date_le = facts.date_of_service_from <= facts.eligibility_period_thru;
    let date_le_diff = if date_le {
        facts.eligibility_period_thru - facts.date_of_service_from
    } else {
        facts.date_of_service_from - facts.eligibility_period_thru - 1
    };
    row[COL_DATE_LE_THRU] = ProductionFelt::from(date_le as u32);
    row[COL_DATE_LE_DIFF] = felt(date_le_diff);
    set_u64_bits(&mut row, DATE_LE_DIFF_BITS_START, date_le_diff);

    let soc_zero = facts.soc_amount == 0;
    row[COL_SOC_ZERO] = ProductionFelt::from(soc_zero as u32);
    row[COL_SOC_INVERSE] = inverse_or_zero(row[COL_SOC_AMOUNT]);

    let aid_product = supported_aid_product(row[COL_AID_CODE]);
    row[COL_AID_PRODUCT_INVERSE] = inverse_or_zero(aid_product);
    row[COL_DECISION] = ProductionFelt::from(semantics.outcome.decision as u32);
    row[COL_FAILURE_CODE] = ProductionFelt::from(semantics.outcome.failure_code);

    Ok(row)
}

fn transition_degrees() -> Vec<TransitionConstraintDegree> {
    let mut degrees = vec![TransitionConstraintDegree::new(6); SEMANTIC_CONSTRAINT_COUNT];
    degrees.push(TransitionConstraintDegree::new(1));
    degrees
}

fn trace_inputs(target: &ProductionAirInputV1) -> Vec<ProductionAirInputV1> {
    let mut approved = target.clone();
    approved.facts.eligibility_active = 1;
    approved.facts.aid_code = 53;
    approved.facts.benefit_level_exists = 1;
    approved.facts.date_of_service_from = 20_000;
    approved.facts.eligibility_period_from = 19_900;
    approved.facts.eligibility_period_thru = 21_000;
    approved.facts.soc_amount = 0;
    approved.facts.soc_met = 1;
    approved.facts.provider_enrolled = 1;
    approved.facts.provider_type_valid = 1;
    approved.facts.billing_code_valid = 1;
    approved.facts.units_valid = 1;
    approved.facts.is_duplicate = 0;
    approved.facts.disability_determination_valid = 1;
    approved.facts.recipient_not_deceased = 1;
    approved.facts.physician_certification_valid = 1;
    refresh_expected_outcome(&mut approved);

    let mut approved_max_ge_diff = approved.clone();
    approved_max_ge_diff.facts.aid_code = 104;
    approved_max_ge_diff.facts.date_of_service_from = u64::MAX;
    approved_max_ge_diff.facts.eligibility_period_from = 0;
    approved_max_ge_diff.facts.eligibility_period_thru = u64::MAX;
    approved_max_ge_diff.facts.soc_amount = 100;
    approved_max_ge_diff.facts.soc_met = 1;
    refresh_expected_outcome(&mut approved_max_ge_diff);

    let mut rows = vec![target.clone(), approved_max_ge_diff];

    let mut case = approved.clone();
    case.facts.eligibility_active = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.aid_code = 999;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.benefit_level_exists = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.date_of_service_from = case.facts.eligibility_period_thru + 1;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.soc_amount = 100;
    case.facts.soc_met = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.provider_enrolled = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.provider_type_valid = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.billing_code_valid = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.units_valid = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.is_duplicate = 1;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.disability_determination_valid = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.recipient_not_deceased = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut case = approved.clone();
    case.facts.physician_certification_valid = 0;
    refresh_expected_outcome(&mut case);
    rows.push(case);

    let mut date_before = approved;
    date_before.facts.date_of_service_from = 0;
    date_before.facts.eligibility_period_from = 1;
    date_before.facts.eligibility_period_thru = u64::MAX;
    refresh_expected_outcome(&mut date_before);
    rows.push(date_before);

    debug_assert_eq!(rows.len(), TRACE_LENGTH);
    rows
}

fn refresh_expected_outcome(input: &mut ProductionAirInputV1) {
    input.expected_outcome = evaluate_outcome(&input.facts);
}

fn boolean_columns() -> Vec<usize> {
    let mut columns = BOOLEAN_FACT_COLUMNS.to_vec();
    columns.extend(GATES_START..GATES_START + GATE_COUNT);
    columns.extend([
        COL_DATE_GE_FROM,
        COL_DATE_LE_THRU,
        COL_SOC_ZERO,
        COL_DECISION,
    ]);
    columns
}

fn supported_aid_product<E: FieldElement + From<ProductionFelt>>(aid_code: E) -> E {
    [13u32, 23, 53, 103, 104]
        .into_iter()
        .fold(E::ONE, |product, allowed| {
            product * (aid_code - E::from(allowed))
        })
}

fn bits_to_value<E: FieldElement + From<ProductionFelt>>(row: &[E], start: usize) -> E {
    let mut value = E::ZERO;
    for bit in 0..U64_BITS {
        value += row[start + bit] * E::from(ProductionFelt::new(1u128 << bit));
    }
    value
}

fn set_u64_bits(row: &mut [ProductionFelt; TRACE_WIDTH], start: usize, value: u64) {
    for bit in 0..U64_BITS {
        row[start + bit] = ProductionFelt::from(((value >> bit) & 1) as u32);
    }
}

fn parse_claim_hash_limbs(claim_hash: &str) -> Result<[ProductionFelt; 4], Vec<String>> {
    let hex = claim_hash.strip_prefix("0x").unwrap_or(claim_hash);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(vec![
            "claim_hash must be a 0x-prefixed 32-byte hex string".to_string(),
        ]);
    }

    let mut limbs = [ProductionFelt::ZERO; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 16;
        let value = u64::from_str_radix(&hex[start..start + 16], 16)
            .map_err(|error| vec![format!("invalid claim_hash limb {index}: {error}")])?;
        *limb = felt(value);
    }
    Ok(limbs)
}

fn felt(value: u64) -> ProductionFelt {
    ProductionFelt::new(value as u128)
}

fn inverse_or_zero(value: ProductionFelt) -> ProductionFelt {
    if value == ProductionFelt::ZERO {
        ProductionFelt::ZERO
    } else {
        value.inv()
    }
}

fn gate_column(gate: usize) -> usize {
    GATES_START + gate
}

fn prefix_column(gate: usize) -> usize {
    PREFIXES_START + gate
}

#[cfg(test)]
#[path = "production_air_winterfell_tests.rs"]
mod tests;
