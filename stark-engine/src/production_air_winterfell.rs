use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions,
    Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
    crypto::{
        DefaultRandomCoin, ElementHasher, MerkleTree,
        hashers::{Blake3_256, Rp64_256},
    },
    math::{FieldElement, ToElements, fields::f64::BaseElement},
    matrix::ColMatrix,
};

use std::fmt::Write as _;

use crate::{
    StarkBridgeInput,
    production_air::{ProductionAirInputV1, ProductionAirSemanticsTraceV1},
    production_fee_schedule_root::{
        FEE_SCHEDULE_ROOT_DOMAIN_TAG, FEE_SCHEDULE_ROOT_HASH_TAG, FEE_SCHEDULE_ROOT_LEAF_INDEX,
        FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH, FEE_SCHEDULE_ROOT_NORMALIZATION_TAG,
        FEE_SCHEDULE_ROOT_SCHEMA_TAG, FEE_SCHEDULE_ROOT_TREE_DEPTH,
        ProductionFeeScheduleRootArtifactV1,
    },
    source_roots::{
        CLAIM_SOURCE_ROOT_DOMAIN_TAG, CLAIM_SOURCE_ROOT_HASH_TAG, CLAIM_SOURCE_ROOT_LEAF_INDEX,
        CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH, CLAIM_SOURCE_ROOT_SCHEMA_TAG,
        CLAIM_SOURCE_ROOT_TREE_DEPTH, CLAIM_SOURCE_ROOT_UNIT_TAG, ORACLE_FACTS_ROOT_DOMAIN_TAG,
        ORACLE_FACTS_ROOT_HASH_TAG, ORACLE_FACTS_ROOT_LEAF_INDEX,
        ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH, ORACLE_FACTS_ROOT_NORMALIZATION_TAG,
        ORACLE_FACTS_ROOT_SCHEMA_TAG, ORACLE_FACTS_ROOT_TREE_DEPTH,
        ProductionClaimSourceRootArtifactV1, ProductionOracleFactsRootArtifactV1,
    },
};

pub type ProductionFelt = BaseElement;

pub const TRACE_LENGTH: usize = 512;

pub const FACT_COMMITMENT_SCHEMA_VERSION: &str = "stark-claim-fact-commitment-v1";
pub const FACT_COMMITMENT_HASH_FUNCTION: &str = "winterfell-rp64-256";
pub const FACT_COMMITMENT_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCFACT\0");
pub const FACT_COMMITMENT_RULESET_TAG: u64 = u64::from_le_bytes(*b"G1G10V1\0");
pub const PUBLIC_INPUT_ROOT_SCHEMA_VERSION: &str = "stark-public-input-root-v4";
pub const PUBLIC_INPUT_ROOT_HASH_FUNCTION: &str = "winterfell-rp64-256";
pub const PUBLIC_INPUT_ROOT_ENCODING: &str = "bytes32-four-canonical-f64-big-endian";
pub const PUBLIC_INPUT_ROOT_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCPIR04");
pub const PUBLIC_INPUT_ROOT_RULESET_TAG: u64 = FACT_COMMITMENT_RULESET_TAG;
pub const FACT_COMMITMENT_FACT_ORDER: [&str; 16] = [
    "eligibility_active",
    "aid_code",
    "benefit_level_exists",
    "date_of_service_from",
    "eligibility_period_from",
    "eligibility_period_thru",
    "soc_amount",
    "soc_met",
    "provider_enrolled",
    "provider_type_valid",
    "billing_code_valid",
    "units_valid",
    "is_duplicate",
    "disability_determination_valid",
    "recipient_not_deceased",
    "physician_certification_valid",
];
pub const PUBLIC_INPUT_ROOT_PREIMAGE_ORDER: [&str; 26] = [
    "claim_hash_be_u32_limb_0",
    "claim_hash_be_u32_limb_1",
    "claim_hash_be_u32_limb_2",
    "claim_hash_be_u32_limb_3",
    "claim_hash_be_u32_limb_4",
    "claim_hash_be_u32_limb_5",
    "claim_hash_be_u32_limb_6",
    "claim_hash_be_u32_limb_7",
    "fact_commitment_element_0",
    "fact_commitment_element_1",
    "fact_commitment_element_2",
    "fact_commitment_element_3",
    "claim_source_root_element_0",
    "claim_source_root_element_1",
    "claim_source_root_element_2",
    "claim_source_root_element_3",
    "oracle_facts_root_element_0",
    "oracle_facts_root_element_1",
    "oracle_facts_root_element_2",
    "oracle_facts_root_element_3",
    "fee_schedule_root_element_0",
    "fee_schedule_root_element_1",
    "fee_schedule_root_element_2",
    "fee_schedule_root_element_3",
    "decision",
    "failure_code",
];

const CLAIM_HASH_LIMB_COUNT: usize = 8;
const FACT_COMMITMENT_WIDTH: usize = 4;
const FACT_COMMITMENT_PREIMAGE_LENGTH: usize = 28;
pub const CLAIM_SOURCE_ROOT_WIDTH: usize = 4;
pub const ORACLE_FACTS_ROOT_WIDTH: usize = 4;
pub const FEE_SCHEDULE_ROOT_WIDTH: usize = 4;
const PUBLIC_INPUT_ROOT_WIDTH: usize = 4;
const PUBLIC_INPUT_ROOT_PREIMAGE_LENGTH: usize = 30;
const FACT_COUNT: u64 = 16;
const PUBLIC_INPUT_ROOT_ELEMENT_COUNT: u64 = 26;
const FACT_HASH_TRACE_LENGTH: usize = 32;
const CLAIM_SOURCE_LEAF_TRACE_START: usize = FACT_HASH_TRACE_LENGTH;
const CLAIM_SOURCE_LEAF_TRACE_LENGTH: usize = 40;
const CLAIM_SOURCE_MERKLE_TRACE_START: usize =
    CLAIM_SOURCE_LEAF_TRACE_START + CLAIM_SOURCE_LEAF_TRACE_LENGTH;
const CLAIM_SOURCE_MERKLE_LEVEL_LENGTH: usize = 8;
const CLAIM_SOURCE_MERKLE_TRACE_LENGTH: usize =
    CLAIM_SOURCE_ROOT_TREE_DEPTH * CLAIM_SOURCE_MERKLE_LEVEL_LENGTH;
const ORACLE_FACTS_LEAF_TRACE_START: usize =
    CLAIM_SOURCE_MERKLE_TRACE_START + CLAIM_SOURCE_MERKLE_TRACE_LENGTH;
const ORACLE_FACTS_LEAF_TRACE_LENGTH: usize = 32;
const ORACLE_FACTS_MERKLE_TRACE_START: usize =
    ORACLE_FACTS_LEAF_TRACE_START + ORACLE_FACTS_LEAF_TRACE_LENGTH;
const ORACLE_FACTS_MERKLE_LEVEL_LENGTH: usize = 8;
const ORACLE_FACTS_MERKLE_TRACE_LENGTH: usize =
    ORACLE_FACTS_ROOT_TREE_DEPTH * ORACLE_FACTS_MERKLE_LEVEL_LENGTH;
const FEE_SCHEDULE_LEAF_TRACE_START: usize =
    ORACLE_FACTS_MERKLE_TRACE_START + ORACLE_FACTS_MERKLE_TRACE_LENGTH;
const FEE_SCHEDULE_LEAF_TRACE_LENGTH: usize = 32;
const FEE_SCHEDULE_MERKLE_TRACE_START: usize =
    FEE_SCHEDULE_LEAF_TRACE_START + FEE_SCHEDULE_LEAF_TRACE_LENGTH;
const FEE_SCHEDULE_MERKLE_LEVEL_LENGTH: usize = 8;
const FEE_SCHEDULE_MERKLE_TRACE_LENGTH: usize =
    FEE_SCHEDULE_ROOT_TREE_DEPTH * FEE_SCHEDULE_MERKLE_LEVEL_LENGTH;
const PUBLIC_ROOT_TRACE_START: usize =
    FEE_SCHEDULE_MERKLE_TRACE_START + FEE_SCHEDULE_MERKLE_TRACE_LENGTH;
const RESCUE_STATE_WIDTH: usize = 12;
const RESCUE_RATE_START: usize = 4;
const RESCUE_RATE_WIDTH: usize = 8;
const RESCUE_ROUND_COUNT: usize = 7;
const HASH_ROUND_SELECTOR_COUNT: usize = RESCUE_ROUND_COUNT;
const FACT_HASH_ABSORB_SELECTOR_COUNT: usize = 3;
const CLAIM_SOURCE_LEAF_ABSORB_SELECTOR_COUNT: usize = 4;
const ORACLE_FACTS_LEAF_ABSORB_SELECTOR_COUNT: usize = 3;
const FEE_SCHEDULE_LEAF_ABSORB_SELECTOR_COUNT: usize = 3;
const PUBLIC_ROOT_ABSORB_SELECTOR_COUNT: usize = 3;
const FACT_HASH_ABSORB_SELECTOR_START: usize = HASH_ROUND_SELECTOR_COUNT;
const CLAIM_SOURCE_LEAF_ABSORB_SELECTOR_START: usize =
    FACT_HASH_ABSORB_SELECTOR_START + FACT_HASH_ABSORB_SELECTOR_COUNT;
const CLAIM_SOURCE_LEAF_RESET_SELECTOR: usize =
    CLAIM_SOURCE_LEAF_ABSORB_SELECTOR_START + CLAIM_SOURCE_LEAF_ABSORB_SELECTOR_COUNT;
const CLAIM_SOURCE_MERKLE_RESET_SELECTOR_START: usize = CLAIM_SOURCE_LEAF_RESET_SELECTOR + 1;
const ORACLE_FACTS_LEAF_ABSORB_SELECTOR_START: usize =
    CLAIM_SOURCE_MERKLE_RESET_SELECTOR_START + CLAIM_SOURCE_ROOT_TREE_DEPTH;
const ORACLE_FACTS_LEAF_RESET_SELECTOR: usize =
    ORACLE_FACTS_LEAF_ABSORB_SELECTOR_START + ORACLE_FACTS_LEAF_ABSORB_SELECTOR_COUNT;
const ORACLE_FACTS_MERKLE_RESET_SELECTOR_START: usize = ORACLE_FACTS_LEAF_RESET_SELECTOR + 1;
const FEE_SCHEDULE_LEAF_ABSORB_SELECTOR_START: usize =
    ORACLE_FACTS_MERKLE_RESET_SELECTOR_START + ORACLE_FACTS_ROOT_TREE_DEPTH;
const FEE_SCHEDULE_LEAF_RESET_SELECTOR: usize =
    FEE_SCHEDULE_LEAF_ABSORB_SELECTOR_START + FEE_SCHEDULE_LEAF_ABSORB_SELECTOR_COUNT;
const FEE_SCHEDULE_MERKLE_RESET_SELECTOR_START: usize = FEE_SCHEDULE_LEAF_RESET_SELECTOR + 1;
const PUBLIC_ROOT_ABSORB_SELECTOR_START: usize =
    FEE_SCHEDULE_MERKLE_RESET_SELECTOR_START + FEE_SCHEDULE_ROOT_TREE_DEPTH;
const PUBLIC_ROOT_RESET_SELECTOR: usize =
    PUBLIC_ROOT_ABSORB_SELECTOR_START + PUBLIC_ROOT_ABSORB_SELECTOR_COUNT;
const PUBLIC_ROOT_HOLD_SELECTOR: usize = PUBLIC_ROOT_RESET_SELECTOR + 1;
const HASH_PERIODIC_COLUMN_COUNT: usize = PUBLIC_ROOT_HOLD_SELECTOR + 1;

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
const GATES_START: usize = 24;
const PREFIXES_START: usize = 37;
const COL_DATE_GE_FROM: usize = 50;
const COL_DATE_LE_THRU: usize = 51;
const COL_DATE_GE_DIFF: usize = 52;
const COL_DATE_LE_DIFF: usize = 53;
const COL_SOC_ZERO: usize = 54;
const COL_SOC_INVERSE: usize = 55;
const COL_AID_PRODUCT_INVERSE: usize = 56;
const COL_DECISION: usize = 57;
const COL_FAILURE_CODE: usize = 58;
const DATE_GE_DIFF_BITS_START: usize = 59;
const DATE_LE_DIFF_BITS_START: usize = 91;
const COL_CLOCK: usize = 123;
const HASH_STATE_START: usize = 124;
const FACT_COMMITMENT_RESULT_START: usize = 136;
const CLAIM_SOURCE_PREIMAGE_START: usize = 140;
const CLAIM_SOURCE_PATH_START: usize =
    CLAIM_SOURCE_PREIMAGE_START + CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH;
const CLAIM_SOURCE_ROOT_RESULT_START: usize =
    CLAIM_SOURCE_PATH_START + CLAIM_SOURCE_ROOT_TREE_DEPTH * CLAIM_SOURCE_ROOT_WIDTH;
const ORACLE_FACTS_PREIMAGE_START: usize = CLAIM_SOURCE_PREIMAGE_START;
const ORACLE_FACTS_PATH_START: usize = CLAIM_SOURCE_PATH_START;
const ORACLE_FACTS_ROOT_RESULT_START: usize =
    CLAIM_SOURCE_ROOT_RESULT_START + CLAIM_SOURCE_ROOT_WIDTH;
const FEE_SCHEDULE_PREIMAGE_START: usize = CLAIM_SOURCE_PREIMAGE_START;
const FEE_SCHEDULE_PATH_START: usize = CLAIM_SOURCE_PATH_START;
const FEE_SCHEDULE_ROOT_RESULT_START: usize =
    ORACLE_FACTS_ROOT_RESULT_START + ORACLE_FACTS_ROOT_WIDTH;
const COL_CLAIM_SOURCE_DATE_BINDING: usize =
    FEE_SCHEDULE_ROOT_RESULT_START + FEE_SCHEDULE_ROOT_WIDTH;
const CLAIM_SOURCE_SERVICE_LINES_DIGEST_BINDING_START: usize = COL_CLAIM_SOURCE_DATE_BINDING + 1;
const COL_CLAIM_SOURCE_TOTAL_CHARGE_BINDING: usize =
    CLAIM_SOURCE_SERVICE_LINES_DIGEST_BINDING_START + 4;

pub const TRACE_WIDTH: usize = COL_CLAIM_SOURCE_TOTAL_CHARGE_BINDING + 1;
const GATE_COUNT: usize = 13;
const RANGE_BITS: usize = 32;
const BASE_SEMANTIC_CONSTRAINT_COUNT: usize = 129;
const CLAIM_SOURCE_LINK_CONSTRAINT_COUNT: usize = 1;
const ORACLE_FACTS_LINK_CONSTRAINT_COUNT: usize = 0;
const FEE_SCHEDULE_LINK_CONSTRAINT_COUNT: usize = 0;
const SEMANTIC_CONSTRAINT_COUNT: usize = BASE_SEMANTIC_CONSTRAINT_COUNT
    + CLAIM_SOURCE_LINK_CONSTRAINT_COUNT
    + ORACLE_FACTS_LINK_CONSTRAINT_COUNT
    + FEE_SCHEDULE_LINK_CONSTRAINT_COUNT;
const COMMITMENT_BOUND_COLUMN_COUNT: usize = 16
    + CLAIM_HASH_LIMB_COUNT
    + FACT_COMMITMENT_WIDTH
    + CLAIM_SOURCE_ROOT_WIDTH
    + ORACLE_FACTS_ROOT_WIDTH
    + FEE_SCHEDULE_ROOT_WIDTH
    + 1
    + 4
    + 1;
const HASH_CONSTRAINT_COUNT: usize = RESCUE_STATE_WIDTH;
const FACT_COMMITMENT_BIND_CONSTRAINT_COUNT: usize = FACT_COMMITMENT_WIDTH;
const CLAIM_SOURCE_ROOT_BIND_CONSTRAINT_COUNT: usize = CLAIM_SOURCE_ROOT_WIDTH;
const ORACLE_FACTS_ROOT_BIND_CONSTRAINT_COUNT: usize = ORACLE_FACTS_ROOT_WIDTH;
const FEE_SCHEDULE_ROOT_BIND_CONSTRAINT_COUNT: usize = FEE_SCHEDULE_ROOT_WIDTH;
const TRANSITION_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT
    + COMMITMENT_BOUND_COLUMN_COUNT
    + HASH_CONSTRAINT_COUNT
    + FACT_COMMITMENT_BIND_CONSTRAINT_COUNT
    + CLAIM_SOURCE_ROOT_BIND_CONSTRAINT_COUNT
    + ORACLE_FACTS_ROOT_BIND_CONSTRAINT_COUNT
    + FEE_SCHEDULE_ROOT_BIND_CONSTRAINT_COUNT
    + 1;
const CLAIM_SOURCE_FIXED_ASSERTION_COUNT: usize = 8;
const ORACLE_FACTS_FIXED_ASSERTION_COUNT: usize = 9;
const FEE_SCHEDULE_FIXED_ASSERTION_COUNT: usize = 7;
const PUBLIC_ASSERTION_COUNT: usize = CLAIM_HASH_LIMB_COUNT
    + 2
    + 1
    + RESCUE_STATE_WIDTH
    + PUBLIC_INPUT_ROOT_WIDTH
    + CLAIM_SOURCE_ROOT_WIDTH
    + ORACLE_FACTS_ROOT_WIDTH
    + FEE_SCHEDULE_ROOT_WIDTH
    + CLAIM_SOURCE_FIXED_ASSERTION_COUNT
    + ORACLE_FACTS_FIXED_ASSERTION_COUNT
    + FEE_SCHEDULE_FIXED_ASSERTION_COUNT
    + CLAIM_HASH_LIMB_COUNT * 3;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionAirProofInputV4 {
    pub adjudication: ProductionAirInputV1,
    pub claim_source: ProductionClaimSourceWitnessV2,
    pub oracle_facts: ProductionOracleFactsWitnessV3,
    pub fee_schedule: ProductionFeeScheduleWitnessV4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionClaimSourceWitnessV2 {
    pub leaf_preimage: [ProductionFelt; CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH],
    pub merkle_path: [[ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH]; CLAIM_SOURCE_ROOT_TREE_DEPTH],
    pub root: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionOracleFactsWitnessV3 {
    pub leaf_preimage: [ProductionFelt; ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH],
    pub merkle_path: [[ProductionFelt; ORACLE_FACTS_ROOT_WIDTH]; ORACLE_FACTS_ROOT_TREE_DEPTH],
    pub root: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionFeeScheduleWitnessV4 {
    pub leaf_preimage: [ProductionFelt; FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH],
    pub merkle_path: [[ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH]; FEE_SCHEDULE_ROOT_TREE_DEPTH],
    pub root: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH],
}

#[derive(Clone, Copy, Debug)]
pub struct ProductionAirPublicInputsV4 {
    pub claim_hash_limbs: [ProductionFelt; CLAIM_HASH_LIMB_COUNT],
    pub public_input_root: [ProductionFelt; PUBLIC_INPUT_ROOT_WIDTH],
    pub claim_source_root: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH],
    pub oracle_facts_root: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH],
    pub fee_schedule_root: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH],
    pub decision: ProductionFelt,
    pub failure_code: ProductionFelt,
}

pub type ProductionAirProofInputV3 = ProductionAirProofInputV4;
pub type ProductionAirProofInputV2 = ProductionAirProofInputV4;
pub type ProductionAirPublicInputsV3 = ProductionAirPublicInputsV4;
pub type ProductionAirPublicInputsV2 = ProductionAirPublicInputsV4;
pub type ProductionAirPublicInputsV1 = ProductionAirPublicInputsV4;

impl ToElements<ProductionFelt> for ProductionAirPublicInputsV4 {
    fn to_elements(&self) -> Vec<ProductionFelt> {
        let mut elements = self.claim_hash_limbs.to_vec();
        elements.extend(self.public_input_root);
        elements.extend(self.claim_source_root);
        elements.extend(self.oracle_facts_root);
        elements.extend(self.fee_schedule_root);
        elements.push(self.decision);
        elements.push(self.failure_code);
        elements
    }
}

impl ProductionAirProofInputV4 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-air-proof-input-v4";

    pub fn from_bridge_input(bridge: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        let adjudication = ProductionAirInputV1::from_bridge_input(bridge)?;
        let claim_source_artifact = ProductionClaimSourceRootArtifactV1::from_bridge_input(bridge)?;
        let (leaf_preimage, merkle_path, root) = claim_source_artifact.air_witness_components()?;
        let oracle_facts_artifact = ProductionOracleFactsRootArtifactV1::from_bridge_input(bridge)?;
        let (oracle_leaf_preimage, oracle_merkle_path, oracle_root) =
            oracle_facts_artifact.air_witness_components()?;
        let fee_schedule_artifact = ProductionFeeScheduleRootArtifactV1::from_bridge_input(bridge)?;
        let (fee_leaf_preimage, fee_merkle_path, fee_root) =
            fee_schedule_artifact.air_witness_components()?;
        let input = Self {
            adjudication,
            claim_source: ProductionClaimSourceWitnessV2 {
                leaf_preimage,
                merkle_path,
                root,
            },
            oracle_facts: ProductionOracleFactsWitnessV3 {
                leaf_preimage: oracle_leaf_preimage,
                merkle_path: oracle_merkle_path,
                root: oracle_root,
            },
            fee_schedule: ProductionFeeScheduleWitnessV4 {
                leaf_preimage: fee_leaf_preimage,
                merkle_path: fee_merkle_path,
                root: fee_root,
            },
        };
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if let Err(mut input_errors) = self.adjudication.validate() {
            errors.append(&mut input_errors);
        }
        if let Err(mut witness_errors) = self.claim_source.validate(&self.adjudication) {
            errors.append(&mut witness_errors);
        }
        if let Err(mut witness_errors) = self.oracle_facts.validate(&self.adjudication) {
            errors.append(&mut witness_errors);
        }
        if let Err(mut witness_errors) = self
            .fee_schedule
            .validate(&self.adjudication, &self.claim_source)
        {
            errors.append(&mut witness_errors);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ProductionOracleFactsWitnessV3 {
    pub fn validate(&self, adjudication: &ProductionAirInputV1) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let expected_header = [
            felt(ORACLE_FACTS_ROOT_DOMAIN_TAG),
            felt(ORACLE_FACTS_ROOT_SCHEMA_TAG),
            felt(ORACLE_FACTS_ROOT_HASH_TAG),
            felt(ORACLE_FACTS_ROOT_NORMALIZATION_TAG),
        ];
        if self.leaf_preimage[..4] != expected_header {
            errors.push("oracle-facts leaf header is not canonical".to_string());
        }
        if self.leaf_preimage[24..27] != [ProductionFelt::ONE; 3] {
            errors.push("oracle-facts presence flags must all be one".to_string());
        }
        if self.leaf_preimage[30..32] != [ProductionFelt::ZERO; 2] {
            errors.push("oracle-facts reserved fields must be zero".to_string());
        }
        if self.leaf_preimage[27] == ProductionFelt::ZERO
            || self.leaf_preimage[28] == ProductionFelt::ZERO
            || self.leaf_preimage[29] != self.leaf_preimage[27]
        {
            errors.push(
                "oracle-facts counts must be nonzero and all facts must be verified".to_string(),
            );
        }

        match parse_claim_hash_limbs(&adjudication.claim_hash) {
            Ok(claim_hash_limbs) if self.leaf_preimage[4..12] != claim_hash_limbs => {
                errors.push(
                    "oracle-facts leaf claim hash limbs do not match adjudication claim hash"
                        .to_string(),
                );
            }
            Ok(_) => {}
            Err(mut claim_hash_errors) => errors.append(&mut claim_hash_errors),
        }

        let leaf = Rp64_256::hash_elements(&self.leaf_preimage);
        let mut current: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH] = leaf
            .as_elements()
            .try_into()
            .expect("Rp64_256 digest must contain four field elements");
        for (level, sibling) in self.merkle_path.iter().enumerate() {
            current = merge_oracle_facts_level(current, *sibling, level);
        }
        if current != self.root {
            errors.push("oracle-facts Merkle path does not produce the supplied root".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ProductionFeeScheduleWitnessV4 {
    pub fn validate(
        &self,
        adjudication: &ProductionAirInputV1,
        claim_source: &ProductionClaimSourceWitnessV2,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let expected_header = [
            felt(FEE_SCHEDULE_ROOT_DOMAIN_TAG),
            felt(FEE_SCHEDULE_ROOT_SCHEMA_TAG),
            felt(FEE_SCHEDULE_ROOT_HASH_TAG),
            felt(FEE_SCHEDULE_ROOT_NORMALIZATION_TAG),
        ];
        if self.leaf_preimage[..4] != expected_header {
            errors.push("fee-schedule leaf header is not canonical".to_string());
        }
        if self.leaf_preimage[24..27] != [ProductionFelt::ONE; 3] {
            errors.push("fee-schedule presence flags must all be one".to_string());
        }
        if self.leaf_preimage[27] == ProductionFelt::ZERO
            || self.leaf_preimage[28] == ProductionFelt::ZERO
        {
            errors.push("fee-schedule entry and match counts must be nonzero".to_string());
        }

        match parse_claim_hash_limbs(&adjudication.claim_hash) {
            Ok(claim_hash_limbs) if self.leaf_preimage[4..12] != claim_hash_limbs => {
                errors.push(
                    "fee-schedule leaf claim hash limbs do not match adjudication claim hash"
                        .to_string(),
                );
            }
            Ok(_) => {}
            Err(mut claim_hash_errors) => errors.append(&mut claim_hash_errors),
        }
        if self.leaf_preimage[20..24] != claim_source.leaf_preimage[28..32] {
            errors.push(
                "fee-schedule service-line digest does not match claim-source leaf".to_string(),
            );
        }
        if self.leaf_preimage[29].as_int() != adjudication.facts.date_of_service_from
            || self.leaf_preimage[29] != claim_source.leaf_preimage[27]
        {
            errors.push(
                "fee-schedule service date does not match adjudication and claim-source leaf"
                    .to_string(),
            );
        }
        if self.leaf_preimage[31] != claim_source.leaf_preimage[26] {
            errors.push(
                "fee-schedule charged amount does not match claim-source total charge".to_string(),
            );
        }
        if self.leaf_preimage[30].as_int() < self.leaf_preimage[31].as_int() {
            errors.push("fee-schedule allowed amount must cover charged amount".to_string());
        }

        let leaf = Rp64_256::hash_elements(&self.leaf_preimage);
        let mut current: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH] = leaf
            .as_elements()
            .try_into()
            .expect("Rp64_256 digest must contain four field elements");
        for (level, sibling) in self.merkle_path.iter().enumerate() {
            current = merge_fee_schedule_level(current, *sibling, level);
        }
        if current != self.root {
            errors.push("fee-schedule Merkle path does not produce the supplied root".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ProductionClaimSourceWitnessV2 {
    pub fn validate(&self, adjudication: &ProductionAirInputV1) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let expected_header = [
            felt(CLAIM_SOURCE_ROOT_DOMAIN_TAG),
            felt(CLAIM_SOURCE_ROOT_SCHEMA_TAG),
            felt(CLAIM_SOURCE_ROOT_HASH_TAG),
            felt(CLAIM_SOURCE_ROOT_UNIT_TAG),
        ];
        if self.leaf_preimage[..4] != expected_header {
            errors.push("claim-source leaf header is not canonical".to_string());
        }
        if self.leaf_preimage[20..24] != [ProductionFelt::ONE; 4] {
            errors.push("claim-source presence flags must all be one".to_string());
        }

        match parse_claim_hash_limbs(&adjudication.claim_hash) {
            Ok(claim_hash_limbs) if self.leaf_preimage[4..12] != claim_hash_limbs => {
                errors.push(
                    "claim-source leaf claim hash limbs do not match adjudication claim hash"
                        .to_string(),
                );
            }
            Ok(_) => {}
            Err(mut claim_hash_errors) => errors.append(&mut claim_hash_errors),
        }
        if self.leaf_preimage[27].as_int() != adjudication.facts.date_of_service_from {
            errors.push(
                "claim-source leaf service date does not match adjudication date_of_service_from"
                    .to_string(),
            );
        }

        let leaf = Rp64_256::hash_elements(&self.leaf_preimage);
        let mut current: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH] = leaf
            .as_elements()
            .try_into()
            .expect("Rp64_256 digest must contain four field elements");
        for (level, sibling) in self.merkle_path.iter().enumerate() {
            current = merge_claim_source_level(current, *sibling, level);
        }
        if current != self.root {
            errors.push("claim-source Merkle path does not produce the supplied root".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub struct ProductionG1G10Air {
    context: AirContext<ProductionFelt>,
    public_inputs: ProductionAirPublicInputsV4,
}

impl Air for ProductionG1G10Air {
    type BaseField = ProductionFelt;
    type PublicInputs = ProductionAirPublicInputsV4;

    fn new(
        trace_info: TraceInfo,
        public_inputs: Self::PublicInputs,
        options: ProofOptions,
    ) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width());
        Self {
            context: AirContext::new(
                trace_info,
                transition_degrees(),
                PUBLIC_ASSERTION_COUNT,
                options,
            ),
            public_inputs,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let one = E::ONE;
        let mut index = 0;
        debug_assert_eq!(periodic_values.len(), HASH_PERIODIC_COLUMN_COUNT);

        for column in boolean_columns() {
            let value = current[column];
            result[index] = value * (value - one);
            index += 1;
        }

        for bits_start in [DATE_GE_DIFF_BITS_START, DATE_LE_DIFF_BITS_START] {
            for bit in 0..RANGE_BITS {
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

        debug_assert_eq!(index, BASE_SEMANTIC_CONSTRAINT_COUNT);

        result[index] = current[COL_CLAIM_SOURCE_DATE_BINDING] - current[COL_DATE_OF_SERVICE_FROM];
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

        for (bound_index, column) in commitment_bound_columns().into_iter().enumerate() {
            result[index] = next[column] - current[column]
                + clock_transition * E::from((bound_index + 1) as u32);
            index += 1;
        }
        let current_hash: [E; RESCUE_STATE_WIDTH] =
            core::array::from_fn(|offset| current[HASH_STATE_START + offset]);
        let next_hash: [E; RESCUE_STATE_WIDTH] =
            core::array::from_fn(|offset| next[HASH_STATE_START + offset]);
        let round_constraints: [[E; RESCUE_STATE_WIDTH]; RESCUE_ROUND_COUNT] =
            core::array::from_fn(|round| {
                rescue_round_constraints(&current_hash, &next_hash, round)
            });
        let fact_absorption_blocks = [
            commitment_absorption_block(current, 1),
            commitment_absorption_block(current, 2),
            commitment_absorption_block(current, 3),
        ];
        let claim_source_leaf_absorption_blocks = [
            claim_source_leaf_absorption_block(current, 1),
            claim_source_leaf_absorption_block(current, 2),
            claim_source_leaf_absorption_block(current, 3),
            claim_source_leaf_absorption_block(current, 4),
        ];
        let oracle_facts_leaf_absorption_blocks = [
            oracle_facts_leaf_absorption_block(current, 1),
            oracle_facts_leaf_absorption_block(current, 2),
            oracle_facts_leaf_absorption_block(current, 3),
        ];
        let fee_schedule_leaf_absorption_blocks = [
            fee_schedule_leaf_absorption_block(current, 1),
            fee_schedule_leaf_absorption_block(current, 2),
            fee_schedule_leaf_absorption_block(current, 3),
        ];
        let public_root_absorption_blocks = [
            public_input_root_absorption_block(current, 1),
            public_input_root_absorption_block(current, 2),
            public_input_root_absorption_block(current, 3),
        ];
        let claim_source_leaf_initial_state = initial_claim_source_leaf_hash_state(current);
        let oracle_facts_leaf_initial_state = initial_oracle_facts_leaf_hash_state(current);
        let fee_schedule_leaf_initial_state = initial_fee_schedule_leaf_hash_state(current);
        let public_root_initial_state = initial_public_input_root_hash_state(current);

        let mut hash_degree_adjustment = clock_transition;
        for _ in 0..6 {
            hash_degree_adjustment *= current[COL_CLOCK];
        }
        hash_degree_adjustment *= periodic_values[FACT_HASH_ABSORB_SELECTOR_START];

        for state_index in 0..RESCUE_STATE_WIDTH {
            let mut constraint = E::ZERO;
            for round in 0..RESCUE_ROUND_COUNT {
                constraint += periodic_values[round] * round_constraints[round][state_index];
            }
            for (block_index, block) in fact_absorption_blocks.iter().enumerate() {
                let absorbed = if (RESCUE_RATE_START..RESCUE_RATE_START + RESCUE_RATE_WIDTH)
                    .contains(&state_index)
                {
                    block[state_index - RESCUE_RATE_START]
                } else {
                    E::ZERO
                };
                constraint += periodic_values[FACT_HASH_ABSORB_SELECTOR_START + block_index]
                    * (next_hash[state_index] - current_hash[state_index] - absorbed);
            }
            for (block_index, block) in claim_source_leaf_absorption_blocks.iter().enumerate() {
                let absorbed = if (RESCUE_RATE_START..RESCUE_RATE_START + RESCUE_RATE_WIDTH)
                    .contains(&state_index)
                {
                    block[state_index - RESCUE_RATE_START]
                } else {
                    E::ZERO
                };
                constraint += periodic_values
                    [CLAIM_SOURCE_LEAF_ABSORB_SELECTOR_START + block_index]
                    * (next_hash[state_index] - current_hash[state_index] - absorbed);
            }
            constraint += periodic_values[CLAIM_SOURCE_LEAF_RESET_SELECTOR]
                * (next_hash[state_index] - claim_source_leaf_initial_state[state_index]);
            for level in 0..CLAIM_SOURCE_ROOT_TREE_DEPTH {
                let merge_initial_state = initial_claim_source_merkle_state(current, level);
                constraint += periodic_values[CLAIM_SOURCE_MERKLE_RESET_SELECTOR_START + level]
                    * (next_hash[state_index] - merge_initial_state[state_index]);
            }
            for (block_index, block) in oracle_facts_leaf_absorption_blocks.iter().enumerate() {
                let absorbed = if (RESCUE_RATE_START..RESCUE_RATE_START + RESCUE_RATE_WIDTH)
                    .contains(&state_index)
                {
                    block[state_index - RESCUE_RATE_START]
                } else {
                    E::ZERO
                };
                constraint += periodic_values
                    [ORACLE_FACTS_LEAF_ABSORB_SELECTOR_START + block_index]
                    * (next_hash[state_index] - current_hash[state_index] - absorbed);
            }
            constraint += periodic_values[ORACLE_FACTS_LEAF_RESET_SELECTOR]
                * (next_hash[state_index] - oracle_facts_leaf_initial_state[state_index]);
            for level in 0..ORACLE_FACTS_ROOT_TREE_DEPTH {
                let merge_initial_state = initial_oracle_facts_merkle_state(current, level);
                constraint += periodic_values[ORACLE_FACTS_MERKLE_RESET_SELECTOR_START + level]
                    * (next_hash[state_index] - merge_initial_state[state_index]);
            }
            for (block_index, block) in fee_schedule_leaf_absorption_blocks.iter().enumerate() {
                let absorbed = if (RESCUE_RATE_START..RESCUE_RATE_START + RESCUE_RATE_WIDTH)
                    .contains(&state_index)
                {
                    block[state_index - RESCUE_RATE_START]
                } else {
                    E::ZERO
                };
                constraint += periodic_values
                    [FEE_SCHEDULE_LEAF_ABSORB_SELECTOR_START + block_index]
                    * (next_hash[state_index] - current_hash[state_index] - absorbed);
            }
            constraint += periodic_values[FEE_SCHEDULE_LEAF_RESET_SELECTOR]
                * (next_hash[state_index] - fee_schedule_leaf_initial_state[state_index]);
            for level in 0..FEE_SCHEDULE_ROOT_TREE_DEPTH {
                let merge_initial_state = initial_fee_schedule_merkle_state(current, level);
                constraint += periodic_values[FEE_SCHEDULE_MERKLE_RESET_SELECTOR_START + level]
                    * (next_hash[state_index] - merge_initial_state[state_index]);
            }
            for (block_index, block) in public_root_absorption_blocks.iter().enumerate() {
                let absorbed = if (RESCUE_RATE_START..RESCUE_RATE_START + RESCUE_RATE_WIDTH)
                    .contains(&state_index)
                {
                    block[state_index - RESCUE_RATE_START]
                } else {
                    E::ZERO
                };
                constraint += periodic_values[PUBLIC_ROOT_ABSORB_SELECTOR_START + block_index]
                    * (next_hash[state_index] - current_hash[state_index] - absorbed);
            }
            constraint += periodic_values[PUBLIC_ROOT_RESET_SELECTOR]
                * (next_hash[state_index] - public_root_initial_state[state_index]);
            constraint += periodic_values[PUBLIC_ROOT_HOLD_SELECTOR]
                * (next_hash[state_index] - current_hash[state_index]);
            constraint += hash_degree_adjustment * E::from((state_index + 1) as u32);
            result[index] = constraint;
            index += 1;
        }

        for digest_index in 0..FACT_COMMITMENT_WIDTH {
            result[index] = periodic_values[CLAIM_SOURCE_LEAF_RESET_SELECTOR]
                * (current[HASH_STATE_START + RESCUE_RATE_START + digest_index]
                    - current[FACT_COMMITMENT_RESULT_START + digest_index]);
            index += 1;
        }

        for digest_index in 0..CLAIM_SOURCE_ROOT_WIDTH {
            result[index] = periodic_values[ORACLE_FACTS_LEAF_RESET_SELECTOR]
                * (current[HASH_STATE_START + RESCUE_RATE_START + digest_index]
                    - current[CLAIM_SOURCE_ROOT_RESULT_START + digest_index]);
            index += 1;
        }
        for digest_index in 0..ORACLE_FACTS_ROOT_WIDTH {
            result[index] = periodic_values[FEE_SCHEDULE_LEAF_RESET_SELECTOR]
                * (current[HASH_STATE_START + RESCUE_RATE_START + digest_index]
                    - current[ORACLE_FACTS_ROOT_RESULT_START + digest_index]);
            index += 1;
        }
        for digest_index in 0..FEE_SCHEDULE_ROOT_WIDTH {
            result[index] = periodic_values[PUBLIC_ROOT_RESET_SELECTOR]
                * (current[HASH_STATE_START + RESCUE_RATE_START + digest_index]
                    - current[FEE_SCHEDULE_ROOT_RESULT_START + digest_index]);
            index += 1;
        }

        result[index] = clock_transition;
        index += 1;

        debug_assert_eq!(index, TRANSITION_CONSTRAINT_COUNT);
        debug_assert_eq!(index, result.len());
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(PUBLIC_ASSERTION_COUNT);
        for (limb, value) in self.public_inputs.claim_hash_limbs.iter().enumerate() {
            assertions.push(Assertion::single(CLAIM_HASH_LIMBS_START + limb, 0, *value));
            assertions.push(Assertion::single(
                CLAIM_SOURCE_PREIMAGE_START + 4 + limb,
                0,
                *value,
            ));
            assertions.push(Assertion::single(
                ORACLE_FACTS_PREIMAGE_START + 4 + limb,
                ORACLE_FACTS_LEAF_TRACE_START - 1,
                *value,
            ));
            assertions.push(Assertion::single(
                FEE_SCHEDULE_PREIMAGE_START + 4 + limb,
                FEE_SCHEDULE_LEAF_TRACE_START - 1,
                *value,
            ));
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

        let first_claim_hash_limbs: [ProductionFelt; 4] = self.public_inputs.claim_hash_limbs[..4]
            .try_into()
            .expect("first four claim hash limbs");
        let initial_hash_state = initial_commitment_hash_state(&first_claim_hash_limbs);
        for (state_index, value) in initial_hash_state.into_iter().enumerate() {
            assertions.push(Assertion::single(HASH_STATE_START + state_index, 0, value));
        }
        for (digest_index, value) in self.public_inputs.public_input_root.iter().enumerate() {
            assertions.push(Assertion::single(
                HASH_STATE_START + RESCUE_RATE_START + digest_index,
                TRACE_LENGTH - 1,
                *value,
            ));
        }
        for (digest_index, value) in self.public_inputs.claim_source_root.iter().enumerate() {
            assertions.push(Assertion::single(
                CLAIM_SOURCE_ROOT_RESULT_START + digest_index,
                0,
                *value,
            ));
        }
        for (digest_index, value) in self.public_inputs.oracle_facts_root.iter().enumerate() {
            assertions.push(Assertion::single(
                ORACLE_FACTS_ROOT_RESULT_START + digest_index,
                0,
                *value,
            ));
        }
        for (digest_index, value) in self.public_inputs.fee_schedule_root.iter().enumerate() {
            assertions.push(Assertion::single(
                FEE_SCHEDULE_ROOT_RESULT_START + digest_index,
                0,
                *value,
            ));
        }
        for (offset, value) in [
            (0, felt(CLAIM_SOURCE_ROOT_DOMAIN_TAG)),
            (1, felt(CLAIM_SOURCE_ROOT_SCHEMA_TAG)),
            (2, felt(CLAIM_SOURCE_ROOT_HASH_TAG)),
            (3, felt(CLAIM_SOURCE_ROOT_UNIT_TAG)),
            (20, ProductionFelt::ONE),
            (21, ProductionFelt::ONE),
            (22, ProductionFelt::ONE),
            (23, ProductionFelt::ONE),
        ] {
            assertions.push(Assertion::single(
                CLAIM_SOURCE_PREIMAGE_START + offset,
                0,
                value,
            ));
        }
        for (offset, value) in [
            (0, felt(FEE_SCHEDULE_ROOT_DOMAIN_TAG)),
            (1, felt(FEE_SCHEDULE_ROOT_SCHEMA_TAG)),
            (2, felt(FEE_SCHEDULE_ROOT_HASH_TAG)),
            (3, felt(FEE_SCHEDULE_ROOT_NORMALIZATION_TAG)),
            (24, ProductionFelt::ONE),
            (25, ProductionFelt::ONE),
            (26, ProductionFelt::ONE),
        ] {
            assertions.push(Assertion::single(
                FEE_SCHEDULE_PREIMAGE_START + offset,
                FEE_SCHEDULE_LEAF_TRACE_START - 1,
                value,
            ));
        }
        for (offset, value) in [
            (0, felt(ORACLE_FACTS_ROOT_DOMAIN_TAG)),
            (1, felt(ORACLE_FACTS_ROOT_SCHEMA_TAG)),
            (2, felt(ORACLE_FACTS_ROOT_HASH_TAG)),
            (3, felt(ORACLE_FACTS_ROOT_NORMALIZATION_TAG)),
            (24, ProductionFelt::ONE),
            (25, ProductionFelt::ONE),
            (26, ProductionFelt::ONE),
            (30, ProductionFelt::ZERO),
            (31, ProductionFelt::ZERO),
        ] {
            assertions.push(Assertion::single(
                ORACLE_FACTS_PREIMAGE_START + offset,
                ORACLE_FACTS_LEAF_TRACE_START - 1,
                value,
            ));
        }
        debug_assert_eq!(assertions.len(), PUBLIC_ASSERTION_COUNT);
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        commitment_periodic_columns()
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ProductionAirPublicInputsV2 {
        ProductionAirPublicInputsV2 {
            claim_hash_limbs: core::array::from_fn(|limb| {
                trace.get(CLAIM_HASH_LIMBS_START + limb, 0)
            }),
            public_input_root: core::array::from_fn(|limb| {
                trace.get(
                    HASH_STATE_START + RESCUE_RATE_START + limb,
                    TRACE_LENGTH - 1,
                )
            }),
            claim_source_root: core::array::from_fn(|limb| {
                trace.get(CLAIM_SOURCE_ROOT_RESULT_START + limb, 0)
            }),
            oracle_facts_root: core::array::from_fn(|limb| {
                trace.get(ORACLE_FACTS_ROOT_RESULT_START + limb, 0)
            }),
            fee_schedule_root: core::array::from_fn(|limb| {
                trace.get(FEE_SCHEDULE_ROOT_RESULT_START + limb, 0)
            }),
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
    input: &ProductionAirProofInputV2,
) -> Result<TraceTable<ProductionFelt>, Vec<String>> {
    input.validate()?;
    let adjudication = &input.adjudication;
    validate_commitment_field_range(adjudication)?;
    let semantics = adjudication.evaluate()?;
    let commitment_preimage = canonical_claim_fact_commitment_preimage(adjudication)?;
    let fact_hash_states = build_commitment_hash_states(&commitment_preimage);
    let fact_commitment: [ProductionFelt; FACT_COMMITMENT_WIDTH] = core::array::from_fn(|index| {
        fact_hash_states[FACT_HASH_TRACE_LENGTH - 1][RESCUE_RATE_START + index]
    });
    let claim_source_leaf_hash_states =
        build_claim_source_leaf_hash_states(&input.claim_source.leaf_preimage);
    let claim_source_leaf: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH] =
        core::array::from_fn(|index| {
            claim_source_leaf_hash_states[CLAIM_SOURCE_LEAF_TRACE_LENGTH - 1]
                [RESCUE_RATE_START + index]
        });
    let claim_source_merkle_hash_states =
        build_claim_source_merkle_hash_states(claim_source_leaf, &input.claim_source.merkle_path);
    let computed_claim_source_root: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH] =
        core::array::from_fn(|index| {
            claim_source_merkle_hash_states[CLAIM_SOURCE_MERKLE_TRACE_LENGTH - 1]
                [RESCUE_RATE_START + index]
        });
    if computed_claim_source_root != input.claim_source.root {
        return Err(vec![
            "claim-source trace root does not match validated witness root".to_string(),
        ]);
    }
    let oracle_facts_leaf_hash_states =
        build_oracle_facts_leaf_hash_states(&input.oracle_facts.leaf_preimage);
    let oracle_facts_leaf: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH] =
        core::array::from_fn(|index| {
            oracle_facts_leaf_hash_states[ORACLE_FACTS_LEAF_TRACE_LENGTH - 1]
                [RESCUE_RATE_START + index]
        });
    let oracle_facts_merkle_hash_states =
        build_oracle_facts_merkle_hash_states(oracle_facts_leaf, &input.oracle_facts.merkle_path);
    let computed_oracle_facts_root: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH] =
        core::array::from_fn(|index| {
            oracle_facts_merkle_hash_states[ORACLE_FACTS_MERKLE_TRACE_LENGTH - 1]
                [RESCUE_RATE_START + index]
        });
    if computed_oracle_facts_root != input.oracle_facts.root {
        return Err(vec![
            "oracle-facts trace root does not match validated witness root".to_string(),
        ]);
    }
    let fee_schedule_leaf_hash_states =
        build_fee_schedule_leaf_hash_states(&input.fee_schedule.leaf_preimage);
    let fee_schedule_leaf: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH] =
        core::array::from_fn(|index| {
            fee_schedule_leaf_hash_states[FEE_SCHEDULE_LEAF_TRACE_LENGTH - 1]
                [RESCUE_RATE_START + index]
        });
    let fee_schedule_merkle_hash_states =
        build_fee_schedule_merkle_hash_states(fee_schedule_leaf, &input.fee_schedule.merkle_path);
    let computed_fee_schedule_root: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH] =
        core::array::from_fn(|index| {
            fee_schedule_merkle_hash_states[FEE_SCHEDULE_MERKLE_TRACE_LENGTH - 1]
                [RESCUE_RATE_START + index]
        });
    if computed_fee_schedule_root != input.fee_schedule.root {
        return Err(vec![
            "fee-schedule trace root does not match validated witness root".to_string(),
        ]);
    }
    let public_root_preimage = canonical_public_input_root_preimage_with_commitments(
        adjudication,
        &fact_commitment,
        &computed_claim_source_root,
        &computed_oracle_facts_root,
        &computed_fee_schedule_root,
    )?;
    let public_root_hash_states = build_public_input_root_hash_states(&public_root_preimage);
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    for step in 0..TRACE_LENGTH {
        let mut row = build_trace_row(adjudication, &semantics)?;
        row[COL_CLOCK] = ProductionFelt::from(step as u32);
        row[FACT_COMMITMENT_RESULT_START..FACT_COMMITMENT_RESULT_START + FACT_COMMITMENT_WIDTH]
            .copy_from_slice(&fact_commitment);
        if step < ORACLE_FACTS_LEAF_TRACE_START - 1 {
            row[CLAIM_SOURCE_PREIMAGE_START
                ..CLAIM_SOURCE_PREIMAGE_START + CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH]
                .copy_from_slice(&input.claim_source.leaf_preimage);
            for (level, sibling) in input.claim_source.merkle_path.iter().enumerate() {
                let start = CLAIM_SOURCE_PATH_START + level * CLAIM_SOURCE_ROOT_WIDTH;
                row[start..start + CLAIM_SOURCE_ROOT_WIDTH].copy_from_slice(sibling);
            }
        } else if step < FEE_SCHEDULE_LEAF_TRACE_START - 1 {
            row[ORACLE_FACTS_PREIMAGE_START
                ..ORACLE_FACTS_PREIMAGE_START + ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH]
                .copy_from_slice(&input.oracle_facts.leaf_preimage);
            for (level, sibling) in input.oracle_facts.merkle_path.iter().enumerate() {
                let start = ORACLE_FACTS_PATH_START + level * ORACLE_FACTS_ROOT_WIDTH;
                row[start..start + ORACLE_FACTS_ROOT_WIDTH].copy_from_slice(sibling);
            }
        } else {
            row[FEE_SCHEDULE_PREIMAGE_START
                ..FEE_SCHEDULE_PREIMAGE_START + FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH]
                .copy_from_slice(&input.fee_schedule.leaf_preimage);
            for (level, sibling) in input.fee_schedule.merkle_path.iter().enumerate() {
                let start = FEE_SCHEDULE_PATH_START + level * FEE_SCHEDULE_ROOT_WIDTH;
                row[start..start + FEE_SCHEDULE_ROOT_WIDTH].copy_from_slice(sibling);
            }
        }
        row[CLAIM_SOURCE_ROOT_RESULT_START
            ..CLAIM_SOURCE_ROOT_RESULT_START + CLAIM_SOURCE_ROOT_WIDTH]
            .copy_from_slice(&computed_claim_source_root);
        row[ORACLE_FACTS_ROOT_RESULT_START
            ..ORACLE_FACTS_ROOT_RESULT_START + ORACLE_FACTS_ROOT_WIDTH]
            .copy_from_slice(&computed_oracle_facts_root);
        row[FEE_SCHEDULE_ROOT_RESULT_START
            ..FEE_SCHEDULE_ROOT_RESULT_START + FEE_SCHEDULE_ROOT_WIDTH]
            .copy_from_slice(&computed_fee_schedule_root);
        row[COL_CLAIM_SOURCE_DATE_BINDING] = felt(adjudication.facts.date_of_service_from);
        row[CLAIM_SOURCE_SERVICE_LINES_DIGEST_BINDING_START
            ..CLAIM_SOURCE_SERVICE_LINES_DIGEST_BINDING_START + 4]
            .copy_from_slice(&input.claim_source.leaf_preimage[28..32]);
        row[COL_CLAIM_SOURCE_TOTAL_CHARGE_BINDING] = input.claim_source.leaf_preimage[26];

        let hash_state = if step < CLAIM_SOURCE_LEAF_TRACE_START {
            fact_hash_states[step]
        } else if step < CLAIM_SOURCE_MERKLE_TRACE_START {
            claim_source_leaf_hash_states[step - CLAIM_SOURCE_LEAF_TRACE_START]
        } else if step < ORACLE_FACTS_LEAF_TRACE_START {
            claim_source_merkle_hash_states[step - CLAIM_SOURCE_MERKLE_TRACE_START]
        } else if step < ORACLE_FACTS_MERKLE_TRACE_START {
            oracle_facts_leaf_hash_states[step - ORACLE_FACTS_LEAF_TRACE_START]
        } else if step < FEE_SCHEDULE_LEAF_TRACE_START {
            oracle_facts_merkle_hash_states[step - ORACLE_FACTS_MERKLE_TRACE_START]
        } else if step < FEE_SCHEDULE_MERKLE_TRACE_START {
            fee_schedule_leaf_hash_states[step - FEE_SCHEDULE_LEAF_TRACE_START]
        } else if step < PUBLIC_ROOT_TRACE_START {
            fee_schedule_merkle_hash_states[step - FEE_SCHEDULE_MERKLE_TRACE_START]
        } else {
            public_root_hash_states[step - PUBLIC_ROOT_TRACE_START]
        };
        row[HASH_STATE_START..HASH_STATE_START + RESCUE_STATE_WIDTH].copy_from_slice(&hash_state);
        rows.push(row);
    }
    let columns = (0..TRACE_WIDTH)
        .map(|column| rows.iter().map(|row| row[column]).collect())
        .collect();
    Ok(TraceTable::init(columns))
}

pub fn prove_production_air(
    input: &ProductionAirProofInputV2,
) -> Result<(Proof, ProductionAirPublicInputsV2), String> {
    let trace = build_production_air_trace(input).map_err(|errors| errors.join("; "))?;
    let prover = ProductionG1G10Prover::new(default_options());
    let public_inputs = prover.get_pub_inputs(&trace);
    let proof = prover
        .prove(trace)
        .map_err(|error| format!("production G1-G10 proof generation failed: {error}"))?;
    Ok((proof, public_inputs))
}

pub fn verify_production_air(proof: Proof, public_inputs: ProductionAirPublicInputsV2) -> bool {
    verify_production_air_result(proof, public_inputs).is_ok()
}

pub fn verify_production_air_result(
    proof: Proof,
    public_inputs: ProductionAirPublicInputsV2,
) -> Result<(), winterfell::VerifierError> {
    winterfell::verify::<
        ProductionG1G10Air,
        Blake3_256<ProductionFelt>,
        DefaultRandomCoin<Blake3_256<ProductionFelt>>,
        MerkleTree<Blake3_256<ProductionFelt>>,
    >(proof, public_inputs, &acceptable_options())
}

pub fn default_options() -> ProofOptions {
    ProofOptions::new(
        32,
        16,
        0,
        FieldExtension::Quadratic,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn acceptable_options() -> AcceptableOptions {
    AcceptableOptions::MinConjecturedSecurity(80)
}

pub fn canonical_claim_fact_commitment_preimage(
    input: &ProductionAirInputV1,
) -> Result<[ProductionFelt; FACT_COMMITMENT_PREIMAGE_LENGTH], Vec<String>> {
    input.validate()?;
    validate_commitment_field_range(input)?;

    let claim_hash_limbs = parse_claim_hash_limbs(&input.claim_hash)?;
    let facts = canonical_fact_elements(input);
    let mut elements = [ProductionFelt::ZERO; FACT_COMMITMENT_PREIMAGE_LENGTH];
    elements[..4].copy_from_slice(&commitment_header());
    elements[4..12].copy_from_slice(&claim_hash_limbs);
    elements[12..].copy_from_slice(&facts);
    Ok(elements)
}

pub fn compute_claim_fact_commitment(
    input: &ProductionAirInputV1,
) -> Result<[ProductionFelt; FACT_COMMITMENT_WIDTH], Vec<String>> {
    let elements = canonical_claim_fact_commitment_preimage(input)?;
    let digest = Rp64_256::hash_elements(&elements);
    Ok(digest
        .as_elements()
        .try_into()
        .expect("Rp64_256 digest must contain four field elements"))
}

pub fn canonical_public_input_root_preimage(
    input: &ProductionAirProofInputV2,
) -> Result<[ProductionFelt; PUBLIC_INPUT_ROOT_PREIMAGE_LENGTH], Vec<String>> {
    input.validate()?;
    let fact_commitment = compute_claim_fact_commitment(&input.adjudication)?;
    canonical_public_input_root_preimage_with_commitments(
        &input.adjudication,
        &fact_commitment,
        &input.claim_source.root,
        &input.oracle_facts.root,
        &input.fee_schedule.root,
    )
}

pub fn compute_public_input_root(
    input: &ProductionAirProofInputV2,
) -> Result<[ProductionFelt; PUBLIC_INPUT_ROOT_WIDTH], Vec<String>> {
    let elements = canonical_public_input_root_preimage(input)?;
    let digest = Rp64_256::hash_elements(&elements);
    Ok(digest
        .as_elements()
        .try_into()
        .expect("Rp64_256 digest must contain four field elements"))
}

pub fn pack_public_input_root_bytes32(
    public_input_root: &[ProductionFelt; PUBLIC_INPUT_ROOT_WIDTH],
) -> String {
    let mut encoded = String::with_capacity(66);
    encoded.push_str("0x");
    for element in public_input_root {
        write!(&mut encoded, "{:016x}", element.as_int()).expect("writing to a String cannot fail");
    }
    encoded
}

pub fn unpack_public_input_root_bytes32(
    encoded: &str,
) -> Result<[ProductionFelt; PUBLIC_INPUT_ROOT_WIDTH], String> {
    let hex = encoded.strip_prefix("0x").unwrap_or(encoded);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("public_input_root must be a 0x-prefixed bytes32 hex string".to_string());
    }

    let mut elements = [ProductionFelt::ZERO; PUBLIC_INPUT_ROOT_WIDTH];
    for (index, element) in elements.iter_mut().enumerate() {
        let start = index * 16;
        let value = u64::from_str_radix(&hex[start..start + 16], 16)
            .map_err(|error| format!("invalid public_input_root element {index}: {error}"))?;
        let candidate = ProductionFelt::new(value);
        if candidate.as_int() != value {
            return Err(format!(
                "public_input_root element {index} is not a canonical f64 field element"
            ));
        }
        *element = candidate;
    }
    Ok(elements)
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
    set_range_bits(&mut row, DATE_GE_DIFF_BITS_START, date_ge_diff);

    let date_le = facts.date_of_service_from <= facts.eligibility_period_thru;
    let date_le_diff = if date_le {
        facts.eligibility_period_thru - facts.date_of_service_from
    } else {
        facts.date_of_service_from - facts.eligibility_period_thru - 1
    };
    row[COL_DATE_LE_THRU] = ProductionFelt::from(date_le as u32);
    row[COL_DATE_LE_DIFF] = felt(date_le_diff);
    set_range_bits(&mut row, DATE_LE_DIFF_BITS_START, date_le_diff);

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
    degrees.extend((0..COMMITMENT_BOUND_COLUMN_COUNT).map(|_| TransitionConstraintDegree::new(1)));
    degrees.extend(
        (0..HASH_CONSTRAINT_COUNT)
            .map(|_| TransitionConstraintDegree::with_cycles(7, vec![TRACE_LENGTH])),
    );
    degrees.extend(
        (0..FACT_COMMITMENT_BIND_CONSTRAINT_COUNT)
            .map(|_| TransitionConstraintDegree::with_cycles(1, vec![TRACE_LENGTH])),
    );
    degrees.extend(
        (0..CLAIM_SOURCE_ROOT_BIND_CONSTRAINT_COUNT)
            .map(|_| TransitionConstraintDegree::with_cycles(1, vec![TRACE_LENGTH])),
    );
    degrees.extend(
        (0..ORACLE_FACTS_ROOT_BIND_CONSTRAINT_COUNT)
            .map(|_| TransitionConstraintDegree::with_cycles(1, vec![TRACE_LENGTH])),
    );
    degrees.extend(
        (0..FEE_SCHEDULE_ROOT_BIND_CONSTRAINT_COUNT)
            .map(|_| TransitionConstraintDegree::with_cycles(1, vec![TRACE_LENGTH])),
    );
    degrees.push(TransitionConstraintDegree::new(1));
    debug_assert_eq!(degrees.len(), TRANSITION_CONSTRAINT_COUNT);
    degrees
}

fn commitment_periodic_columns() -> Vec<Vec<ProductionFelt>> {
    let mut columns = vec![vec![ProductionFelt::ZERO; TRACE_LENGTH]; HASH_PERIODIC_COLUMN_COUNT];
    let mut round_block_starts = vec![0usize, 8, 16, 24, 32, 40, 48, 56, 64];
    round_block_starts.extend(
        (0..CLAIM_SOURCE_ROOT_TREE_DEPTH).map(|level| {
            CLAIM_SOURCE_MERKLE_TRACE_START + level * CLAIM_SOURCE_MERKLE_LEVEL_LENGTH
        }),
    );
    round_block_starts.extend([
        ORACLE_FACTS_LEAF_TRACE_START,
        ORACLE_FACTS_LEAF_TRACE_START + 8,
        ORACLE_FACTS_LEAF_TRACE_START + 16,
        ORACLE_FACTS_LEAF_TRACE_START + 24,
    ]);
    round_block_starts.extend(
        (0..ORACLE_FACTS_ROOT_TREE_DEPTH).map(|level| {
            ORACLE_FACTS_MERKLE_TRACE_START + level * ORACLE_FACTS_MERKLE_LEVEL_LENGTH
        }),
    );
    round_block_starts.extend([
        FEE_SCHEDULE_LEAF_TRACE_START,
        FEE_SCHEDULE_LEAF_TRACE_START + 8,
        FEE_SCHEDULE_LEAF_TRACE_START + 16,
        FEE_SCHEDULE_LEAF_TRACE_START + 24,
    ]);
    round_block_starts.extend(
        (0..FEE_SCHEDULE_ROOT_TREE_DEPTH).map(|level| {
            FEE_SCHEDULE_MERKLE_TRACE_START + level * FEE_SCHEDULE_MERKLE_LEVEL_LENGTH
        }),
    );
    round_block_starts.extend([
        PUBLIC_ROOT_TRACE_START,
        PUBLIC_ROOT_TRACE_START + 8,
        PUBLIC_ROOT_TRACE_START + 16,
        PUBLIC_ROOT_TRACE_START + 24,
    ]);
    for block_start in round_block_starts {
        for round in 0..RESCUE_ROUND_COUNT {
            columns[round][block_start + round] = ProductionFelt::ONE;
        }
    }
    for (selector, step) in [7usize, 15, 23].into_iter().enumerate() {
        columns[FACT_HASH_ABSORB_SELECTOR_START + selector][step] = ProductionFelt::ONE;
    }
    for (selector, step) in [39usize, 47, 55, 63].into_iter().enumerate() {
        columns[CLAIM_SOURCE_LEAF_ABSORB_SELECTOR_START + selector][step] = ProductionFelt::ONE;
    }
    columns[CLAIM_SOURCE_LEAF_RESET_SELECTOR][31] = ProductionFelt::ONE;
    for level in 0..CLAIM_SOURCE_ROOT_TREE_DEPTH {
        let step = CLAIM_SOURCE_MERKLE_TRACE_START - 1 + level * CLAIM_SOURCE_MERKLE_LEVEL_LENGTH;
        columns[CLAIM_SOURCE_MERKLE_RESET_SELECTOR_START + level][step] = ProductionFelt::ONE;
    }
    for (selector, step) in [
        ORACLE_FACTS_LEAF_TRACE_START + 7,
        ORACLE_FACTS_LEAF_TRACE_START + 15,
        ORACLE_FACTS_LEAF_TRACE_START + 23,
    ]
    .into_iter()
    .enumerate()
    {
        columns[ORACLE_FACTS_LEAF_ABSORB_SELECTOR_START + selector][step] = ProductionFelt::ONE;
    }
    columns[ORACLE_FACTS_LEAF_RESET_SELECTOR][ORACLE_FACTS_LEAF_TRACE_START - 1] =
        ProductionFelt::ONE;
    for level in 0..ORACLE_FACTS_ROOT_TREE_DEPTH {
        let step = ORACLE_FACTS_MERKLE_TRACE_START - 1 + level * ORACLE_FACTS_MERKLE_LEVEL_LENGTH;
        columns[ORACLE_FACTS_MERKLE_RESET_SELECTOR_START + level][step] = ProductionFelt::ONE;
    }
    for (selector, step) in [
        FEE_SCHEDULE_LEAF_TRACE_START + 7,
        FEE_SCHEDULE_LEAF_TRACE_START + 15,
        FEE_SCHEDULE_LEAF_TRACE_START + 23,
    ]
    .into_iter()
    .enumerate()
    {
        columns[FEE_SCHEDULE_LEAF_ABSORB_SELECTOR_START + selector][step] = ProductionFelt::ONE;
    }
    columns[FEE_SCHEDULE_LEAF_RESET_SELECTOR][FEE_SCHEDULE_LEAF_TRACE_START - 1] =
        ProductionFelt::ONE;
    for level in 0..FEE_SCHEDULE_ROOT_TREE_DEPTH {
        let step = FEE_SCHEDULE_MERKLE_TRACE_START - 1 + level * FEE_SCHEDULE_MERKLE_LEVEL_LENGTH;
        columns[FEE_SCHEDULE_MERKLE_RESET_SELECTOR_START + level][step] = ProductionFelt::ONE;
    }
    for (selector, step) in [
        PUBLIC_ROOT_TRACE_START + 7,
        PUBLIC_ROOT_TRACE_START + 15,
        PUBLIC_ROOT_TRACE_START + 23,
    ]
    .into_iter()
    .enumerate()
    {
        columns[PUBLIC_ROOT_ABSORB_SELECTOR_START + selector][step] = ProductionFelt::ONE;
    }
    columns[PUBLIC_ROOT_RESET_SELECTOR][PUBLIC_ROOT_TRACE_START - 1] = ProductionFelt::ONE;
    for step in PUBLIC_ROOT_TRACE_START + 31..TRACE_LENGTH - 1 {
        columns[PUBLIC_ROOT_HOLD_SELECTOR][step] = ProductionFelt::ONE;
    }
    columns
}

fn commitment_bound_columns() -> Vec<usize> {
    (COL_ELIGIBILITY_ACTIVE..=COL_PHYSICIAN_CERTIFICATION_VALID)
        .chain(CLAIM_HASH_LIMBS_START..CLAIM_HASH_LIMBS_START + CLAIM_HASH_LIMB_COUNT)
        .chain(FACT_COMMITMENT_RESULT_START..FACT_COMMITMENT_RESULT_START + FACT_COMMITMENT_WIDTH)
        .chain(
            CLAIM_SOURCE_ROOT_RESULT_START
                ..CLAIM_SOURCE_ROOT_RESULT_START + CLAIM_SOURCE_ROOT_WIDTH,
        )
        .chain(
            ORACLE_FACTS_ROOT_RESULT_START
                ..ORACLE_FACTS_ROOT_RESULT_START + ORACLE_FACTS_ROOT_WIDTH,
        )
        .chain(
            FEE_SCHEDULE_ROOT_RESULT_START
                ..FEE_SCHEDULE_ROOT_RESULT_START + FEE_SCHEDULE_ROOT_WIDTH,
        )
        .chain(core::iter::once(COL_CLAIM_SOURCE_DATE_BINDING))
        .chain(
            CLAIM_SOURCE_SERVICE_LINES_DIGEST_BINDING_START
                ..CLAIM_SOURCE_SERVICE_LINES_DIGEST_BINDING_START + 4,
        )
        .chain(core::iter::once(COL_CLAIM_SOURCE_TOTAL_CHARGE_BINDING))
        .collect()
}

fn commitment_header() -> [ProductionFelt; 4] {
    [
        felt(FACT_COMMITMENT_DOMAIN_TAG),
        felt(1),
        felt(FACT_COMMITMENT_RULESET_TAG),
        felt(FACT_COUNT),
    ]
}

fn public_input_root_header() -> [ProductionFelt; 4] {
    [
        felt(PUBLIC_INPUT_ROOT_DOMAIN_TAG),
        felt(4),
        felt(PUBLIC_INPUT_ROOT_RULESET_TAG),
        felt(PUBLIC_INPUT_ROOT_ELEMENT_COUNT),
    ]
}

fn canonical_public_input_root_preimage_with_commitments(
    input: &ProductionAirInputV1,
    fact_commitment: &[ProductionFelt; FACT_COMMITMENT_WIDTH],
    claim_source_root: &[ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH],
    oracle_facts_root: &[ProductionFelt; ORACLE_FACTS_ROOT_WIDTH],
    fee_schedule_root: &[ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH],
) -> Result<[ProductionFelt; PUBLIC_INPUT_ROOT_PREIMAGE_LENGTH], Vec<String>> {
    input.validate()?;
    validate_commitment_field_range(input)?;

    let claim_hash_limbs = parse_claim_hash_limbs(&input.claim_hash)?;
    let mut elements = [ProductionFelt::ZERO; PUBLIC_INPUT_ROOT_PREIMAGE_LENGTH];
    elements[..4].copy_from_slice(&public_input_root_header());
    elements[4..12].copy_from_slice(&claim_hash_limbs);
    elements[12..16].copy_from_slice(fact_commitment);
    elements[16..20].copy_from_slice(claim_source_root);
    elements[20..24].copy_from_slice(oracle_facts_root);
    elements[24..28].copy_from_slice(fee_schedule_root);
    elements[28] = felt(input.expected_outcome.decision as u64);
    elements[29] = felt(input.expected_outcome.failure_code as u64);
    Ok(elements)
}

fn canonical_fact_elements(input: &ProductionAirInputV1) -> [ProductionFelt; 16] {
    let facts = &input.facts;
    [
        felt(facts.eligibility_active as u64),
        felt(facts.aid_code),
        felt(facts.benefit_level_exists as u64),
        felt(facts.date_of_service_from),
        felt(facts.eligibility_period_from),
        felt(facts.eligibility_period_thru),
        felt(facts.soc_amount),
        felt(facts.soc_met as u64),
        felt(facts.provider_enrolled as u64),
        felt(facts.provider_type_valid as u64),
        felt(facts.billing_code_valid as u64),
        felt(facts.units_valid as u64),
        felt(facts.is_duplicate as u64),
        felt(facts.disability_determination_valid as u64),
        felt(facts.recipient_not_deceased as u64),
        felt(facts.physician_certification_valid as u64),
    ]
}

fn initial_commitment_hash_state(
    first_claim_hash_limbs: &[ProductionFelt; 4],
) -> [ProductionFelt; RESCUE_STATE_WIDTH] {
    let mut state = [ProductionFelt::ZERO; RESCUE_STATE_WIDTH];
    state[0] = felt(FACT_COMMITMENT_PREIMAGE_LENGTH as u64);
    state[RESCUE_RATE_START..RESCUE_RATE_START + 4].copy_from_slice(&commitment_header());
    state[RESCUE_RATE_START + 4..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(first_claim_hash_limbs);
    state
}

fn initial_public_input_root_hash_state<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
) -> [E; RESCUE_STATE_WIDTH] {
    let mut state = [E::ZERO; RESCUE_STATE_WIDTH];
    state[0] = E::from(felt(PUBLIC_INPUT_ROOT_PREIMAGE_LENGTH as u64));
    for (offset, value) in public_input_root_header().into_iter().enumerate() {
        state[RESCUE_RATE_START + offset] = E::from(value);
    }
    for offset in 0..4 {
        state[RESCUE_RATE_START + 4 + offset] = row[CLAIM_HASH_LIMBS_START + offset];
    }
    state
}

fn initial_claim_source_leaf_hash_state<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
) -> [E; RESCUE_STATE_WIDTH] {
    let mut state = [E::ZERO; RESCUE_STATE_WIDTH];
    state[0] = E::from(felt(CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH as u64));
    for rate_index in 0..RESCUE_RATE_WIDTH {
        state[RESCUE_RATE_START + rate_index] = row[CLAIM_SOURCE_PREIMAGE_START + rate_index];
    }
    state
}

fn initial_oracle_facts_leaf_hash_state<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
) -> [E; RESCUE_STATE_WIDTH] {
    let mut state = [E::ZERO; RESCUE_STATE_WIDTH];
    state[0] = E::from(felt(ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH as u64));
    for rate_index in 0..RESCUE_RATE_WIDTH {
        state[RESCUE_RATE_START + rate_index] = row[ORACLE_FACTS_PREIMAGE_START + rate_index];
    }
    state
}

fn initial_fee_schedule_leaf_hash_state<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
) -> [E; RESCUE_STATE_WIDTH] {
    let mut state = [E::ZERO; RESCUE_STATE_WIDTH];
    state[0] = E::from(felt(FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH as u64));
    for rate_index in 0..RESCUE_RATE_WIDTH {
        state[RESCUE_RATE_START + rate_index] = row[FEE_SCHEDULE_PREIMAGE_START + rate_index];
    }
    state
}

fn initial_claim_source_merkle_state<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
    level: usize,
) -> [E; RESCUE_STATE_WIDTH] {
    let mut state = [E::ZERO; RESCUE_STATE_WIDTH];
    state[0] = E::from(felt(RESCUE_RATE_WIDTH as u64));
    let current: [E; CLAIM_SOURCE_ROOT_WIDTH] =
        core::array::from_fn(|index| row[HASH_STATE_START + RESCUE_RATE_START + index]);
    let sibling_start = CLAIM_SOURCE_PATH_START + level * CLAIM_SOURCE_ROOT_WIDTH;
    let sibling: [E; CLAIM_SOURCE_ROOT_WIDTH] =
        core::array::from_fn(|index| row[sibling_start + index]);
    let (left, right) = if claim_source_index_bit(level) == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };
    state[RESCUE_RATE_START..RESCUE_RATE_START + CLAIM_SOURCE_ROOT_WIDTH].copy_from_slice(&left);
    state[RESCUE_RATE_START + CLAIM_SOURCE_ROOT_WIDTH..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&right);
    state
}

fn initial_oracle_facts_merkle_state<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
    level: usize,
) -> [E; RESCUE_STATE_WIDTH] {
    let mut state = [E::ZERO; RESCUE_STATE_WIDTH];
    state[0] = E::from(felt(RESCUE_RATE_WIDTH as u64));
    let current: [E; ORACLE_FACTS_ROOT_WIDTH] =
        core::array::from_fn(|index| row[HASH_STATE_START + RESCUE_RATE_START + index]);
    let sibling_start = ORACLE_FACTS_PATH_START + level * ORACLE_FACTS_ROOT_WIDTH;
    let sibling: [E; ORACLE_FACTS_ROOT_WIDTH] =
        core::array::from_fn(|index| row[sibling_start + index]);
    let (left, right) = if oracle_facts_index_bit(level) == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };
    state[RESCUE_RATE_START..RESCUE_RATE_START + ORACLE_FACTS_ROOT_WIDTH].copy_from_slice(&left);
    state[RESCUE_RATE_START + ORACLE_FACTS_ROOT_WIDTH..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&right);
    state
}

fn initial_fee_schedule_merkle_state<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
    level: usize,
) -> [E; RESCUE_STATE_WIDTH] {
    let mut state = [E::ZERO; RESCUE_STATE_WIDTH];
    state[0] = E::from(felt(RESCUE_RATE_WIDTH as u64));
    let current: [E; FEE_SCHEDULE_ROOT_WIDTH] =
        core::array::from_fn(|index| row[HASH_STATE_START + RESCUE_RATE_START + index]);
    let sibling_start = FEE_SCHEDULE_PATH_START + level * FEE_SCHEDULE_ROOT_WIDTH;
    let sibling: [E; FEE_SCHEDULE_ROOT_WIDTH] =
        core::array::from_fn(|index| row[sibling_start + index]);
    let (left, right) = if fee_schedule_index_bit(level) == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };
    state[RESCUE_RATE_START..RESCUE_RATE_START + FEE_SCHEDULE_ROOT_WIDTH].copy_from_slice(&left);
    state[RESCUE_RATE_START + FEE_SCHEDULE_ROOT_WIDTH..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&right);
    state
}

fn build_commitment_hash_states(
    elements: &[ProductionFelt; FACT_COMMITMENT_PREIMAGE_LENGTH],
) -> [[ProductionFelt; RESCUE_STATE_WIDTH]; FACT_HASH_TRACE_LENGTH] {
    let first_claim_hash_limbs: [ProductionFelt; 4] = elements[4..8]
        .try_into()
        .expect("canonical commitment contains four initial claim hash limbs");
    let mut state = initial_commitment_hash_state(&first_claim_hash_limbs);
    let mut states = [[ProductionFelt::ZERO; RESCUE_STATE_WIDTH]; FACT_HASH_TRACE_LENGTH];
    states[0] = state;
    let mut step = 0;

    for block in 0..4 {
        for round in 0..RESCUE_ROUND_COUNT {
            Rp64_256::apply_round(&mut state, round);
            step += 1;
            states[step] = state;
        }
        if block < 3 {
            let next_block_start = (block + 1) * RESCUE_RATE_WIDTH;
            for rate_index in 0..RESCUE_RATE_WIDTH {
                let element_index = next_block_start + rate_index;
                if element_index < FACT_COMMITMENT_PREIMAGE_LENGTH {
                    state[RESCUE_RATE_START + rate_index] += elements[element_index];
                }
            }
            step += 1;
            states[step] = state;
        }
    }

    debug_assert_eq!(step, FACT_HASH_TRACE_LENGTH - 1);
    states
}

fn build_claim_source_leaf_hash_states(
    elements: &[ProductionFelt; CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH],
) -> [[ProductionFelt; RESCUE_STATE_WIDTH]; CLAIM_SOURCE_LEAF_TRACE_LENGTH] {
    let mut state = [ProductionFelt::ZERO; RESCUE_STATE_WIDTH];
    state[0] = felt(CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH as u64);
    state[RESCUE_RATE_START..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&elements[..RESCUE_RATE_WIDTH]);

    let mut states = [[ProductionFelt::ZERO; RESCUE_STATE_WIDTH]; CLAIM_SOURCE_LEAF_TRACE_LENGTH];
    states[0] = state;
    let mut step = 0;

    for block in 0..5 {
        for round in 0..RESCUE_ROUND_COUNT {
            Rp64_256::apply_round(&mut state, round);
            step += 1;
            states[step] = state;
        }
        if block < 4 {
            let next_block_start = (block + 1) * RESCUE_RATE_WIDTH;
            for rate_index in 0..RESCUE_RATE_WIDTH {
                let element_index = next_block_start + rate_index;
                if element_index < CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH {
                    state[RESCUE_RATE_START + rate_index] += elements[element_index];
                }
            }
            step += 1;
            states[step] = state;
        }
    }

    debug_assert_eq!(step, CLAIM_SOURCE_LEAF_TRACE_LENGTH - 1);
    states
}

fn build_oracle_facts_leaf_hash_states(
    elements: &[ProductionFelt; ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH],
) -> [[ProductionFelt; RESCUE_STATE_WIDTH]; ORACLE_FACTS_LEAF_TRACE_LENGTH] {
    let mut state = [ProductionFelt::ZERO; RESCUE_STATE_WIDTH];
    state[0] = felt(ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH as u64);
    state[RESCUE_RATE_START..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&elements[..RESCUE_RATE_WIDTH]);

    let mut states = [[ProductionFelt::ZERO; RESCUE_STATE_WIDTH]; ORACLE_FACTS_LEAF_TRACE_LENGTH];
    states[0] = state;
    let mut step = 0;

    for block in 0..4 {
        for round in 0..RESCUE_ROUND_COUNT {
            Rp64_256::apply_round(&mut state, round);
            step += 1;
            states[step] = state;
        }
        if block < 3 {
            let next_block_start = (block + 1) * RESCUE_RATE_WIDTH;
            for rate_index in 0..RESCUE_RATE_WIDTH {
                state[RESCUE_RATE_START + rate_index] += elements[next_block_start + rate_index];
            }
            step += 1;
            states[step] = state;
        }
    }

    debug_assert_eq!(step, ORACLE_FACTS_LEAF_TRACE_LENGTH - 1);
    states
}

fn build_fee_schedule_leaf_hash_states(
    elements: &[ProductionFelt; FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH],
) -> [[ProductionFelt; RESCUE_STATE_WIDTH]; FEE_SCHEDULE_LEAF_TRACE_LENGTH] {
    let mut state = [ProductionFelt::ZERO; RESCUE_STATE_WIDTH];
    state[0] = felt(FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH as u64);
    state[RESCUE_RATE_START..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&elements[..RESCUE_RATE_WIDTH]);

    let mut states = [[ProductionFelt::ZERO; RESCUE_STATE_WIDTH]; FEE_SCHEDULE_LEAF_TRACE_LENGTH];
    states[0] = state;
    let mut step = 0;

    for block in 0..4 {
        for round in 0..RESCUE_ROUND_COUNT {
            Rp64_256::apply_round(&mut state, round);
            step += 1;
            states[step] = state;
        }
        if block < 3 {
            let next_block_start = (block + 1) * RESCUE_RATE_WIDTH;
            for rate_index in 0..RESCUE_RATE_WIDTH {
                state[RESCUE_RATE_START + rate_index] += elements[next_block_start + rate_index];
            }
            step += 1;
            states[step] = state;
        }
    }

    debug_assert_eq!(step, FEE_SCHEDULE_LEAF_TRACE_LENGTH - 1);
    states
}

fn build_claim_source_merkle_hash_states(
    leaf: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH],
    path: &[[ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH]; CLAIM_SOURCE_ROOT_TREE_DEPTH],
) -> [[ProductionFelt; RESCUE_STATE_WIDTH]; CLAIM_SOURCE_MERKLE_TRACE_LENGTH] {
    let mut states = [[ProductionFelt::ZERO; RESCUE_STATE_WIDTH]; CLAIM_SOURCE_MERKLE_TRACE_LENGTH];
    let mut current = leaf;

    for (level, sibling) in path.iter().copied().enumerate() {
        let start = level * CLAIM_SOURCE_MERKLE_LEVEL_LENGTH;
        let mut state = initial_claim_source_merge_state(current, sibling, level);
        states[start] = state;
        for round in 0..RESCUE_ROUND_COUNT {
            Rp64_256::apply_round(&mut state, round);
            states[start + round + 1] = state;
        }
        current = state[RESCUE_RATE_START..RESCUE_RATE_START + CLAIM_SOURCE_ROOT_WIDTH]
            .try_into()
            .expect("claim-source Merkle digest width");
    }

    states
}

fn build_oracle_facts_merkle_hash_states(
    leaf: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH],
    path: &[[ProductionFelt; ORACLE_FACTS_ROOT_WIDTH]; ORACLE_FACTS_ROOT_TREE_DEPTH],
) -> [[ProductionFelt; RESCUE_STATE_WIDTH]; ORACLE_FACTS_MERKLE_TRACE_LENGTH] {
    let mut states = [[ProductionFelt::ZERO; RESCUE_STATE_WIDTH]; ORACLE_FACTS_MERKLE_TRACE_LENGTH];
    let mut current = leaf;

    for (level, sibling) in path.iter().copied().enumerate() {
        let start = level * ORACLE_FACTS_MERKLE_LEVEL_LENGTH;
        let mut state = initial_oracle_facts_merge_state(current, sibling, level);
        states[start] = state;
        for round in 0..RESCUE_ROUND_COUNT {
            Rp64_256::apply_round(&mut state, round);
            states[start + round + 1] = state;
        }
        current = state[RESCUE_RATE_START..RESCUE_RATE_START + ORACLE_FACTS_ROOT_WIDTH]
            .try_into()
            .expect("oracle-facts Merkle digest width");
    }

    states
}

fn build_fee_schedule_merkle_hash_states(
    leaf: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH],
    path: &[[ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH]; FEE_SCHEDULE_ROOT_TREE_DEPTH],
) -> [[ProductionFelt; RESCUE_STATE_WIDTH]; FEE_SCHEDULE_MERKLE_TRACE_LENGTH] {
    let mut states = [[ProductionFelt::ZERO; RESCUE_STATE_WIDTH]; FEE_SCHEDULE_MERKLE_TRACE_LENGTH];
    let mut current = leaf;

    for (level, sibling) in path.iter().copied().enumerate() {
        let start = level * FEE_SCHEDULE_MERKLE_LEVEL_LENGTH;
        let mut state = initial_fee_schedule_merge_state(current, sibling, level);
        states[start] = state;
        for round in 0..RESCUE_ROUND_COUNT {
            Rp64_256::apply_round(&mut state, round);
            states[start + round + 1] = state;
        }
        current = state[RESCUE_RATE_START..RESCUE_RATE_START + FEE_SCHEDULE_ROOT_WIDTH]
            .try_into()
            .expect("fee-schedule Merkle digest width");
    }

    states
}

fn initial_claim_source_merge_state(
    current: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH],
    sibling: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH],
    level: usize,
) -> [ProductionFelt; RESCUE_STATE_WIDTH] {
    let mut state = [ProductionFelt::ZERO; RESCUE_STATE_WIDTH];
    state[0] = felt(RESCUE_RATE_WIDTH as u64);
    let (left, right) = if claim_source_index_bit(level) == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };
    state[RESCUE_RATE_START..RESCUE_RATE_START + CLAIM_SOURCE_ROOT_WIDTH].copy_from_slice(&left);
    state[RESCUE_RATE_START + CLAIM_SOURCE_ROOT_WIDTH..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&right);
    state
}

fn merge_claim_source_level(
    current: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH],
    sibling: [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH],
    level: usize,
) -> [ProductionFelt; CLAIM_SOURCE_ROOT_WIDTH] {
    let mut state = initial_claim_source_merge_state(current, sibling, level);
    for round in 0..RESCUE_ROUND_COUNT {
        Rp64_256::apply_round(&mut state, round);
    }
    state[RESCUE_RATE_START..RESCUE_RATE_START + CLAIM_SOURCE_ROOT_WIDTH]
        .try_into()
        .expect("claim-source Merkle digest width")
}

fn initial_oracle_facts_merge_state(
    current: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH],
    sibling: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH],
    level: usize,
) -> [ProductionFelt; RESCUE_STATE_WIDTH] {
    let mut state = [ProductionFelt::ZERO; RESCUE_STATE_WIDTH];
    state[0] = felt(RESCUE_RATE_WIDTH as u64);
    let (left, right) = if oracle_facts_index_bit(level) == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };
    state[RESCUE_RATE_START..RESCUE_RATE_START + ORACLE_FACTS_ROOT_WIDTH].copy_from_slice(&left);
    state[RESCUE_RATE_START + ORACLE_FACTS_ROOT_WIDTH..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&right);
    state
}

fn merge_oracle_facts_level(
    current: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH],
    sibling: [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH],
    level: usize,
) -> [ProductionFelt; ORACLE_FACTS_ROOT_WIDTH] {
    let mut state = initial_oracle_facts_merge_state(current, sibling, level);
    for round in 0..RESCUE_ROUND_COUNT {
        Rp64_256::apply_round(&mut state, round);
    }
    state[RESCUE_RATE_START..RESCUE_RATE_START + ORACLE_FACTS_ROOT_WIDTH]
        .try_into()
        .expect("oracle-facts Merkle digest width")
}

fn initial_fee_schedule_merge_state(
    current: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH],
    sibling: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH],
    level: usize,
) -> [ProductionFelt; RESCUE_STATE_WIDTH] {
    let mut state = [ProductionFelt::ZERO; RESCUE_STATE_WIDTH];
    state[0] = felt(RESCUE_RATE_WIDTH as u64);
    let (left, right) = if fee_schedule_index_bit(level) == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };
    state[RESCUE_RATE_START..RESCUE_RATE_START + FEE_SCHEDULE_ROOT_WIDTH].copy_from_slice(&left);
    state[RESCUE_RATE_START + FEE_SCHEDULE_ROOT_WIDTH..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&right);
    state
}

fn merge_fee_schedule_level(
    current: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH],
    sibling: [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH],
    level: usize,
) -> [ProductionFelt; FEE_SCHEDULE_ROOT_WIDTH] {
    let mut state = initial_fee_schedule_merge_state(current, sibling, level);
    for round in 0..RESCUE_ROUND_COUNT {
        Rp64_256::apply_round(&mut state, round);
    }
    state[RESCUE_RATE_START..RESCUE_RATE_START + FEE_SCHEDULE_ROOT_WIDTH]
        .try_into()
        .expect("fee-schedule Merkle digest width")
}

fn claim_source_index_bit(level: usize) -> u8 {
    ((CLAIM_SOURCE_ROOT_LEAF_INDEX >> level) & 1) as u8
}

fn oracle_facts_index_bit(level: usize) -> u8 {
    ((ORACLE_FACTS_ROOT_LEAF_INDEX >> level) & 1) as u8
}

fn fee_schedule_index_bit(level: usize) -> u8 {
    ((FEE_SCHEDULE_ROOT_LEAF_INDEX >> level) & 1) as u8
}

fn build_public_input_root_hash_states(
    elements: &[ProductionFelt; PUBLIC_INPUT_ROOT_PREIMAGE_LENGTH],
) -> [[ProductionFelt; RESCUE_STATE_WIDTH]; TRACE_LENGTH - PUBLIC_ROOT_TRACE_START] {
    let first_claim_hash_limbs: [ProductionFelt; 4] = elements[4..8]
        .try_into()
        .expect("canonical public input root contains four initial claim hash limbs");
    let mut state = [ProductionFelt::ZERO; RESCUE_STATE_WIDTH];
    state[0] = felt(PUBLIC_INPUT_ROOT_PREIMAGE_LENGTH as u64);
    state[RESCUE_RATE_START..RESCUE_RATE_START + 4].copy_from_slice(&public_input_root_header());
    state[RESCUE_RATE_START + 4..RESCUE_RATE_START + RESCUE_RATE_WIDTH]
        .copy_from_slice(&first_claim_hash_limbs);

    let mut states =
        [[ProductionFelt::ZERO; RESCUE_STATE_WIDTH]; TRACE_LENGTH - PUBLIC_ROOT_TRACE_START];
    states[0] = state;
    let mut step = 0;

    for block in 0..4 {
        for round in 0..RESCUE_ROUND_COUNT {
            Rp64_256::apply_round(&mut state, round);
            step += 1;
            states[step] = state;
        }
        if block < 3 {
            let next_block_start = (block + 1) * RESCUE_RATE_WIDTH;
            for rate_index in 0..RESCUE_RATE_WIDTH {
                let element_index = next_block_start + rate_index;
                if element_index < PUBLIC_INPUT_ROOT_PREIMAGE_LENGTH {
                    state[RESCUE_RATE_START + rate_index] += elements[element_index];
                }
            }
            step += 1;
            states[step] = state;
        }
    }

    debug_assert_eq!(step, 31);
    for hold_step in step + 1..states.len() {
        states[hold_step] = state;
    }
    states
}

fn commitment_absorption_block<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
    block: usize,
) -> [E; RESCUE_RATE_WIDTH] {
    match block {
        1 => [
            row[CLAIM_HASH_LIMBS_START + 4],
            row[CLAIM_HASH_LIMBS_START + 5],
            row[CLAIM_HASH_LIMBS_START + 6],
            row[CLAIM_HASH_LIMBS_START + 7],
            row[COL_ELIGIBILITY_ACTIVE],
            row[COL_AID_CODE],
            row[COL_BENEFIT_LEVEL_EXISTS],
            row[COL_DATE_OF_SERVICE_FROM],
        ],
        2 => [
            row[COL_ELIGIBILITY_PERIOD_FROM],
            row[COL_ELIGIBILITY_PERIOD_THRU],
            row[COL_SOC_AMOUNT],
            row[COL_SOC_MET],
            row[COL_PROVIDER_ENROLLED],
            row[COL_PROVIDER_TYPE_VALID],
            row[COL_BILLING_CODE_VALID],
            row[COL_UNITS_VALID],
        ],
        3 => [
            row[COL_IS_DUPLICATE],
            row[COL_DISABILITY_DETERMINATION_VALID],
            row[COL_RECIPIENT_NOT_DECEASED],
            row[COL_PHYSICIAN_CERTIFICATION_VALID],
            E::ZERO,
            E::ZERO,
            E::ZERO,
            E::ZERO,
        ],
        _ => unreachable!("commitment absorption block must be 1, 2, or 3"),
    }
}

fn claim_source_leaf_absorption_block<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
    block: usize,
) -> [E; RESCUE_RATE_WIDTH] {
    debug_assert!((1..=4).contains(&block));
    let start = CLAIM_SOURCE_PREIMAGE_START + block * RESCUE_RATE_WIDTH;
    core::array::from_fn(|offset| {
        let element_index = block * RESCUE_RATE_WIDTH + offset;
        if element_index == 26 {
            row[COL_CLAIM_SOURCE_TOTAL_CHARGE_BINDING]
        } else if element_index == 27 {
            row[COL_CLAIM_SOURCE_DATE_BINDING]
        } else if (28..32).contains(&element_index) {
            row[CLAIM_SOURCE_SERVICE_LINES_DIGEST_BINDING_START + element_index - 28]
        } else if element_index < CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH {
            row[start + offset]
        } else {
            E::ZERO
        }
    })
}

fn oracle_facts_leaf_absorption_block<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
    block: usize,
) -> [E; RESCUE_RATE_WIDTH] {
    debug_assert!((1..=3).contains(&block));
    let start = ORACLE_FACTS_PREIMAGE_START + block * RESCUE_RATE_WIDTH;
    core::array::from_fn(|offset| row[start + offset])
}

fn fee_schedule_leaf_absorption_block<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
    block: usize,
) -> [E; RESCUE_RATE_WIDTH] {
    debug_assert!((1..=3).contains(&block));
    let start = FEE_SCHEDULE_PREIMAGE_START + block * RESCUE_RATE_WIDTH;
    core::array::from_fn(|offset| {
        let element_index = block * RESCUE_RATE_WIDTH + offset;
        if (20..24).contains(&element_index) {
            row[CLAIM_SOURCE_SERVICE_LINES_DIGEST_BINDING_START + element_index - 20]
        } else if element_index == 29 {
            row[COL_CLAIM_SOURCE_DATE_BINDING]
        } else if element_index == 31 {
            row[COL_CLAIM_SOURCE_TOTAL_CHARGE_BINDING]
        } else {
            row[start + offset]
        }
    })
}

fn public_input_root_absorption_block<E: FieldElement + From<ProductionFelt>>(
    row: &[E],
    block: usize,
) -> [E; RESCUE_RATE_WIDTH] {
    match block {
        1 => [
            row[CLAIM_HASH_LIMBS_START + 4],
            row[CLAIM_HASH_LIMBS_START + 5],
            row[CLAIM_HASH_LIMBS_START + 6],
            row[CLAIM_HASH_LIMBS_START + 7],
            row[FACT_COMMITMENT_RESULT_START],
            row[FACT_COMMITMENT_RESULT_START + 1],
            row[FACT_COMMITMENT_RESULT_START + 2],
            row[FACT_COMMITMENT_RESULT_START + 3],
        ],
        2 => [
            row[CLAIM_SOURCE_ROOT_RESULT_START],
            row[CLAIM_SOURCE_ROOT_RESULT_START + 1],
            row[CLAIM_SOURCE_ROOT_RESULT_START + 2],
            row[CLAIM_SOURCE_ROOT_RESULT_START + 3],
            row[ORACLE_FACTS_ROOT_RESULT_START],
            row[ORACLE_FACTS_ROOT_RESULT_START + 1],
            row[ORACLE_FACTS_ROOT_RESULT_START + 2],
            row[ORACLE_FACTS_ROOT_RESULT_START + 3],
        ],
        3 => [
            row[FEE_SCHEDULE_ROOT_RESULT_START],
            row[FEE_SCHEDULE_ROOT_RESULT_START + 1],
            row[FEE_SCHEDULE_ROOT_RESULT_START + 2],
            row[FEE_SCHEDULE_ROOT_RESULT_START + 3],
            row[COL_DECISION],
            row[COL_FAILURE_CODE],
            E::ZERO,
            E::ZERO,
        ],
        _ => unreachable!("public input root absorption block must be 1, 2, or 3"),
    }
}

fn rescue_round_constraints<E: FieldElement + From<ProductionFelt>>(
    current: &[E; RESCUE_STATE_WIDTH],
    next: &[E; RESCUE_STATE_WIDTH],
    round: usize,
) -> [E; RESCUE_STATE_WIDTH] {
    let current_sboxed = core::array::from_fn(|index| exp7(current[index]));
    let mut first_half = apply_rescue_matrix(&Rp64_256::MDS, &current_sboxed);
    for (index, value) in first_half.iter_mut().enumerate() {
        *value += E::from(Rp64_256::ARK1[round][index]);
    }

    let next_without_constants =
        core::array::from_fn(|index| next[index] - E::from(Rp64_256::ARK2[round][index]));
    let inverse_linear = apply_rescue_matrix(&Rp64_256::INV_MDS, &next_without_constants);
    core::array::from_fn(|index| exp7(inverse_linear[index]) - first_half[index])
}

fn apply_rescue_matrix<E: FieldElement + From<ProductionFelt>>(
    matrix: &[[ProductionFelt; RESCUE_STATE_WIDTH]; RESCUE_STATE_WIDTH],
    vector: &[E; RESCUE_STATE_WIDTH],
) -> [E; RESCUE_STATE_WIDTH] {
    core::array::from_fn(|row| {
        (0..RESCUE_STATE_WIDTH).fold(E::ZERO, |value, column| {
            value + E::from(matrix[row][column]) * vector[column]
        })
    })
}

fn exp7<E: FieldElement>(value: E) -> E {
    let squared = value.square();
    let fourth = squared.square();
    fourth * squared * value
}

fn validate_commitment_field_range(input: &ProductionAirInputV1) -> Result<(), Vec<String>> {
    let facts = &input.facts;
    let mut errors = Vec::new();
    for (name, value) in [
        ("aid_code", facts.aid_code),
        ("date_of_service_from", facts.date_of_service_from),
        ("eligibility_period_from", facts.eligibility_period_from),
        ("eligibility_period_thru", facts.eligibility_period_thru),
        ("soc_amount", facts.soc_amount),
    ] {
        if value > u32::MAX as u64 {
            errors.push(format!(
                "{name} must fit in 32 bits for lossless Rp64 commitment encoding and sound range checks"
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
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
    for bit in 0..RANGE_BITS {
        value += row[start + bit] * E::from(ProductionFelt::new(1u64 << bit));
    }
    value
}

fn set_range_bits(row: &mut [ProductionFelt; TRACE_WIDTH], start: usize, value: u64) {
    for bit in 0..RANGE_BITS {
        row[start + bit] = ProductionFelt::from(((value >> bit) & 1) as u32);
    }
}

fn parse_claim_hash_limbs(
    claim_hash: &str,
) -> Result<[ProductionFelt; CLAIM_HASH_LIMB_COUNT], Vec<String>> {
    let hex = claim_hash.strip_prefix("0x").unwrap_or(claim_hash);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(vec![
            "claim_hash must be a 0x-prefixed 32-byte hex string".to_string(),
        ]);
    }

    let mut limbs = [ProductionFelt::ZERO; CLAIM_HASH_LIMB_COUNT];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 8;
        let value = u32::from_str_radix(&hex[start..start + 8], 16)
            .map_err(|error| vec![format!("invalid claim_hash limb {index}: {error}")])?;
        *limb = ProductionFelt::from(value);
    }
    Ok(limbs)
}

fn felt(value: u64) -> ProductionFelt {
    ProductionFelt::new(value)
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
