//! BL-PQ512 cryptographic substrate and current Wave 2 proof core.
//!
//! This crate owns the M31 degree-16 tower, strict field encoding, SHA3-512
//! commitments and rejection samplers, the selected native-masked relay-free
//! GKR, Construction 8.2 PCS bindings, authenticated public coin, canonical
//! proof parsing, and the Rust-authoritative independent verifier used by the
//! H4 K128/K512 prototype. Historical Circle-FRI and Wave 1B modules remain
//! differential or theorem-reference controls unless a current caller imports
//! them. H4 is nonactivating: Gate 2E state binding, the complete composed
//! simulator/security ledger, H5, H6, and production verifier remain open.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod air_composition;
pub mod air_ir;
pub mod air_logup;
pub mod chained_public_coin;
#[cfg(feature = "std")]
pub mod chained_public_coin_client;
pub mod circle_fft;
pub mod circle_fri;
pub mod circle_hiding;
pub mod claim_source;
pub mod composition_chunks;
pub mod composition_mask;
pub mod cover_nullifier;
pub mod cross_domain;
pub mod deep_quotient;
#[cfg(feature = "std")]
pub mod disk_air;
#[cfg(feature = "std")]
pub mod disk_composition;
#[cfg(feature = "std")]
pub mod disk_deep;
#[cfg(feature = "std")]
pub mod disk_fft;
#[cfg(feature = "std")]
pub mod disk_fri;
#[cfg(feature = "std")]
pub mod disk_logup;
#[cfg(feature = "std")]
pub mod disk_permutation;
pub mod field;
#[cfg(feature = "parallel")]
pub mod file_backed_sumcheck;
pub mod fp16_relay_free_gkr_schedule;
pub mod fp16_relay_free_gkr_source;
pub mod fp16_relay_free_gkr_uniform;
pub mod fp16_zk_rs_gkr_binding;
pub mod fp16_zk_rs_row_sumcheck;
pub mod fri_layer_multiproof;
pub mod fri_pipeline;
pub mod fri_proof;
pub mod gf128;
pub mod gkr_packed_binary_bridge_fp16;
pub mod gkr_packed_bridge;
pub mod gkr_packed_bridge_fp16;
pub mod gkr_pcs_bridge;
pub mod gkr_sumcheck;
#[cfg(feature = "parallel")]
pub mod gkr_worker;
pub mod gkr_zk_mask;
pub mod hash_bus;
#[cfg(feature = "std")]
pub mod hash_bus_b16_boundary;
pub mod hash_bus_b16_gkr_plan;
#[cfg(feature = "std")]
pub mod hash_bus_b16_gkr_worker;
#[cfg(feature = "std")]
pub mod hash_bus_b16_trace;
pub mod hash_bus_snapshot;
pub mod hash_bus_source;
pub mod keccak_circuit;
pub mod keccak_gkr_binary_dag;
pub mod keccak_gkr_dag;
pub mod keccak_gkr_wiring;
pub mod master_commitments;
pub mod merkle;
pub mod merkle_multiproof;
#[cfg(feature = "parallel")]
pub mod mlpcs_gpu_worker;
pub mod multi_factor_sumcheck;
pub mod multilinear_batch_sumcheck;
pub mod multilinear_pcs;
pub mod multilinear_pcs_proof;
pub mod multilinear_pcs_query;
pub mod multilinear_pcs_transcript;
pub mod oods;
pub mod oracle_bundle;
pub mod oracle_commitment;
pub mod ordered_map_schedule;
pub mod packed_boolean_sumcheck;
pub mod payment_keys;
pub mod payment_log;
pub mod policy_bundle;
pub mod proof_format;
pub mod proof_parameters;
pub mod quotient_mask;
pub mod resource_preflight;
pub mod salt_use;
pub mod sampler;
pub mod selected_challenge;
pub mod selected_proof_package;
pub mod sha3_air;
pub mod sha3_boolean_air;
pub mod sha3_coprocessor;
pub mod streaming_ir;
pub mod streaming_mlpcs;
#[cfg(feature = "std")]
pub mod streaming_store;
pub mod trace_mask;
pub mod wave1a_dimensions;
pub mod wave1a_global_schedule;
pub mod wave1b_schedule;
pub mod zk_ring_switch;

pub use field::{Fp2, Fp4, Fp8, Fp16, M31};
