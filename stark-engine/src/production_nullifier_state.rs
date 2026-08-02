use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    StarkBridgeInput,
    production_air_winterfell::{pack_public_input_root_bytes32, unpack_public_input_root_bytes32},
    production_nullifier_root_transition::{
        NULLIFIER_ROOT_CAPACITY, NULLIFIER_ROOT_ENCODING, NULLIFIER_ROOT_HASH_FUNCTION,
        NULLIFIER_ROOT_TREE_DEPTH, ProductionNullifierCommittedLeafV1,
        ProductionNullifierRootTransitionArtifactV1,
        canonical_nullifier_digest_bytes32_from_claim_hash, canonical_nullifier_leaf_index,
        canonical_nullifier_state_root_bytes32,
    },
};

pub const PRODUCTION_NULLIFIER_STATE_SCHEMA_VERSION: &str = "stark-production-nullifier-state-v1";
pub const PRODUCTION_NULLIFIER_STATE_STATUS: &str = "persistent_file_state_compare_and_swap_v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionNullifierStateV1 {
    pub schema_version: String,
    pub state_status: String,
    pub hash_function: String,
    pub root_encoding: String,
    pub tree_depth: usize,
    pub capacity: usize,
    pub generation: u64,
    pub root_elements: [String; 4],
    pub root_bytes32: String,
    pub leaves: Vec<ProductionNullifierCommittedLeafV1>,
    pub governance_status: String,
    pub runtime_wired: bool,
    pub on_chain_verifier_wired: bool,
    pub groth16_flow_unchanged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionNullifierStateApplyReceiptV1 {
    pub schema_version: String,
    pub status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub nullifier_bytes32: String,
    pub leaf_index: usize,
    pub transition_applied: bool,
    pub generation_before: u64,
    pub generation_after: u64,
    pub root_before_bytes32: String,
    pub root_after_bytes32: String,
    pub state_status: String,
    pub groth16_flow_unchanged: bool,
}

pub struct ProductionNullifierStateLock {
    path: PathBuf,
}

impl ProductionNullifierStateV1 {
    pub const GOVERNANCE_STATUS: &'static str = "local_state_not_governance_registered";

    pub fn empty() -> Result<Self, Vec<String>> {
        let root_bytes32 = canonical_nullifier_state_root_bytes32(&[])?;
        let root_elements = root_elements_from_bytes32(&root_bytes32)?;
        let state = Self {
            schema_version: PRODUCTION_NULLIFIER_STATE_SCHEMA_VERSION.to_string(),
            state_status: PRODUCTION_NULLIFIER_STATE_STATUS.to_string(),
            hash_function: NULLIFIER_ROOT_HASH_FUNCTION.to_string(),
            root_encoding: NULLIFIER_ROOT_ENCODING.to_string(),
            tree_depth: NULLIFIER_ROOT_TREE_DEPTH,
            capacity: NULLIFIER_ROOT_CAPACITY,
            generation: 0,
            root_elements,
            root_bytes32,
            leaves: Vec::new(),
            governance_status: Self::GOVERNANCE_STATUS.to_string(),
            runtime_wired: false,
            on_chain_verifier_wired: false,
            groth16_flow_unchanged: true,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for (field, actual, expected) in [
            (
                "schema_version",
                self.schema_version.as_str(),
                PRODUCTION_NULLIFIER_STATE_SCHEMA_VERSION,
            ),
            (
                "state_status",
                self.state_status.as_str(),
                PRODUCTION_NULLIFIER_STATE_STATUS,
            ),
            (
                "hash_function",
                self.hash_function.as_str(),
                NULLIFIER_ROOT_HASH_FUNCTION,
            ),
            (
                "root_encoding",
                self.root_encoding.as_str(),
                NULLIFIER_ROOT_ENCODING,
            ),
            (
                "governance_status",
                self.governance_status.as_str(),
                Self::GOVERNANCE_STATUS,
            ),
        ] {
            if actual != expected {
                errors.push(format!("{field} must be {expected}, got {actual}"));
            }
        }
        if self.tree_depth != NULLIFIER_ROOT_TREE_DEPTH {
            errors.push(format!("tree_depth must be {NULLIFIER_ROOT_TREE_DEPTH}"));
        }
        if self.capacity != NULLIFIER_ROOT_CAPACITY {
            errors.push(format!("capacity must be {NULLIFIER_ROOT_CAPACITY}"));
        }
        if self.leaves.len() > NULLIFIER_ROOT_CAPACITY {
            errors.push("nullifier state exceeds tree capacity".to_string());
        }
        if self.generation != self.leaves.len() as u64 {
            errors
                .push("generation must equal the number of committed approved leaves".to_string());
        }
        match canonical_nullifier_state_root_bytes32(&self.leaves) {
            Ok(expected) if expected != self.root_bytes32 => {
                errors.push("root_bytes32 does not match committed leaves".to_string())
            }
            Ok(expected) => match root_elements_from_bytes32(&expected) {
                Ok(elements) if elements != self.root_elements => {
                    errors.push("root_elements do not match root_bytes32".to_string())
                }
                Ok(_) => {}
                Err(mut value) => errors.append(&mut value),
            },
            Err(mut value) => errors.append(&mut value),
        }
        if self.runtime_wired || self.on_chain_verifier_wired {
            errors.push("state scaffolding must not claim runtime or on-chain wiring".to_string());
        }
        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must remain true".to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn prepare_transition(
        &self,
        bridge: &StarkBridgeInput,
    ) -> Result<ProductionNullifierRootTransitionArtifactV1, Vec<String>> {
        self.validate()?;
        ProductionNullifierRootTransitionArtifactV1::from_bridge_input_with_committed_leaves(
            bridge,
            self.generation,
            &self.leaves,
            ProductionNullifierRootTransitionArtifactV1::PERSISTENT_STATE_SOURCE_STATUS,
        )
    }

    pub fn apply_transition(
        &mut self,
        transition: &ProductionNullifierRootTransitionArtifactV1,
    ) -> Result<ProductionNullifierStateApplyReceiptV1, Vec<String>> {
        self.validate()?;
        transition.validate()?;
        let mut errors = Vec::new();
        if transition.state_source_status
            != ProductionNullifierRootTransitionArtifactV1::PERSISTENT_STATE_SOURCE_STATUS
        {
            errors.push("only persistent-state transitions may be applied".to_string());
        }
        if transition.state_generation_before != self.generation {
            errors.push(format!(
                "stale transition generation: expected {}, got {}",
                self.generation, transition.state_generation_before
            ));
        }
        if transition.nullifier_root_before_bytes32 != self.root_bytes32 {
            errors.push("stale transition root_before does not match current state".to_string());
        }
        if !errors.is_empty() {
            return Err(errors);
        }

        let generation_before = self.generation;
        let root_before_bytes32 = self.root_bytes32.clone();
        if transition.transition_applied {
            let expected_index = canonical_nullifier_leaf_index(&transition.claim_hash)?;
            let expected_nullifier =
                canonical_nullifier_digest_bytes32_from_claim_hash(&transition.claim_hash)?;
            if expected_index != transition.leaf_index
                || expected_nullifier != transition.nullifier_bytes32
            {
                return Err(vec![
                    "transition nullifier identity is not canonical".to_string(),
                ]);
            }
            if self.leaves.iter().any(|leaf| {
                leaf.leaf_index == transition.leaf_index
                    || leaf.claim_hash == transition.claim_hash
                    || leaf.nullifier_bytes32 == transition.nullifier_bytes32
            }) {
                return Err(vec![
                    "duplicate nullifier, claim hash, or deterministic leaf collision".to_string(),
                ]);
            }
            self.leaves.push(ProductionNullifierCommittedLeafV1 {
                leaf_index: transition.leaf_index,
                claim_hash: transition.claim_hash.clone(),
                nullifier_bytes32: transition.nullifier_bytes32.clone(),
            });
            self.leaves.sort_by_key(|leaf| leaf.leaf_index);
        }
        self.generation = transition.state_generation_after;
        self.root_bytes32 = canonical_nullifier_state_root_bytes32(&self.leaves)?;
        self.root_elements = root_elements_from_bytes32(&self.root_bytes32)?;
        if self.root_bytes32 != transition.nullifier_root_after_bytes32 {
            return Err(vec![
                "applied state root does not match transition root_after".to_string(),
            ]);
        }
        self.validate()?;

        Ok(ProductionNullifierStateApplyReceiptV1 {
            schema_version: "stark-production-nullifier-state-apply-receipt-v1".to_string(),
            status: "applied_compare_and_swap".to_string(),
            claim_id: transition.claim_id.clone(),
            claim_hash: transition.claim_hash.clone(),
            nullifier_bytes32: transition.nullifier_bytes32.clone(),
            leaf_index: transition.leaf_index,
            transition_applied: transition.transition_applied,
            generation_before,
            generation_after: self.generation,
            root_before_bytes32,
            root_after_bytes32: self.root_bytes32.clone(),
            state_status: self.state_status.clone(),
            groth16_flow_unchanged: true,
        })
    }
}

impl Drop for ProductionNullifierStateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn load_production_nullifier_state(
    path: impl AsRef<Path>,
) -> Result<ProductionNullifierStateV1, Vec<String>> {
    let path = path.as_ref();
    let json = fs::read_to_string(path)
        .map_err(|error| vec![format!("could not read {}: {error}", path.display())])?;
    let state: ProductionNullifierStateV1 = serde_json::from_str(&json)
        .map_err(|error| vec![format!("invalid nullifier state JSON: {error}")])?;
    state.validate()?;
    Ok(state)
}

pub fn acquire_production_nullifier_state_lock(
    state_path: impl AsRef<Path>,
) -> Result<ProductionNullifierStateLock, Vec<String>> {
    let lock_path = lock_path_for(state_path.as_ref());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|error| {
            vec![format!(
                "could not acquire nullifier state lock {}: {error}",
                lock_path.display()
            )]
        })?;
    writeln!(file, "pid={}", std::process::id())
        .map_err(|error| vec![format!("could not write state lock: {error}")])?;
    file.sync_all()
        .map_err(|error| vec![format!("could not sync state lock: {error}")])?;
    Ok(ProductionNullifierStateLock { path: lock_path })
}

pub fn write_production_nullifier_state_atomic(
    path: impl AsRef<Path>,
    state: &ProductionNullifierStateV1,
) -> Result<(), Vec<String>> {
    state.validate()?;
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| vec![format!("could not create {}: {error}", parent.display())])?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| vec!["nullifier state path must have a UTF-8 file name".to_string()])?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let json = serde_json::to_string_pretty(state)
        .map_err(|error| vec![format!("could not serialize nullifier state: {error}")])?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| vec![format!("could not create {}: {error}", temporary.display())])?;
    file.write_all(format!("{json}\n").as_bytes())
        .map_err(|error| vec![format!("could not write {}: {error}", temporary.display())])?;
    file.sync_all()
        .map_err(|error| vec![format!("could not sync {}: {error}", temporary.display())])?;
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        vec![format!(
            "could not atomically replace {}: {error}",
            path.display()
        )]
    })
}

fn lock_path_for(state_path: &Path) -> PathBuf {
    let mut value = state_path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn root_elements_from_bytes32(value: &str) -> Result<[String; 4], Vec<String>> {
    let elements = unpack_public_input_root_bytes32(value).map_err(|error| vec![error])?;
    let canonical = pack_public_input_root_bytes32(&elements);
    if canonical != value {
        return Err(vec!["root_bytes32 must use canonical encoding".to_string()]);
    }
    Ok(core::array::from_fn(|index| {
        elements[index].as_int().to_string()
    }))
}
