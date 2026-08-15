//! Create fresh nonactivating calibration custody for one bridge proof.
//!
//! This is deliberately separate from proof production. It derives the frozen
//! schedule before generating a key, publishes all private material only into
//! an explicitly supplied custody directory, and never claims independent
//! organizational contributors or production activation.

use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use bl_pq512_crypto_core::{
    binding_root_v2::{BINDING_V2_BYTES, BindingDigestV2},
    field::Fp16,
    semantic_h4_bridge_gkr::{
        SemanticH4BridgeProfile, semantic_h4_bridge_governed_schedule,
        semantic_h4_bridge_mask_layout,
    },
    strict_pq_public_coin_v2::{
        STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, STRICT_PQ_LAMPORT_SECRET_BYTES_V2,
        StrictPqGovernedVerifierKeyV2, StrictPqKeyContextV2, StrictPqLamportSecretKeyV2,
    },
};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

const USAGE: &str = "usage: semantic_h4_bridge_custody_prepare <K128_CALIBRATION|K512_CALIBRATION> <context.bin|integration-payload:FILE> <epoch-u64> <statement-sequence-u64> <attempt-u8> <new-custody-directory>";
const SECRET_BYTES: usize = STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2 * STRICT_PQ_LAMPORT_SECRET_BYTES_V2;

fn profile(value: &str) -> Result<SemanticH4BridgeProfile, String> {
    match value {
        "K128_CALIBRATION" => Ok(SemanticH4BridgeProfile::K128),
        "K512_CALIBRATION" => Ok(SemanticH4BridgeProfile::K512),
        _ => Err("profile_invalid".to_owned()),
    }
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut value = Sha3_512::new();
    value.update(domain);
    for part in parts {
        value.update((part.len() as u64).to_be_bytes());
        value.update(part);
    }
    value.finalize().into()
}

fn random_bytes(count: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut value = vec![0_u8; count];
    getrandom::fill(&mut value).map_err(|error| format!("{label}_entropy:{error}"))?;
    Ok(value)
}

fn random_nonzero<const N: usize>(label: &str) -> Result<[u8; N], String> {
    let value = random_bytes(N, label)?;
    let result: [u8; N] = value.try_into().map_err(|_| format!("{label}_shape"))?;
    if result.iter().all(|byte| *byte == 0) {
        return Err(format!("{label}_zero"));
    }
    Ok(result)
}

fn random_fp16() -> Result<Fp16, String> {
    let mut coefficients = [0_u32; 16];
    for coefficient in &mut coefficients {
        loop {
            let bytes: [u8; 4] = random_bytes(4, "mask")?
                .try_into()
                .map_err(|_| "mask_shape".to_owned())?;
            let candidate = u32::from_le_bytes(bytes) & 0x7fff_ffff;
            if candidate < 2_147_483_647 {
                *coefficient = candidate;
                break;
            }
        }
    }
    Fp16::from_coefficients(coefficients).map_err(|error| format!("mask_field:{error:?}"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("output_open:{:?}", error.kind()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("output_write:{:?}", error.kind()))
}

struct ContributorMaterial {
    contributor_id: [u8; 64],
    public_key: bl_pq512_crypto_core::strict_pq_public_coin_v2::StrictPqLamportPublicKeyV2,
    secret: Vec<u8>,
    tail: [u8; BINDING_V2_BYTES],
}

fn run(args: &[OsString]) -> Result<(), String> {
    if args.len() != 7 {
        return Err(USAGE.to_owned());
    }
    let selected = profile(args[1].to_str().ok_or("profile_utf8")?)?;
    let context_argument = args[2].to_str().ok_or("context_utf8")?;
    let integration_payload = context_argument.strip_prefix("integration-payload:");
    let context_path = PathBuf::from(integration_payload.unwrap_or(context_argument));
    if !context_path.is_absolute() {
        return Err("context_path_not_absolute".to_owned());
    }
    let supplied_context =
        fs::read(&context_path).map_err(|error| format!("context_read:{:?}", error.kind()))?;
    if supplied_context.is_empty() || supplied_context.len() > 64 * 1024 * 1024 {
        return Err("context_input_length".to_owned());
    }
    let context_bytes = if integration_payload.is_some() {
        BindingDigestV2::hash(
            bl_pq512_crypto_core::binding_root_v2::BindingRoleV2::Payload,
            &supplied_context,
        )
        .map_err(|error| format!("integration_context_hash:{error:?}"))?
        .to_bytes()
        .to_vec()
    } else {
        supplied_context
    };
    let context = BindingDigestV2::decode(&context_bytes)
        .map_err(|error| format!("context_decode:{error:?}"))?;
    let epoch = args[3]
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or("epoch_invalid")?;
    let sequence = args[4]
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or("sequence_invalid")?;
    let attempt = args[5]
        .to_str()
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or("attempt_invalid")?;
    let output = PathBuf::from(&args[6]);
    if !output.is_absolute() || output.exists() {
        return Err("custody_must_be_new_absolute_directory".to_owned());
    }
    let partial = PathBuf::from(format!("{}.partial", output.display()));
    if partial.exists() {
        return Err("partial_exists".to_owned());
    }

    let (schedule, round_count) = semantic_h4_bridge_governed_schedule(selected, context, 0)
        .map_err(|error| format!("schedule:{error:?}"))?;
    let session_id = random_nonzero::<64>("session")?;
    let candidate = hash(
        b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/CANDIDATE/v1\0",
        &[&[match selected {
            SemanticH4BridgeProfile::K128 => 1,
            SemanticH4BridgeProfile::K512 => 3,
        }]],
    );
    let schema = hash(
        b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/SCHEMA/v1\0",
        &[context.as_bytes()],
    );
    let statement = hash(
        b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/STATEMENT/v1\0",
        &[context.as_bytes(), &session_id, &schedule],
    );
    let mut contributors = Vec::with_capacity(2);
    for index in 0_u8..2 {
        let contributor_id = hash(
            b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/LOCAL-CALIBRATION-CONTRIBUTOR/v1\0",
            &[&[index], &session_id],
        );
        let key_id = hash(
            b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/LOCAL-CALIBRATION-KEY/v1\0",
            &[&[index], &session_id],
        );
        let key_context = StrictPqKeyContextV2::new(
            candidate,
            schema,
            epoch,
            sequence,
            statement,
            contributor_id,
            key_id,
            attempt,
        )
        .map_err(|error| format!("key_context:{error:?}"))?;
        let mut secret = random_bytes(SECRET_BYTES, "lamport_secret")?;
        let secret_words = secret
            .chunks_exact(STRICT_PQ_LAMPORT_SECRET_BYTES_V2)
            .map(|chunk| {
                <[u8; STRICT_PQ_LAMPORT_SECRET_BYTES_V2]>::try_from(chunk).expect("exact chunk")
            })
            .collect::<Vec<_>>();
        let (_, public_key) =
            StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(key_context, secret_words)
                .map_err(|error| {
                    secret.zeroize();
                    format!("lamport_keygen:{error:?}")
                })?;
        contributors.push(ContributorMaterial {
            contributor_id,
            public_key,
            secret,
            tail: random_nonzero::<BINDING_V2_BYTES>("chain_tail")?,
        });
    }
    contributors.sort_by_key(|value| value.contributor_id);
    let governed = StrictPqGovernedVerifierKeyV2::new(
        session_id,
        schedule,
        round_count,
        contributors
            .iter()
            .map(|value| value.public_key.clone())
            .collect(),
    )
    .map_err(|error| format!("governed_key:{error:?}"))?;
    let layout = semantic_h4_bridge_mask_layout(selected)
        .map_err(|error| format!("mask_layout:{error:?}"))?;
    let mut masks = Vec::with_capacity(layout.padded_coefficients * 64);
    for _ in 0..layout.padded_coefficients {
        masks.extend_from_slice(&random_fp16()?.encode());
    }
    if masks.iter().all(|byte| *byte == 0) {
        return Err("mask_all_zero".to_owned());
    }

    fs::create_dir(&partial).map_err(|error| format!("partial_create:{:?}", error.kind()))?;
    let publish = (|| {
        write_new(&partial.join("h4-gkr-key.bin"), &governed.encode())?;
        write_new(&partial.join("h4-gkr-mask-coefficients.bin"), &masks)?;
        write_new(
            &partial.join("h4-gkr-secret-0.bin"),
            &contributors[0].secret,
        )?;
        write_new(&partial.join("h4-gkr-tail-0.bin"), &contributors[0].tail)?;
        write_new(
            &partial.join("h4-gkr-secret-1.bin"),
            &contributors[1].secret,
        )?;
        write_new(&partial.join("h4-gkr-tail-1.bin"), &contributors[1].tail)?;
        write_new(&partial.join("h4-gkr-schedule.bin"), &schedule)?;
        write_new(&partial.join("h4-gkr-session.bin"), &session_id)?;
        write_new(&partial.join("h4-gkr-context.bin"), &context_bytes)?;
        fs::rename(&partial, &output).map_err(|error| format!("custody_publish:{:?}", error.kind()))
    })();
    for contributor in &mut contributors {
        contributor.secret.zeroize();
        contributor.tail.zeroize();
    }
    masks.zeroize();
    if let Err(error) = publish {
        let _ = fs::remove_dir_all(&partial);
        return Err(error);
    }
    println!("status=SEMANTIC_H4_BRIDGE_LOCAL_CALIBRATION_CUSTODY_PREPARED");
    println!("round_count={round_count}");
    println!("mask_coefficients={}", layout.padded_coefficients);
    println!("independent_contributor_authority=false");
    println!(
        "integration_context_derived={}",
        integration_payload.is_some()
    );
    println!("proofSuiteId=null");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("semantic_h4_bridge_custody_prepare_error={error}");
            eprintln!("proofSuiteId=null");
            eprintln!("production_usable=false");
            eprintln!("activation_allowed=false");
            ExitCode::from(2)
        }
    }
}
