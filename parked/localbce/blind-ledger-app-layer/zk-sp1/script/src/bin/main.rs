use clap::Parser;
use fibonacci_lib::{abi_decode_public_values, expected_public_values, ClaimInput};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1PublicValues, SP1Stdin,
};
use std::time::Instant;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
const CLAIM_ADJUDICATION_ELF: Elf = include_elf!("claim-adjudication-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,
}

#[derive(Clone)]
struct Case {
    name: &'static str,
    input: ClaimInput,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let client = ProverClient::builder().cpu().build();
    let cases = test_cases();

    if args.execute {
        println!("mode=execute");
        for case in &cases {
            let mut stdin = SP1Stdin::new();
            stdin.write(&case.input);
            let start = Instant::now();
            let (output, report) = client
                .execute(CLAIM_ADJUDICATION_ELF, stdin)
                .run()
                .expect("failed to execute claim adjudication guest");
            let elapsed = start.elapsed();
            let actual =
                abi_decode_public_values(output.as_slice()).expect("invalid public values shape");
            let expected = expected_public_values(&case.input);
            assert_eq!(actual.raw_claim_identity_commitment, case.input.raw_claim_identity_commitment, "claim identity mismatch for {}", case.name);
            assert_eq!(actual.batch_context_commitment, case.input.batch_context_commitment, "batch context mismatch for {}", case.name);
            assert_eq!((actual.decision, actual.failure_code), expected, "public output mismatch for {}", case.name);
            println!(
                "case={} decision={} failure_code={} execute_ms={} cycles={}",
                case.name,
                actual.decision,
                actual.failure_code,
                elapsed.as_millis(),
                report.total_instruction_count()
            );
        }
    } else {
        println!("mode=prove_core");
        println!("prover=SP1 local CPU core proof");
        let setup_start = Instant::now();
        let pk = client
            .setup(CLAIM_ADJUDICATION_ELF)
            .expect("failed to setup claim adjudication elf");
        println!("setup_ms={}", setup_start.elapsed().as_millis());

        let mut tamper_result = String::from("not_run");
        for (idx, case) in cases.iter().enumerate() {
            let mut stdin = SP1Stdin::new();
            stdin.write(&case.input);
            let expected = expected_public_values(&case.input);

            let prove_start = Instant::now();
            let proof = client
                .prove(&pk, stdin)
                .core()
                .run()
                .expect("failed to generate SP1 core proof");
            let prove_elapsed = prove_start.elapsed();

            let public_values = proof.public_values.as_slice();
            let actual =
                abi_decode_public_values(public_values).expect("invalid public values shape");
            assert_eq!(actual.raw_claim_identity_commitment, case.input.raw_claim_identity_commitment, "claim identity mismatch for {}", case.name);
            assert_eq!(actual.batch_context_commitment, case.input.batch_context_commitment, "batch context mismatch for {}", case.name);
            assert_eq!((actual.decision, actual.failure_code), expected, "public output mismatch for {}", case.name);

            let verify_start = Instant::now();
            client
                .verify(&proof, pk.verifying_key(), None)
                .expect("failed to verify SP1 core proof");
            let verify_elapsed = verify_start.elapsed();
            let serialized_size =
                bincode::serialized_size(&proof).expect("failed to size serialized proof");

            println!(
                "case={} decision={} failure_code={} proof_size_bytes={} prove_ms={} verify_ms={} status=PASS",
                case.name,
                actual.decision,
                actual.failure_code,
                serialized_size,
                prove_elapsed.as_millis(),
                verify_elapsed.as_millis()
            );

            if idx == 0 {
                let mut tampered = proof.clone();
                let mut tampered_public_values = tampered.public_values.to_vec();
                tampered_public_values[31] ^= 1;
                tampered.public_values = SP1PublicValues::from(&tampered_public_values);
                tamper_result = match client.verify(&tampered, pk.verifying_key(), None) {
                    Ok(()) => String::from("FAILED_ACCEPTED_TAMPER"),
                    Err(err) => format!("PASS_REJECTED_TAMPER error={err:?}"),
                };
            }
        }
        println!("tamper_test={}", tamper_result);
    }
}

fn test_cases() -> Vec<Case> {
    let approved = ClaimInput {
        raw_claim_identity_commitment: claim_identity(1),
        batch_context_commitment: batch_context(1),
        member_id_present: true,
        eligibility_active: true,
        provider_npi_present: true,
        provider_enrolled: true,
        service_line_present: true,
        diagnosis_present: true,
        prior_auth_ok: true,
        charge_cents: 12_500,
        max_charge_cents: 500_000,
        duplicate_claim: false,
        program_integrity_hold: false,
    };

    let mut ineligible_denied = approved;
    ineligible_denied.eligibility_active = false;

    let mut duplicate_denied = approved;
    duplicate_denied.duplicate_claim = true;

    let mut excessive_charge_denied = approved;
    excessive_charge_denied.charge_cents = 500_001;

    vec![
        Case {
            name: "approved",
            input: approved,
        },
        Case {
            name: "ineligible_denied",
            input: ineligible_denied,
        },
        Case {
            name: "duplicate_denied",
            input: duplicate_denied,
        },
        Case {
            name: "excessive_charge_denied",
            input: excessive_charge_denied,
        },
    ]
}

fn claim_identity(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = seed;
    out[31] = seed ^ 0xA5;
    out
}

fn batch_context(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = seed;
    out[1] = seed ^ 0x33;
    out[31] = seed ^ 0xC3;
    out
}
