use methods::{PRIVACY_V2_GUEST_ELF, PRIVACY_V2_GUEST_ID};
use privacy_v2_model::{encode_witness, execute_complete_claim, kat_complete_claim_witness};
use risc0_zkvm::{
    get_prover_server, ExecutorEnv, ExecutorImpl, ProverOpts, Segment, SessionEvents,
    VerifierContext,
};
use std::{
    cell::RefCell,
    rc::Rc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
struct SegmentTiming {
    index: u32,
    po2: usize,
    elapsed: Duration,
}

struct SegmentTimer {
    active: RefCell<Option<(u32, usize, Instant)>>,
    samples: Rc<RefCell<Vec<SegmentTiming>>>,
}

impl SessionEvents for SegmentTimer {
    fn on_pre_prove_segment(&self, segment: &Segment) {
        let previous = self
            .active
            .replace(Some((segment.index, segment.po2(), Instant::now())));
        assert!(previous.is_none(), "segment timing hook cannot overlap");
        eprintln!(
            "profile_event=segment_prove_start segment_index={} segment_po2={}",
            segment.index,
            segment.po2()
        );
    }

    fn on_post_prove_segment(&self, segment: &Segment) {
        let (index, po2, started) = self
            .active
            .borrow_mut()
            .take()
            .expect("segment timing hook must have a start");
        assert_eq!(index, segment.index, "segment timing hook index mismatch");
        let elapsed = started.elapsed();
        eprintln!(
            "profile_event=segment_prove_end segment_index={index} segment_po2={po2} elapsed_ns={}",
            elapsed.as_nanos()
        );
        self.samples.borrow_mut().push(SegmentTiming {
            index,
            po2,
            elapsed,
        });
    }
}

fn apportioned_percent_units(values: &[u128]) -> Vec<u128> {
    const TOTAL_PERCENT_UNITS: u128 = 100_000_000;
    let total: u128 = values.iter().sum();
    assert!(total > 0, "profile total must be positive");

    let mut units = Vec::with_capacity(values.len());
    let mut remainders = Vec::with_capacity(values.len());
    for (index, value) in values.iter().copied().enumerate() {
        let scaled = value * TOTAL_PERCENT_UNITS;
        units.push(scaled / total);
        remainders.push((scaled % total, index));
    }

    let assigned: u128 = units.iter().sum();
    let missing = usize::try_from(TOTAL_PERCENT_UNITS - assigned)
        .expect("percentage rounding remainder must fit usize");
    remainders.sort_by(|left, right| right.cmp(left));
    for (_, index) in remainders.into_iter().take(missing) {
        units[index] += 1;
    }
    assert_eq!(units.iter().sum::<u128>(), TOTAL_PERCENT_UNITS);
    units
}

fn print_profile(prefix: &str, stages: &[(String, u128)]) {
    let values: Vec<u128> = stages.iter().map(|(_, nanoseconds)| *nanoseconds).collect();
    let percentages = apportioned_percent_units(&values);
    let total: u128 = values.iter().sum();
    println!("{prefix}_total_ns={total}");
    println!("{prefix}_stage_count={}", stages.len());
    for ((name, nanoseconds), percent_units) in stages.iter().zip(percentages) {
        println!(
            "{prefix}_stage={name} elapsed_ns={nanoseconds} percent={}.{:06}",
            percent_units / 1_000_000,
            percent_units % 1_000_000
        );
    }
    println!("{prefix}_percent_sum=100.000000");
}

fn hex_field(field: &[u8; 32]) -> String {
    let mut output = String::with_capacity(66);
    output.push_str("0x");
    for byte in field {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let prepare_started = Instant::now();
    let input = kat_complete_claim_witness();
    let execution =
        execute_complete_claim(&input).expect("validate complete synthetic claim model");
    if std::env::args().nth(1).as_deref() == Some("model") {
        println!("backend=risc0-model-only");
        println!("public_output_count={}", execution.public_fields.len());
        for (index, field) in execution.public_fields.iter().enumerate() {
            println!("public_output[{index}]={}", hex_field(field));
        }
        return;
    }
    let wire = encode_witness(&input).expect("serialize exact complete-claim witness wire format");
    let env = ExecutorEnv::builder()
        .write(&wire)
        .expect("serialize private complete-claim wire bytes")
        .build()
        .expect("build RISC Zero execution environment");
    let prepare_elapsed = prepare_started.elapsed();

    eprintln!("profile_event=guest_execution_start");
    let execute_started = Instant::now();
    let mut executor =
        ExecutorImpl::from_elf(env, PRIVACY_V2_GUEST_ELF).expect("load pinned guest ELF");
    let mut session = executor
        .run()
        .expect("execute complete private claim and build proof segments");
    let execute_elapsed = execute_started.elapsed();
    eprintln!(
        "profile_event=guest_execution_end elapsed_ns={} segments={} total_cycles={}",
        execute_elapsed.as_nanos(),
        session.segments.len(),
        session.total_cycles
    );

    let segment_samples = Rc::new(RefCell::new(Vec::new()));
    session.add_hook(SegmentTimer {
        active: RefCell::new(None),
        samples: Rc::clone(&segment_samples),
    });

    let prover_init_started = Instant::now();
    let prover = get_prover_server(&ProverOpts::default())
        .expect("initialize local non-development RISC Zero prover");
    let prover_init_elapsed = prover_init_started.elapsed();

    eprintln!("profile_event=prove_session_start");
    let prove_session_started = Instant::now();
    let prove_info = prover
        .prove_session(&VerifierContext::default(), &session)
        .expect("generate non-development RISC Zero receipt");
    let prove_session_elapsed = prove_session_started.elapsed();
    eprintln!(
        "profile_event=prove_session_end elapsed_ns={}",
        prove_session_elapsed.as_nanos()
    );
    let receipt = prove_info.receipt;

    let verify_started = Instant::now();
    receipt
        .verify(PRIVACY_V2_GUEST_ID)
        .expect("verify RISC Zero receipt against pinned guest image");
    let verify_elapsed = verify_started.elapsed();

    let compare_started = Instant::now();
    let output: [[u8; 32]; 12] = receipt
        .journal
        .decode()
        .expect("decode exact 12-field V2 journal");
    assert_eq!(output, execution.public_fields);
    let compare_elapsed = compare_started.elapsed();

    let samples = segment_samples.borrow();
    assert_eq!(samples.len(), session.segments.len());
    let segment_total_ns: u128 = samples.iter().map(|sample| sample.elapsed.as_nanos()).sum();
    let prove_session_ns = prove_session_elapsed.as_nanos();
    assert!(segment_total_ns <= prove_session_ns);
    let mut wall_stages = vec![
        ("host_prepare".to_string(), prepare_elapsed.as_nanos()),
        (
            "guest_execute_and_segment".to_string(),
            execute_elapsed.as_nanos(),
        ),
        (
            "prover_initialize".to_string(),
            prover_init_elapsed.as_nanos(),
        ),
    ];
    for sample in samples.iter() {
        wall_stages.push((
            format!("segment_{}_prove_po2_{}", sample.index, sample.po2),
            sample.elapsed.as_nanos(),
        ));
    }
    wall_stages.extend([
        (
            "proof_finalize_and_internal_verify".to_string(),
            prove_session_ns - segment_total_ns,
        ),
        (
            "receipt_external_verify".to_string(),
            verify_elapsed.as_nanos(),
        ),
        (
            "journal_decode_and_kat_compare".to_string(),
            compare_elapsed.as_nanos(),
        ),
    ]);

    let cycle_stages = vec![
        ("user".to_string(), u128::from(session.user_cycles)),
        ("paging".to_string(), u128::from(session.paging_cycles)),
        (
            "reserved_and_padding".to_string(),
            u128::from(session.reserved_cycles),
        ),
    ];

    println!("backend=risc0-zkvm-3.0.5");
    println!("development_mode=false");
    println!("proof_verified=true");
    println!("complete_private_claim_proven=true");
    println!("journal_matches_python_cairo_kat=true");
    println!("public_output_count={}", output.len());
    println!("journal_bytes={}", receipt.journal.bytes.len());
    println!("profile_clock=std::time::Instant_monotonic");
    println!("profile_percent_method=largest_remainder_from_raw_integer_counts");
    print_profile("wall_time", &wall_stages);
    print_profile("vm_cycles", &cycle_stages);
    for (index, field) in output.iter().enumerate() {
        println!("public_output[{index}]={}", hex_field(field));
    }
}
