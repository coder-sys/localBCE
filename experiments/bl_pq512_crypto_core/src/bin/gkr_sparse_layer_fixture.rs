use std::io::Write;

use bl_pq512_crypto_core::{
    Fp16, gkr_sumcheck::repeated_pack_sparse_layer_gpu_fixture,
    keccak_gkr_wiring::build_keccak_gkr_round, packed_boolean_sumcheck::PACK_BITS,
};

fn fp16(seed: u32) -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coefficient| {
        (u64::from(seed) + 65_537 * coefficient as u64).rem_euclid(2_147_483_647) as u32
    }))
    .expect("fixture coordinates are canonical")
}

fn write_fp16(output: &mut impl Write, value: Fp16) -> std::io::Result<()> {
    for coefficient in value.coefficients() {
        output.write_all(&coefficient.to_le_bytes())?;
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| "fixture_path_missing".to_string())?;
    let permutations = std::env::args()
        .nth(2)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "permutation_count_invalid".to_string())
        })
        .transpose()?;
    if permutations.is_some_and(|count| !matches!(count, 782 | 894)) {
        return Err("permutation_count_must_be_782_or_894".to_string());
    }
    let group_count = if permutations.is_some() { 128 } else { 4 };
    let ordinal = 5;
    let layer =
        build_keccak_gkr_round(ordinal).map_err(|error| error.to_string())?[ordinal].clone();
    let groups = (0..group_count)
        .map(|group| {
            core::array::from_fn(|shard| {
                (0..layer.input_width)
                    .map(|wire| {
                        permutations.map_or(group < 2, |count| group * PACK_BITS + shard < count)
                            && ((wire as u64 + 29 * shard as u64 + 101 * group as u64 + 1)
                                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                                >> 63)
                                == 1
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<[Vec<bool>; PACK_BITS]>>();
    let group_point = (0..group_count.trailing_zeros() as usize)
        .map(|index| fp16(607 + 6 * index as u32))
        .collect::<Vec<_>>();
    let output_point = (0..layer.padded_width.trailing_zeros() as usize)
        .map(|index| fp16(617 + 3 * index as u32))
        .collect::<Vec<_>>();
    let repeated_input_width = layer.input_width * group_count;
    let challenges = (0..2 * repeated_input_width.trailing_zeros() as usize)
        .map(|index| fp16(821 + 5 * index as u32))
        .collect::<Vec<_>>();
    let fixture = repeated_pack_sparse_layer_gpu_fixture(
        &layer,
        &groups,
        &group_point,
        &output_point,
        fp16(811),
        &challenges,
    )
    .map_err(|error| format!("{error:?}"))?;

    let mut output =
        std::io::BufWriter::new(std::fs::File::create(path).map_err(|error| error.to_string())?);
    output
        .write_all(b"BLGKR3\0\0")
        .map_err(|error| error.to_string())?;
    output
        .write_all(
            &u32::try_from(fixture.input.len())
                .map_err(|_| "input_count_overflow".to_string())?
                .to_le_bytes(),
        )
        .map_err(|error| error.to_string())?;
    output
        .write_all(
            &u32::try_from(fixture.terms.len())
                .map_err(|_| "term_count_overflow".to_string())?
                .to_le_bytes(),
        )
        .map_err(|error| error.to_string())?;
    output
        .write_all(
            &u32::try_from(fixture.challenges.len())
                .map_err(|_| "round_count_overflow".to_string())?
                .to_le_bytes(),
        )
        .map_err(|error| error.to_string())?;
    for challenge in fixture.challenges {
        write_fp16(&mut output, challenge).map_err(|error| error.to_string())?;
    }
    for round in fixture.expected_rounds {
        for coefficient in round {
            write_fp16(&mut output, coefficient).map_err(|error| error.to_string())?;
        }
    }
    write_fp16(&mut output, fixture.terminal_left).map_err(|error| error.to_string())?;
    write_fp16(&mut output, fixture.terminal_right).map_err(|error| error.to_string())?;
    for value in fixture.input {
        write_fp16(&mut output, value).map_err(|error| error.to_string())?;
    }
    for term in fixture.terms {
        write_fp16(&mut output, term.output_weight).map_err(|error| error.to_string())?;
        output
            .write_all(&term.left.to_le_bytes())
            .and_then(|_| output.write_all(&term.right.to_le_bytes()))
            .and_then(|_| output.write_all(&[term.formula, 0, 0, 0]))
            .map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("sparse-round fixture failed: {error}");
        std::process::exit(1);
    }
}
