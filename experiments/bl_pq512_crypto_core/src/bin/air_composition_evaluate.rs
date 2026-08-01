use std::io::{self, Read};

use bl_pq512_crypto_core::air_composition::build_air_composition_oracle;
use bl_pq512_crypto_core::air_ir::MAX_AIR_BINARY_BYTES;
use bl_pq512_crypto_core::field::Fp16;
use sha3::{Digest, Sha3_512};

fn take<'a>(encoded: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], ()> {
    let end = offset.checked_add(length).ok_or(())?;
    let value = encoded.get(*offset..end).ok_or(())?;
    *offset = end;
    Ok(value)
}

fn u32_at(encoded: &[u8], offset: &mut usize) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(
        take(encoded, offset, 4)?.try_into().map_err(|_| ())?,
    ))
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let mut input = Vec::new();
    if io::stdin()
        .take((MAX_AIR_BINARY_BYTES * 2 + 1024) as u64)
        .read_to_end(&mut input)
        .is_err()
    {
        std::process::exit(2);
    }
    let parsed = (|| -> Result<_, ()> {
        let mut offset = 0;
        let program_length = usize::try_from(u32_at(&input, &mut offset)?).map_err(|_| ())?;
        let program = take(&input, &mut offset, program_length)?;
        let execution_length = usize::try_from(u32_at(&input, &mut offset)?).map_err(|_| ())?;
        let execution = take(&input, &mut offset, execution_length)?;
        let alpha = Fp16::decode(take(&input, &mut offset, 64)?).map_err(|_| ())?;
        let seed = take(&input, &mut offset, 64)?;
        let session = take(&input, &mut offset, 64)?;
        let mask_count = usize::try_from(u32_at(&input, &mut offset)?).map_err(|_| ())?;
        let log_blowup = *take(&input, &mut offset, 1)?.first().ok_or(())?;
        if offset != input.len() {
            return Err(());
        }
        Ok((
            program, execution, alpha, seed, session, mask_count, log_blowup,
        ))
    })();
    let Ok((program, execution, alpha, seed, session, mask_count, log_blowup)) = parsed else {
        eprintln!("air_composition_input_invalid");
        std::process::exit(2);
    };
    match build_air_composition_oracle(
        program, execution, alpha, seed, session, mask_count, log_blowup,
    ) {
        Ok(oracle) => {
            let mut hash = Sha3_512::new();
            for table in &oracle.tables {
                for value in &table.composition {
                    hash.update(value.encode());
                }
            }
            println!("OK");
            println!("source={}", hex(&oracle.source_program_commitment));
            println!("program={}", hex(&oracle.program_binary_commitment));
            println!("tables={}", oracle.tables.len());
            println!("identities={}", oracle.identity_term_count);
            println!("fixed={}", oracle.fixed_term_count);
            println!("public={}", oracle.public_term_count);
            println!("lookups_pending={}", oracle.lookup_count_pending_logup);
            println!(
                "logs={}",
                oracle
                    .tables
                    .iter()
                    .map(|table| table.evaluation_log_size.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!(
                "composition_coefficients={}",
                oracle
                    .tables
                    .iter()
                    .map(|table| table.composition_coefficient_count.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!("composition_digest={}", hex(&hash.finalize()));
        }
        Err(error) => {
            eprintln!("ERR:{error:?}");
            std::process::exit(2);
        }
    }
}
