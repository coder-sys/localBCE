use std::io::{Read, Write};

use bl_pq512_crypto_core::chained_public_coin::{
    ChainedContributor, PqSignatureSuite, chain_head_signature_message, chain_step,
};
use getrandom::fill;
use ml_dsa::{
    Keypair as _, MlDsa87, Seed, SignatureEncoding as _, Signer as _, SigningKey as MlDsaSigningKey,
};
use slh_dsa::{Shake256f, SigningKey as SlhDsaSigningKey};

const REQUEST_MAGIC: &[u8; 8] = b"BLPCSRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"BLPCSRS1";
const ROUND_MAGIC: &[u8; 8] = b"BLPCRND1";
const MAX_ROUNDS: u32 = 65_535;

fn read_exact<const N: usize>(input: &mut impl Read) -> Result<[u8; N], std::io::Error> {
    let mut value = [0_u8; N];
    input.read_exact(&mut value)?;
    Ok(value)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    if &read_exact::<8>(&mut input)? != REQUEST_MAGIC {
        return Err("service request magic".into());
    }
    let suite = match u16::from_be_bytes(read_exact::<2>(&mut input)?) {
        1 => PqSignatureSuite::MlDsa87,
        2 => PqSignatureSuite::SlhDsaShake256f,
        _ => return Err("service suite".into()),
    };
    let session_id = read_exact::<64>(&mut input)?;
    let attempt = u16::from_be_bytes(read_exact::<2>(&mut input)?);
    let schedule_commitment = read_exact::<64>(&mut input)?;
    let round_count = u32::from_be_bytes(read_exact::<4>(&mut input)?);
    let contributor_id = read_exact::<64>(&mut input)?;
    let key_id = read_exact::<64>(&mut input)?;
    if attempt >= 16
        || round_count == 0
        || round_count > MAX_ROUNDS
        || !session_id.iter().any(|byte| *byte != 0)
        || !schedule_commitment.iter().any(|byte| *byte != 0)
        || !contributor_id.iter().any(|byte| *byte != 0)
        || !key_id.iter().any(|byte| *byte != 0)
    {
        return Err("service request shape".into());
    }

    let mut tail = [0_u8; 64];
    fill(&mut tail).map_err(|_| "service entropy")?;
    let mut chain = vec![[0_u8; 64]; usize::try_from(round_count)? + 1];
    chain[usize::try_from(round_count)?] = tail;
    tail.fill(0);
    for round in (0..round_count).rev() {
        chain[usize::try_from(round)?] = chain_step(
            &session_id,
            attempt,
            &schedule_commitment,
            &contributor_id,
            round,
            &chain[usize::try_from(round + 1)?],
        );
    }

    let (public_key, signature) = match suite {
        PqSignatureSuite::MlDsa87 => {
            let mut seed_bytes = [0_u8; 32];
            fill(&mut seed_bytes).map_err(|_| "service entropy")?;
            let signing = MlDsaSigningKey::<MlDsa87>::from_seed(&Seed::from(seed_bytes));
            seed_bytes.fill(0);
            let mut contributor = ChainedContributor {
                contributor_id,
                key_id,
                suite,
                public_key: signing.verifying_key().encode().to_vec(),
                chain_head: chain[0],
                head_signature: Vec::new(),
            };
            let message = chain_head_signature_message(
                &session_id,
                attempt,
                &schedule_commitment,
                round_count,
                &contributor,
            );
            contributor.head_signature = signing.sign(&message).to_bytes().to_vec();
            (contributor.public_key, contributor.head_signature)
        }
        PqSignatureSuite::SlhDsaShake256f => {
            let mut seeds = [0_u8; 96];
            fill(&mut seeds).map_err(|_| "service entropy")?;
            let signing = SlhDsaSigningKey::<Shake256f>::slh_keygen_internal(
                &seeds[..32],
                &seeds[32..64],
                &seeds[64..],
            );
            seeds.fill(0);
            let mut contributor = ChainedContributor {
                contributor_id,
                key_id,
                suite,
                public_key: signing.verifying_key().to_bytes().to_vec(),
                chain_head: chain[0],
                head_signature: Vec::new(),
            };
            let message = chain_head_signature_message(
                &session_id,
                attempt,
                &schedule_commitment,
                round_count,
                &contributor,
            );
            contributor.head_signature = signing.try_sign(&message)?.to_bytes().to_vec();
            (contributor.public_key, contributor.head_signature)
        }
    };

    output.write_all(RESPONSE_MAGIC)?;
    output.write_all(&(suite as u16).to_be_bytes())?;
    output.write_all(&u32::try_from(public_key.len())?.to_be_bytes())?;
    output.write_all(&u32::try_from(signature.len())?.to_be_bytes())?;
    output.write_all(&chain[0])?;
    output.write_all(&public_key)?;
    output.write_all(&signature)?;
    output.flush()?;

    for expected_round in 0..round_count {
        if &read_exact::<8>(&mut input)? != ROUND_MAGIC {
            return Err("service round magic".into());
        }
        if u32::from_be_bytes(read_exact::<4>(&mut input)?) != expected_round {
            return Err("service round order".into());
        }
        let message_digest = read_exact::<64>(&mut input)?;
        if !message_digest.iter().any(|byte| *byte != 0) {
            return Err("service prover message digest".into());
        }
        output.write_all(&chain[usize::try_from(expected_round + 1)?])?;
        output.flush()?;
    }
    chain.fill([0_u8; 64]);
    Ok(())
}
