use std::io::{Read, Write};

use slh_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
use slh_dsa::{Shake256f, Signature, SigningKey, VerifyingKey};

const REQUEST_MAGIC: &[u8; 8] = b"BLPQSGN1";
const RESPONSE_MAGIC: &[u8; 8] = b"BLPQSGR1";
const VERSION: u16 = 1;
const SUITE: u16 = 2;
const OP_GENERATE: u16 = 1;
const OP_SIGN: u16 = 2;
const OP_VERIFY: u16 = 3;
const PUBLIC_KEY_BYTES: usize = 64;
const SECRET_KEY_BYTES: usize = 128;
const SIGNATURE_BYTES: usize = 49_856;
const MAX_MESSAGE_BYTES: usize = 64 << 20;

fn read_exact<const N: usize>(input: &mut impl Read) -> Result<[u8; N], &'static str> {
    let mut value = [0_u8; N];
    input
        .read_exact(&mut value)
        .map_err(|_| "service_request_truncated")?;
    Ok(value)
}

fn read_bytes(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let length = usize::try_from(u32::from_be_bytes(read_exact::<4>(input)?))
        .map_err(|_| "service_request_length")?;
    if length == 0 || length > maximum {
        return Err("service_request_length");
    }
    let mut value = vec![0_u8; length];
    input
        .read_exact(&mut value)
        .map_err(|_| "service_request_truncated")?;
    Ok(value)
}

fn write_header(output: &mut impl Write, operation: u16, status: u16) -> Result<(), &'static str> {
    output
        .write_all(RESPONSE_MAGIC)
        .and_then(|_| output.write_all(&VERSION.to_be_bytes()))
        .and_then(|_| output.write_all(&SUITE.to_be_bytes()))
        .and_then(|_| output.write_all(&operation.to_be_bytes()))
        .and_then(|_| output.write_all(&status.to_be_bytes()))
        .map_err(|_| "service_response_write")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    if read_exact::<8>(&mut input)? != *REQUEST_MAGIC
        || u16::from_be_bytes(read_exact::<2>(&mut input)?) != VERSION
        || u16::from_be_bytes(read_exact::<2>(&mut input)?) != SUITE
    {
        return Err("service_request_header".into());
    }
    let operation = u16::from_be_bytes(read_exact::<2>(&mut input)?);
    match operation {
        OP_GENERATE => {
            let mut seeds = [0_u8; 96];
            getrandom::fill(&mut seeds).map_err(|_| "service_entropy")?;
            let signing = SigningKey::<Shake256f>::slh_keygen_internal(
                &seeds[..32],
                &seeds[32..64],
                &seeds[64..],
            );
            seeds.fill(0);
            let public_key = signing.verifying_key().to_vec();
            let secret_key = signing.to_vec();
            if public_key.len() != PUBLIC_KEY_BYTES || secret_key.len() != SECRET_KEY_BYTES {
                return Err("service_key_shape".into());
            }
            write_header(&mut output, OP_GENERATE, 0)?;
            output.write_all(&(public_key.len() as u32).to_be_bytes())?;
            output.write_all(&(secret_key.len() as u32).to_be_bytes())?;
            output.write_all(&public_key)?;
            output.write_all(&secret_key)?;
        }
        OP_SIGN => {
            let mut secret_key_bytes = read_bytes(&mut input, SECRET_KEY_BYTES)?;
            if secret_key_bytes.len() != SECRET_KEY_BYTES {
                return Err("service_secret_key_shape".into());
            }
            let message = read_bytes(&mut input, MAX_MESSAGE_BYTES)?;
            let signing = SigningKey::<Shake256f>::try_from(secret_key_bytes.as_slice())
                .map_err(|_| "service_secret_key_invalid")?;
            secret_key_bytes.fill(0);
            let signature = signing.try_sign(&message)?.to_vec();
            if signature.len() != SIGNATURE_BYTES {
                return Err("service_signature_shape".into());
            }
            write_header(&mut output, OP_SIGN, 0)?;
            output.write_all(&(signature.len() as u32).to_be_bytes())?;
            output.write_all(&signature)?;
        }
        OP_VERIFY => {
            let public_key = read_bytes(&mut input, PUBLIC_KEY_BYTES)?;
            let message = read_bytes(&mut input, MAX_MESSAGE_BYTES)?;
            let signature_bytes = read_bytes(&mut input, SIGNATURE_BYTES)?;
            if public_key.len() != PUBLIC_KEY_BYTES || signature_bytes.len() != SIGNATURE_BYTES {
                return Err("service_verify_shape".into());
            }
            let verifying = VerifyingKey::<Shake256f>::try_from(public_key.as_slice())
                .map_err(|_| "service_public_key_invalid")?;
            let signature = Signature::<Shake256f>::try_from(signature_bytes.as_slice())
                .map_err(|_| "service_signature_invalid")?;
            let valid = verifying.verify(&message, &signature).is_ok();
            write_header(&mut output, OP_VERIFY, 0)?;
            output.write_all(&[u8::from(valid)])?;
        }
        _ => return Err("service_operation".into()),
    }
    let mut trailing = [0_u8; 1];
    if input.read(&mut trailing)? != 0 {
        return Err("service_request_trailing_bytes".into());
    }
    output.flush()?;
    Ok(())
}
