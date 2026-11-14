//! ML-DSA-87 (FIPS 204 algorithm, non-validated AWS-LC build) custody worker for RR/GATE. A key file holds a
//! seed sealed by DPAPI (user scope); the seed never leaves this process. Binary stdin and stdout.
//!   keygen <file>     : (nothing)  -> public key (2592); creates <file>, never overwrites
//!   public-key <file> : (nothing)  -> public key
//!   sign <file>       : message    -> signature (4627): pure ML-DSA, empty context, hedged; the worker
//!                       verifies it against the key's own public key first (fault defence), else no output
//! Known-answer modes run AWS-LC's FIPS 204 internal functions (M' is passed whole, rnd is 32 bytes):
//!   kat-keygen : seed(32)              -> pk (2592) || sk (4896)
//!   kat-sign   : sk || rnd || M'       -> signature
//!   kat-verify : pk || sig(4627) || M' -> one byte, 1 valid or 0 invalid
//!   (no arguments) : resident signer, framed `sign` requests (see `serve`)
//! Success exits 0; any malformed or refused input exits 2. Messages are bounded at 64 KiB.
use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_87, ML_DSA_87_SIGNING};
use std::ffi::c_void;
use std::io::{Read, Write};
use std::ptr::{null, null_mut};

const SEED: usize = 32;
const PUBLIC_KEY: usize = 2592;
const SECRET_KEY: usize = 4896;
const SIGNATURE: usize = 4627;
const MAX_MESSAGE: usize = 64 * 1024;
const ENTROPY: &[u8] = b"RR/GATE/KEY-FILE/v1\0";
const UI_FORBIDDEN: u32 = 1;

#[repr(C)]
struct Blob {
    len: u32,
    data: *mut u8,
}

#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(i: *const Blob, d: *const u16, e: *const Blob, r: *mut c_void, p: *mut c_void, f: u32, o: *mut Blob) -> i32;
    fn CryptUnprotectData(i: *const Blob, d: *mut *mut u16, e: *const Blob, r: *mut c_void, p: *mut c_void, f: u32, o: *mut Blob) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(m: *mut c_void) -> *mut c_void;
}
extern "C" {
    #[link_name = "aws_lc_0_45_0_ml_dsa_87_keypair_internal"]
    fn keypair_internal(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    #[link_name = "aws_lc_0_45_0_ml_dsa_87_sign_internal"]
    fn sign_internal(sk: *const u8, sig: *mut u8, len: *mut usize, m: *const u8, n: usize, pre: *const u8, p: usize, rnd: *const u8) -> i32;
    #[link_name = "aws_lc_0_45_0_ml_dsa_87_verify_internal"]
    fn verify_internal(pk: *const u8, sig: *const u8, len: usize, m: *const u8, n: usize, pre: *const u8, p: usize) -> i32;
}

fn fail() -> ! {
    std::process::exit(2)
}

fn wipe(bytes: &mut [u8]) {
    for b in bytes {
        unsafe { std::ptr::write_volatile(b, 0) }
    }
}

/// Seal or unseal with DPAPI; the caller wipes the result.
fn dpapi(seal: bool, data: &[u8]) -> Option<Vec<u8>> {
    let blob = |d: &[u8]| Blob { len: d.len() as u32, data: d.as_ptr() as *mut u8 };
    let (input, entropy, mut out) = (blob(data), blob(ENTROPY), Blob { len: 0, data: null_mut() });
    unsafe {
        let ok = if seal {
            CryptProtectData(&input, null(), &entropy, null_mut(), null_mut(), UI_FORBIDDEN, &mut out)
        } else {
            CryptUnprotectData(&input, null_mut(), &entropy, null_mut(), null_mut(), UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            return None;
        }
        let bytes = std::slice::from_raw_parts_mut(out.data, out.len as usize);
        let copy = bytes.to_vec();
        wipe(bytes);
        LocalFree(out.data as *mut c_void);
        Some(copy)
    }
}

fn pair(seed: &mut [u8]) -> PqdsaKeyPair {
    let key = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed);
    wipe(seed);
    key.unwrap_or_else(|_| fail())
}

/// Unseal the key file, sign `msg` (pure, hedged) and self-verify; None on any refusal. No key outlives the call.
fn sign_file(path: &str, msg: &[u8]) -> Option<Vec<u8>> {
    let mut seed = std::fs::read(path).ok().and_then(|b| dpapi(false, &b))?;
    let key = pair(&mut seed);
    let mut signature = vec![0u8; SIGNATURE];
    let sound = msg.len() <= MAX_MESSAGE
        && key.sign(msg, &mut signature) == Ok(SIGNATURE)
        && UnparsedPublicKey::new(&ML_DSA_87, key.public_key().as_ref()).verify(msg, &signature).is_ok();
    sound.then_some(signature)
}

/// No arguments: frames `u32 BE L || u16 BE p || path (p bytes, UTF-8) || message` on stdin, each answered by
/// `u32 BE 4627 || signature` on stdout; clean EOF between frames exits 0, anything else exits 2. Never stderr.
fn serve() -> ! {
    let (mut stdin, mut stdout) = (std::io::stdin().lock(), std::io::stdout().lock());
    loop {
        let mut head = [0u8; 4];
        match stdin.read(&mut head[..1]) {
            Ok(0) => std::process::exit(0),
            Ok(_) => {}
            Err(_) => fail(),
        }
        stdin.read_exact(&mut head[1..]).unwrap_or_else(|_| fail());
        let len = u32::from_be_bytes(head) as usize;
        if !(2..=2 + 32767 + MAX_MESSAGE).contains(&len) {
            fail();
        }
        let mut frame = vec![0u8; len];
        stdin.read_exact(&mut frame).unwrap_or_else(|_| fail());
        let plen = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        if plen == 0 || plen > 32767 || 2 + plen > len || len - 2 - plen > MAX_MESSAGE {
            fail();
        }
        let path = std::str::from_utf8(&frame[2..2 + plen]).unwrap_or_else(|_| fail());
        let signature = sign_file(path, &frame[2 + plen..]).unwrap_or_else(|| fail());
        let mut reply = (SIGNATURE as u32).to_be_bytes().to_vec();
        reply.extend_from_slice(&signature);
        stdout.write_all(&reply).and_then(|_| stdout.flush()).unwrap_or_else(|_| fail());
    }
}

fn main() {
    if std::env::args_os().count() == 1 {
        serve();
    }
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let file = args.next();
    let kat = mode.starts_with("kat-");
    if args.next().is_some() || file.is_some() == kat || !(kat || matches!(mode.as_str(), "keygen" | "public-key" | "sign")) {
        fail();
    }
    let mut input = Vec::new();
    let limit = (PUBLIC_KEY + SIGNATURE + MAX_MESSAGE + 1) as u64;
    if mode != "keygen" && mode != "public-key" && std::io::stdin().take(limit).read_to_end(&mut input).is_err() {
        fail();
    }
    let path = file.unwrap_or_default();
    let output = match mode.as_str() {
        "keygen" => {
            let mut seed = vec![0u8; SEED];
            aws_lc_rs::rand::fill(&mut seed).unwrap_or_else(|_| fail());
            let sealed = dpapi(true, &seed).unwrap_or_else(|| fail());
            let created = std::fs::OpenOptions::new().write(true).create_new(true).open(&path);
            created.and_then(|mut f| f.write_all(&sealed).and_then(|_| f.sync_all())).unwrap_or_else(|_| fail());
            pair(&mut seed).public_key().as_ref().to_vec()
        }
        "public-key" | "sign" => {
            if mode == "sign" {
                sign_file(&path, &input).unwrap_or_else(|| fail())
            } else {
                let mut seed = std::fs::read(&path).ok().and_then(|b| dpapi(false, &b)).unwrap_or_else(|| fail());
                pair(&mut seed).public_key().as_ref().to_vec()
            }
        }
        _ => kat_mode(&mode, &input),
    };
    if std::io::stdout().write_all(&output).is_err() {
        fail();
    }
}

fn kat_mode(mode: &str, input: &[u8]) -> Vec<u8> {
    let (head, ok) = match mode {
        "kat-keygen" => (SEED, input.len() == SEED),
        "kat-sign" => (SECRET_KEY + SEED, input.len() >= SECRET_KEY + SEED),
        "kat-verify" => (PUBLIC_KEY + SIGNATURE, input.len() >= PUBLIC_KEY + SIGNATURE),
        _ => fail(),
    };
    if !ok || input.len() - head > MAX_MESSAGE {
        fail();
    }
    let (a, m) = input.split_at(head);
    unsafe {
        match mode {
            "kat-keygen" => {
                let mut out = vec![0u8; PUBLIC_KEY + SECRET_KEY];
                let (pk, sk) = out.split_at_mut(PUBLIC_KEY);
                if keypair_internal(pk.as_mut_ptr(), sk.as_mut_ptr(), a.as_ptr()) != 1 {
                    fail();
                }
                out
            }
            "kat-sign" => {
                let (mut out, mut len) = (vec![0u8; SIGNATURE], 0usize);
                let done = sign_internal(a.as_ptr(), out.as_mut_ptr(), &mut len, m.as_ptr(), m.len(), null(), 0, a[SECRET_KEY..].as_ptr());
                if done != 1 || len != SIGNATURE {
                    fail();
                }
                out
            }
            _ => vec![(verify_internal(a.as_ptr(), a[PUBLIC_KEY..].as_ptr(), SIGNATURE, m.as_ptr(), m.len(), null(), 0) == 1) as u8],
        }
    }
}
