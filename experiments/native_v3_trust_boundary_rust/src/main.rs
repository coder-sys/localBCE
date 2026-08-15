//! Independent parser/verifier for the native-v3 trust-boundary profile.
//!
//! This is protocol-boundary evidence only.  It does not implement a proof
//! backend, source-membership proof, semantic proof, ZK simulator, or
//! clearance authorization.  It never reads the prover's private state file.

use sha3::{Digest, Sha3_512};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

type D = [u8; 64];

const FRAME_MAGIC: &[u8] = b"BLTBFRM1";
const STATEMENT_MAGIC: &[u8] = b"BLTBST01";
const CHALLENGE_KIND: u8 = 2;
const COMMITMENT_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 3;
const PROVER_ROLE: u8 = 1;
const VERIFIER_ROLE: u8 = 2;
const COMMITMENT_ROUND: u16 = 0;
const CHALLENGE_ROUND: u16 = 1;
const RESPONSE_ROUND: u16 = 2;
const TRANSCRIPT_MAGIC: &[u8] = b"BLTBTX01";
const OPENING_MAGIC: &[u8] = b"BLTBOP01";
const VECTOR_LEAF_MAGIC: &[u8] = b"BLTBLF01";
const VECTOR_NODE_MAGIC: &[u8] = b"BLTBND01";

const FRAME_TAG_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/FRAME-TAG/v1\0";
const STATEMENT_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/STATEMENT/v1\0";
const HANDLE_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/COMMITMENT-HANDLE/v1\0";
const COMMITMENT_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/COMMITMENT-DIGEST/v1\0";
const CHALLENGE_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/CHALLENGE-DIGEST/v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/TRANSCRIPT/v1\0";
const CHALLENGE_AUTH_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/CHALLENGE-AUTH/v1\0";
const VECTOR_LEAF_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/VECTOR-LEAF/v1\0";
const VECTOR_NODE_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/VECTOR-NODE/v1\0";
const LEAF_TAG_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/LEAF-TAG/v1\0";
const NODE_TAG_DOMAIN: &[u8] = b"BL/NATIVE-V3/TBP/NODE-TAG/v1\0";

const PROFILE_ID_HEX: &str = "8b07c423294e2d2cecf320e495b56c31b5ecbd75f28cee5b166785e0de872619a0149b1e3dacd195207c7c2f34a9b46a8843ef8dd1c6fbac613aa66111d4163c";
const ATTEMPT_ID_HEX: &str = "2a1110e501acb83cef3a248182c9017e5569e9ea04d6f78bb9aa44c590df5fff36816b0bd7e5f9938f67df0e380ebccd0bc9c5c8ec938dbc3eda6463891d4209";
const PHASE0_STATEMENT_HEX: &str = "396587f05dbadeede82477853d400692608f6b25c3ed88f228ac1f8af113293c17512972ba9cb808a12685fe842ddd10061136261ef6c5deae1e160bd84495c3";
const SOURCE_ROOT_HEX: &str = "947b9937f37c0c0e4e47dfa1a7a54ef9a9ede7a17e6a4e0fb0fcb70d94ebe0a5cee85aec5b7b74ee0d5eb6459a91ffbdb643f8514f8d2c105f455b956749bdab";
const CONTROL_SET_HEX: &str = "864482b065b1ec00dfb388f72e628dd1b3377541e835c143080eaec8fc1429cb087f89147a1ea0f9fad2e654e72d96005c89f36f913f6090fe9296d3763f825b";
const JOIN_HEX: &str = "d62d56dee1cc8b18869c128dbc178aa3ee993865bfe38216596b7f9b8788fb6b58fc8849b0db30c6b652e40dfa30bf8f8bea1b94f8a5e0f5b8421039ddc09245";
const RECEIPT_HEX: &str = "b55b99adcb9085039947a09e718169fe4b882c49f8a1bb7b8fc221ed518555203ed51565280ba0f25228a9f3f735b205a0abe6620c68c2e8963d4e8635aa8808";
const COMPLETENESS_HEX: &str = "a234511ec4e922a357ec9b0d7c390a25d86c5b0ae564b2c5d130a20d46bbd289b1557af277190bbc7e6160dfc7d5385464f9682d2f73688208746c1879fba7e5";
const CHRONOLOGY_HEX: &str = "1a9626829c39bd3abc9faf969bf8915549b3845486a00f6ff227390520beff2e3dfd6aaf792d562e0a06539a01e250466b4ddb3f075fe4a14cd45745ad6fba99";
const REPLAY_HEX: &str = "c5eeb6caa78f094d831d122b7636a193f6af59675b6519bd8e059058fa95332603dbd6a65abf8667151fde44591cdfb5f4542a1976561c9b112c5099e2244cfa";
const EXCEPTION_HEX: &str = "e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const STATE_BEFORE_HEX: &str = "ea5a9631ab0134beed2231f4b5f1539f976b0c34416ee9eb127ace55302e31dd45a626a8847bf09c32297073dabd9cdadc4fb768b4e043119079ee66504ac024";
const STATE_AFTER_HEX: &str = "4bb1b4fc536e0e9fc30b7cf17af7007b4d1c43b534adadf39e001618f9572ad083d482eccfef63aebfb43cac096ab1a20f37dc85456631c67a80f215a53f84c8";

fn raw_hash(data: &[u8]) -> D {
    Sha3_512::digest(data).into()
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> D {
    let mut h = Sha3_512::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn decode_hex(value: &str) -> Result<D, String> {
    if value.len() != 128 {
        return Err("hex:wrong-width".into());
    }
    let mut out = [0u8; 64];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| "hex:utf8".to_string())?;
        out[index] = u8::from_str_radix(text, 16).map_err(|_| "hex:digit".to_string())?;
    }
    Ok(out)
}

fn hex(value: &[u8]) -> String {
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

fn u16be(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

fn u32be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

fn require_nonzero(value: &D, label: &str) -> Result<(), String> {
    if value.iter().all(|byte| *byte == 0) {
        Err(format!("{label}:zero"))
    } else {
        Ok(())
    }
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, length: usize, label: &str) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| format!("{label}:overflow"))?;
        if end > self.data.len() {
            return Err(format!("{label}:truncated"));
        }
        let result = &self.data[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn array<const N: usize>(&mut self, label: &str) -> Result<[u8; N], String> {
        self.take(N, label)?
            .try_into()
            .map_err(|_| format!("{label}:width"))
    }

    fn u16(&mut self, label: &str) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.array(label)?))
    }

    fn u32(&mut self, label: &str) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.array(label)?))
    }

    fn u64(&mut self, label: &str) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.array(label)?))
    }

    fn finish(&self, label: &str) -> Result<(), String> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(format!("{label}:trailing"))
        }
    }
}

fn frame_tag(kind: u8, role: u8, round: u16) -> D {
    let domain = match kind {
        COMMITMENT_KIND => b"BL/NATIVE-V3/TBP/COMMITMENT/v1\0".as_slice(),
        CHALLENGE_KIND => b"BL/NATIVE-V3/TBP/CHALLENGE/v1\0".as_slice(),
        RESPONSE_KIND => b"BL/NATIVE-V3/TBP/RESPONSE/v1\0".as_slice(),
        _ => b"BL/NATIVE-V3/TBP/UNKNOWN/v1\0".as_slice(),
    };
    digest(FRAME_TAG_DOMAIN, &[domain, &[kind, role], &u16be(round)])
}

fn parse_frame(
    data: &[u8],
    expected_kind: u8,
    expected_role: u8,
    expected_round: u16,
) -> Result<([u8; 32], Vec<u8>), String> {
    let mut reader = Reader::new(data);
    if reader.take(8, "frame:magic")? != FRAME_MAGIC {
        return Err("frame:magic".into());
    }
    if reader.u16("frame:version")? != 1 {
        return Err("frame:version".into());
    }
    let kind = reader.take(1, "frame:kind")?[0];
    let role = reader.take(1, "frame:role")?[0];
    let round = reader.u16("frame:round")?;
    if (kind, role, round) != (expected_kind, expected_role, expected_round) {
        return Err("frame:role-kind-round".into());
    }
    let session = reader.array::<32>("frame:session")?;
    if session.iter().all(|byte| *byte == 0) {
        return Err("frame:zero-session".into());
    }
    let tag = reader.array::<64>("frame:tag")?;
    if tag != frame_tag(kind, role, round) {
        return Err("frame:domain-tag".into());
    }
    let length = reader.u32("frame:length")? as usize;
    let payload = reader.take(length, "frame:payload")?.to_vec();
    reader.finish("frame")?;
    Ok((session, payload))
}

struct Statement {
    session: [u8; 32],
}

fn parse_statement(data: &[u8]) -> Result<Statement, String> {
    if data.len() != 992 {
        return Err("statement:length".into());
    }
    let mut reader = Reader::new(data);
    if reader.take(8, "statement:magic")? != STATEMENT_MAGIC {
        return Err("statement:magic".into());
    }
    if reader.u16("statement:version")? != 1 || reader.u16("statement:flags")? != 0 {
        return Err("statement:header".into());
    }
    if reader.take(1, "statement:suite-marker")? != [0] {
        return Err("statement:suite-marker".into());
    }
    if reader.take(3, "statement:reserved")? != [0, 0, 0] {
        return Err("statement:reserved".into());
    }
    if reader.array::<64>("statement:suite")? != [0u8; 64] {
        return Err("statement:proof-suite-not-null".into());
    }
    let session = reader.array::<32>("statement:session")?;
    if session.iter().all(|byte| *byte == 0) {
        return Err("statement:zero-session".into());
    }
    let expected = [
        decode_hex(PROFILE_ID_HEX)?,
        decode_hex(ATTEMPT_ID_HEX)?,
        decode_hex(PHASE0_STATEMENT_HEX)?,
        decode_hex(SOURCE_ROOT_HEX)?,
        decode_hex(CONTROL_SET_HEX)?,
        decode_hex(JOIN_HEX)?,
        decode_hex(RECEIPT_HEX)?,
        decode_hex(COMPLETENESS_HEX)?,
        decode_hex(CHRONOLOGY_HEX)?,
        decode_hex(REPLAY_HEX)?,
        decode_hex(EXCEPTION_HEX)?,
        decode_hex(STATE_BEFORE_HEX)?,
        decode_hex(STATE_AFTER_HEX)?,
    ];
    for (index, wanted) in expected.iter().enumerate() {
        let value = reader.array::<64>(&format!("statement:binding-{index}"))?;
        require_nonzero(&value, "statement:binding")?;
        if value != *wanted {
            return Err(format!("statement:binding-{index}-mismatch"));
        }
    }
    let sequence_before = reader.u64("statement:sequence-before")?;
    let sequence_after = reader.u64("statement:sequence-after")?;
    let event_time = reader.u64("statement:event-time")?;
    let observation_time = reader.u64("statement:observation-time")?;
    let rule_effective_time = reader.u64("statement:rule-effective-time")?;
    let decision_time = reader.u64("statement:decision-time")?;
    if (sequence_before, sequence_after) != (7, 8)
        || (
            event_time,
            observation_time,
            rule_effective_time,
            decision_time,
        ) != (7000, 7001, 6999, 7002)
    {
        return Err("statement:time-or-sequence-mismatch".into());
    }
    reader.finish("statement")?;
    Ok(Statement { session })
}

struct Commitment {
    session: [u8; 32],
    statement_digest: D,
    root: D,
    handle: D,
    digest: D,
}

fn parse_commitment(data: &[u8]) -> Result<Commitment, String> {
    let (session, payload) = parse_frame(data, COMMITMENT_KIND, PROVER_ROLE, COMMITMENT_ROUND)?;
    if payload.len() != 200 {
        return Err("commitment:payload-length".into());
    }
    let mut reader = Reader::new(&payload);
    let statement_digest = reader.array::<64>("commitment:statement")?;
    let root = reader.array::<64>("commitment:root")?;
    let handle = reader.array::<64>("commitment:handle")?;
    let leaf_count = reader.u32("commitment:leaf-count")?;
    let salt_bytes = reader.u16("commitment:salt-bytes")?;
    if reader.u16("commitment:reserved")? != 0 || leaf_count != 2 || salt_bytes != 32 {
        return Err("commitment:profile-geometry".into());
    }
    reader.finish("commitment-payload")?;
    require_nonzero(&statement_digest, "commitment:statement")?;
    require_nonzero(&root, "commitment:root")?;
    require_nonzero(&handle, "commitment:handle")?;
    Ok(Commitment {
        session,
        statement_digest,
        root,
        handle,
        digest: digest(COMMITMENT_DOMAIN, &[data]),
    })
}

fn hmac_sha3(key: &[u8; 32], message: &[u8]) -> D {
    let mut key_block = [0u8; 72];
    key_block[..32].copy_from_slice(key);
    let mut inner = Vec::with_capacity(72 + message.len());
    for byte in key_block {
        inner.push(byte ^ 0x36);
    }
    inner.extend_from_slice(message);
    let inner_hash = raw_hash(&inner);
    let mut outer = Vec::with_capacity(72 + inner_hash.len());
    for byte in key_block {
        outer.push(byte ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    raw_hash(&outer)
}

struct Challenge {
    session: [u8; 32],
    commitment_digest: D,
    nonce: [u8; 32],
    scalar: [u8; 32],
    selected_index: u32,
    auth_tag: D,
    digest: D,
}

fn challenge_body(challenge: &Challenge) -> Vec<u8> {
    let mut result = Vec::with_capacity(64 + 32 + 32 + 4);
    result.extend_from_slice(&challenge.commitment_digest);
    result.extend_from_slice(&challenge.nonce);
    result.extend_from_slice(&challenge.scalar);
    result.extend_from_slice(&u32be(challenge.selected_index));
    result
}

fn parse_challenge(data: &[u8]) -> Result<Challenge, String> {
    let (session, payload) = parse_frame(data, CHALLENGE_KIND, VERIFIER_ROLE, CHALLENGE_ROUND)?;
    if payload.len() != 196 {
        return Err("challenge:payload-length".into());
    }
    let mut reader = Reader::new(&payload);
    let commitment_digest = reader.array::<64>("challenge:commitment")?;
    let nonce = reader.array::<32>("challenge:nonce")?;
    let scalar = reader.array::<32>("challenge:scalar")?;
    let selected_index = reader.u32("challenge:index")?;
    let auth_tag = reader.array::<64>("challenge:auth")?;
    reader.finish("challenge-payload")?;
    require_nonzero(&commitment_digest, "challenge:commitment")?;
    if selected_index
        != u32::from_be_bytes(
            scalar[..4]
                .try_into()
                .map_err(|_| "challenge:scalar".to_string())?,
        ) % 2
    {
        return Err("challenge:index-not-derived".into());
    }
    let challenge = Challenge {
        session,
        commitment_digest,
        nonce,
        scalar,
        selected_index,
        auth_tag,
        digest: digest(CHALLENGE_DOMAIN, &[data]),
    };
    if challenge_body(&challenge).len() != 132 {
        return Err("challenge:body".into());
    }
    Ok(challenge)
}

fn authenticate_challenge(challenge: &Challenge, key: &[u8; 32]) -> Result<(), String> {
    let mut message = Vec::with_capacity(CHALLENGE_AUTH_DOMAIN.len() + 32 + 132);
    message.extend_from_slice(CHALLENGE_AUTH_DOMAIN);
    message.extend_from_slice(&challenge.session);
    message.extend_from_slice(&challenge_body(challenge));
    if hmac_sha3(key, &message) == challenge.auth_tag {
        Ok(())
    } else {
        Err("challenge:authentication".into())
    }
}

struct Opening {
    index: u32,
    value: Vec<u8>,
    salt: [u8; 32],
    sibling_is_left: bool,
    sibling_hash: D,
}

fn parse_opening(data: &[u8]) -> Result<Opening, String> {
    let mut reader = Reader::new(data);
    if reader.take(8, "opening:magic")? != OPENING_MAGIC
        || reader.u16("opening:version")? != 1
        || reader.u16("opening:reserved")? != 0
    {
        return Err("opening:header".into());
    }
    let index = reader.u32("opening:index")?;
    let value_length = reader.u32("opening:value-length")? as usize;
    let value = reader.take(value_length, "opening:value")?.to_vec();
    let salt_length = reader.u16("opening:salt-length")? as usize;
    if salt_length != 32 {
        return Err("opening:salt-length".into());
    }
    let salt = reader.array::<32>("opening:salt")?;
    if reader.u16("opening:path-count")? != 1 {
        return Err("opening:path-count".into());
    }
    let direction = reader.take(1, "opening:direction")?[0];
    if direction > 1 || reader.take(1, "opening:path-reserved")? != [0] {
        return Err("opening:path-grammar".into());
    }
    let sibling_hash = reader.array::<64>("opening:sibling")?;
    reader.finish("opening")?;
    if index > 1 {
        return Err("opening:index".into());
    }
    Ok(Opening {
        index,
        value,
        salt,
        sibling_is_left: direction == 1,
        sibling_hash,
    })
}

fn leaf_hash(index: u32, value: &[u8], salt: &[u8; 32]) -> D {
    let mut bytes = Vec::with_capacity(8 + 2 + 2 + 64 + 4 + 4 + value.len() + 2 + 32);
    bytes.extend_from_slice(VECTOR_LEAF_MAGIC);
    bytes.extend_from_slice(&u16be(1));
    bytes.extend_from_slice(&u16be(0));
    bytes.extend_from_slice(&digest(LEAF_TAG_DOMAIN, &[VECTOR_LEAF_DOMAIN]));
    bytes.extend_from_slice(&u32be(index));
    bytes.extend_from_slice(&u32be(value.len() as u32));
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(&u16be(32));
    bytes.extend_from_slice(salt);
    digest(VECTOR_LEAF_DOMAIN, &[&bytes])
}

fn node_hash(left: &D, right: &D) -> D {
    let mut bytes = Vec::with_capacity(8 + 2 + 2 + 64 + 2 + 4 + 64 + 64);
    bytes.extend_from_slice(VECTOR_NODE_MAGIC);
    bytes.extend_from_slice(&u16be(1));
    bytes.extend_from_slice(&u16be(0));
    bytes.extend_from_slice(&digest(NODE_TAG_DOMAIN, &[VECTOR_NODE_DOMAIN]));
    bytes.extend_from_slice(&u16be(0));
    bytes.extend_from_slice(&u32be(0));
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    digest(VECTOR_NODE_DOMAIN, &[&bytes])
}

struct Response {
    session: [u8; 32],
    commitment_digest: D,
    challenge_digest: D,
    handle: D,
    opening: Opening,
}

fn parse_response(data: &[u8]) -> Result<Response, String> {
    let (session, payload) = parse_frame(data, RESPONSE_KIND, PROVER_ROLE, RESPONSE_ROUND)?;
    if payload.len() < 228 {
        return Err("response:payload-length".into());
    }
    let mut reader = Reader::new(&payload);
    let commitment_digest = reader.array::<64>("response:commitment")?;
    let challenge_digest = reader.array::<64>("response:challenge")?;
    let handle = reader.array::<64>("response:handle")?;
    let _response_nonce = reader.array::<32>("response:nonce")?;
    let opening_length = reader.u32("response:opening-length")? as usize;
    let opening = parse_opening(reader.take(opening_length, "response:opening")?)?;
    reader.finish("response-payload")?;
    require_nonzero(&commitment_digest, "response:commitment")?;
    require_nonzero(&challenge_digest, "response:challenge")?;
    require_nonzero(&handle, "response:handle")?;
    Ok(Response {
        session,
        commitment_digest,
        challenge_digest,
        handle,
        opening,
    })
}

struct Transcript {
    session: [u8; 32],
    statement: Vec<u8>,
    commitment: Vec<u8>,
    challenge: Vec<u8>,
    response: Vec<u8>,
    digest: D,
    bytes: Vec<u8>,
}

fn parse_transcript(data: &[u8]) -> Result<Transcript, String> {
    let mut reader = Reader::new(data);
    if reader.take(8, "transcript:magic")? != TRANSCRIPT_MAGIC
        || reader.u16("transcript:version")? != 1
        || reader.u16("transcript:flags")? != 0
    {
        return Err("transcript:header".into());
    }
    let session = reader.array::<32>("transcript:session")?;
    let statement_length = reader.u32("transcript:statement-length")? as usize;
    let statement = reader
        .take(statement_length, "transcript:statement")?
        .to_vec();
    if reader.u16("transcript:frame-count")? != 3 {
        return Err("transcript:frame-count".into());
    }
    let mut frames = Vec::with_capacity(3);
    for index in 0..3 {
        let length = reader.u32(&format!("transcript:frame-{index}-length"))? as usize;
        frames.push(
            reader
                .take(length, &format!("transcript:frame-{index}"))?
                .to_vec(),
        );
    }
    let transcript_digest = reader.array::<64>("transcript:digest")?;
    reader.finish("transcript")?;
    let expected_digest = digest(
        TRANSCRIPT_DOMAIN,
        &[
            session.as_slice(),
            &statement,
            &frames[0],
            &frames[1],
            &frames[2],
        ],
    );
    if transcript_digest != expected_digest {
        return Err("transcript:digest".into());
    }
    let statement_obj = parse_statement(&statement)?;
    let commitment = parse_commitment(&frames[0])?;
    let challenge = parse_challenge(&frames[1])?;
    let response = parse_response(&frames[2])?;
    if statement_obj.session != session
        || commitment.session != session
        || challenge.session != session
        || response.session != session
    {
        return Err("transcript:session-binding".into());
    }
    Ok(Transcript {
        session,
        statement,
        commitment: frames[0].clone(),
        challenge: frames[1].clone(),
        response: frames[2].clone(),
        digest: transcript_digest,
        bytes: data.to_vec(),
    })
}

fn claim_marker(registry: &Path, name: &str, content: &[u8]) -> Result<(), String> {
    let directory = registry.join("accepted");
    fs::create_dir_all(&directory).map_err(|error| format!("registry:create:{error}"))?;
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("registry:replay-or-open:{error}"))?;
    file.write_all(content)
        .map_err(|error| format!("registry:write:{error}"))?;
    Ok(())
}

fn read_exact_file(directory: &Path, name: &str) -> Result<Vec<u8>, String> {
    fs::read(directory.join(name)).map_err(|error| format!("read:{name}:{error}"))
}

fn verify_directory(
    directory: &Path,
    registry: &Path,
) -> Result<(Statement, Commitment, Challenge, Transcript), String> {
    let key_bytes = read_exact_file(directory, "verifier.key")?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "verifier-key:width".to_string())?;
    let statement_bytes = read_exact_file(directory, "statement.bin")?;
    let commitment_bytes = read_exact_file(directory, "commitment.bin")?;
    let challenge_bytes = read_exact_file(directory, "challenge.bin")?;
    let response_bytes = read_exact_file(directory, "response.bin")?;
    let transcript_bytes = read_exact_file(directory, "transcript.bin")?;

    let statement = parse_statement(&statement_bytes)?;
    let commitment = parse_commitment(&commitment_bytes)?;
    let challenge = parse_challenge(&challenge_bytes)?;
    let response = parse_response(&response_bytes)?;
    let transcript = parse_transcript(&transcript_bytes)?;

    if commitment.session != statement.session
        || challenge.session != statement.session
        || response.session != statement.session
        || transcript.session != statement.session
    {
        return Err("verify:session-binding".into());
    }
    if commitment.statement_digest != digest(STATEMENT_DOMAIN, &[&statement_bytes]) {
        return Err("verify:statement-digest".into());
    }
    if commitment.handle
        != digest(
            HANDLE_DOMAIN,
            &[
                &statement.session,
                &commitment.statement_digest,
                &commitment.root,
            ],
        )
    {
        return Err("verify:handle".into());
    }
    if challenge.commitment_digest != commitment.digest
        || response.commitment_digest != commitment.digest
    {
        return Err("verify:commitment-binding".into());
    }
    authenticate_challenge(&challenge, &key)?;
    if response.challenge_digest != challenge.digest {
        return Err("verify:challenge-binding".into());
    }
    if response.handle != commitment.handle {
        return Err("verify:response-handle".into());
    }
    if transcript.statement != statement_bytes
        || transcript.commitment != commitment_bytes
        || transcript.challenge != challenge_bytes
        || transcript.response != response_bytes
    {
        return Err("verify:transcript-frame-order".into());
    }
    if response.opening.index != challenge.selected_index {
        return Err("verify:opening-index".into());
    }
    let leaf = leaf_hash(
        response.opening.index,
        &response.opening.value,
        &response.opening.salt,
    );
    let root = if response.opening.sibling_is_left {
        node_hash(&response.opening.sibling_hash, &leaf)
    } else {
        node_hash(&leaf, &response.opening.sibling_hash)
    };
    if root != commitment.root {
        return Err("verify:opening-root".into());
    }
    claim_marker(
        registry,
        &format!("{}.accepted", hex(&statement.session)),
        &transcript.bytes,
    )?;
    Ok((statement, commitment, challenge, transcript))
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    let result = (|| -> Result<(), String> {
        if arguments.len() < 3 || arguments[1] != "verify" || arguments.len() > 4 {
            return Err("usage: verify <session-directory> [registry-directory]".into());
        }
        let directory = PathBuf::from(&arguments[2]);
        let registry = arguments
            .get(3)
            .map(PathBuf::from)
            .unwrap_or_else(|| directory.join("rust-verifier-registry"));
        let (statement, commitment, challenge, transcript) =
            verify_directory(&directory, &registry)?;
        println!("status=TRUST_BOUNDARY_RUST_INDEPENDENT_VERIFY_PASS");
        println!("profile_only=true");
        println!("complete_bound_available=false");
        println!("production_usable=false");
        println!("proof_suite_id=null");
        println!("session_id={}", hex(&statement.session));
        println!("commitment_digest={}", hex(&commitment.digest));
        println!("challenge_digest={}", hex(&challenge.digest));
        println!("transcript_digest={}", hex(&transcript.digest));
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("status=TRUST_BOUNDARY_RUST_INDEPENDENT_VERIFY_FAIL error={error}");
        std::process::exit(1);
    }
}
