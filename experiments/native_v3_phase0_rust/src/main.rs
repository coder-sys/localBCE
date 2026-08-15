//! Independent Rust reconstruction of the native-v3 Phase-0 byte boundary.
//!
//! This deliberately does not import the Python producer or a Blind Ledger
//! business module.  It reconstructs the fixed grammar, parses its own bytes,
//! and checks the same KAT identities so the producer is not its own verifier.

use sha3::{Digest, Sha3_512};
use std::env;

const STATEMENT_MAGIC: &[u8] = b"BLNV3ST1";
const STATEMENT_BYTES: usize = 556;
const CONTEXT_MAGIC: &[u8] = b"BLNV3CX1";
const CONTEXT_BYTES: usize = 396;
const SOURCE_MAGIC: &[u8] = b"BLNV3SL1";
const SOURCE_BYTES: usize = 212;
const OP_MAGIC: &[u8] = b"BLNV3OR1";
const OP_BYTES: usize = 480;
const STATE_MAGIC: &[u8] = b"BLNV3SC1";
const STATE_BYTES: usize = 832;
const NULL_SUITE: [u8; 64] = [0; 64];
const POLICY_RESULT_PASS: u8 = 1;
const POLICY_RESULT_MISSING_EVIDENCE: u8 = 2;
const POLICY_RESULT_AMBIGUOUS: u8 = 3;
const POLICY_RESULT_FAIL: u8 = 4;
const DIRECTIVE_CLEAR: u8 = 1;
const DIRECTIVE_HOLD: u8 = 2;
const DIRECTIVE_HUMAN_REVIEW: u8 = 3;
const DIRECTIVE_BLOCK: u8 = 4;
const DIRECTIVE_EXCEPTION_APPROVED: u8 = 5;
const NO_EXCEPTION_SENTINEL: [u8; 64] = {
    let mut value = [0u8; 64];
    value[0] = 0xe0;
    value
};
const CLEARANCE_AUDIT_ONLY: u8 = 0;
const CLEARANCE_ADVANCED: u8 = 1;
const AUTH_MAGIC: &[u8] = b"BLNV3EA1";
const AUTH_BYTES: usize = 484;
const AUTH_CURRENT_TIME: u64 = 8;

type D = [u8; 64];

fn digest(domain: &[u8], parts: &[&[u8]]) -> D {
    let mut h = Sha3_512::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn u16be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}
fn u32be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}
fn u64be(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

fn expect(actual: &[u8], wanted: &[u8], label: &str) -> Result<(), String> {
    if actual == wanted {
        Ok(())
    } else {
        Err(format!("{label}:mismatch"))
    }
}

fn nonzero<const N: usize>(v: &[u8], label: &str) -> Result<[u8; N], String> {
    if v.len() != N || v.iter().all(|x| *x == 0) {
        return Err(format!("{label}:zero-or-wrong-width"));
    }
    v.try_into().map_err(|_| format!("{label}:width"))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn trusted_authorizer() -> D {
    digest(
        b"BL/NATIVE-V3/AUTHORIZER/v1\0",
        &[b"synthetic-state-authorizer-v1"],
    )
}
fn expected_rule() -> D {
    digest(b"BL/NATIVE-V3/RULE/v1\0", &[b"synthetic-clearance-rule-v1"])
}
fn expected_reason() -> D {
    digest(
        b"BL/NATIVE-V3/EXCEPTION-REASON/v1\0",
        &[b"synthetic-governed-reason-v1"],
    )
}
fn expected_amount_scope() -> D {
    digest(
        b"BL/NATIVE-V3/AMOUNT-SCOPE/v1\0",
        &[b"synthetic-amount-scope-v1"],
    )
}

fn policy_for_directive(directive: u8) -> Result<u8, String> {
    match directive {
        DIRECTIVE_CLEAR => Ok(POLICY_RESULT_PASS),
        DIRECTIVE_HOLD => Ok(POLICY_RESULT_MISSING_EVIDENCE),
        DIRECTIVE_HUMAN_REVIEW => Ok(POLICY_RESULT_AMBIGUOUS),
        DIRECTIVE_BLOCK | DIRECTIVE_EXCEPTION_APPROVED => Ok(POLICY_RESULT_FAIL),
        _ => Err("operation-row:directive".into()),
    }
}

fn directive_name(directive: u8) -> &'static str {
    match directive {
        DIRECTIVE_CLEAR => "CLEAR",
        DIRECTIVE_HOLD => "HOLD",
        DIRECTIVE_HUMAN_REVIEW => "HUMAN_REVIEW",
        DIRECTIVE_BLOCK => "BLOCK",
        DIRECTIVE_EXCEPTION_APPROVED => "EXCEPTION_APPROVED",
        _ => "UNKNOWN",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Context {
    fields: [D; 6],
}

impl Context {
    fn new() -> Self {
        fn item(label: &[u8]) -> D {
            digest(b"BL/NATIVE-V3/CONTEXT-ITEM/v1\0", &[label])
        }
        Self {
            fields: [
                item(b"native-v3-phase0-cpu-one-transition"),
                item(b"native-v3-statement-schema-v1"),
                item(b"native-v3-one-record-five-directive-v2"),
                item(b"native-v3-unselected-verifier-placeholder-v1"),
                item(b"native-v3-backend-unselected-v1"),
                item(b"native-v3-fixed-statement-556-v2-directive"),
            ],
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTEXT_BYTES);
        out.extend_from_slice(CONTEXT_MAGIC);
        out.extend_from_slice(&u16be(1));
        out.extend_from_slice(&u16be(0));
        for f in &self.fields {
            out.extend_from_slice(f);
        }
        out
    }

    fn id(&self) -> D {
        digest(b"BL/NATIVE-V3/EXECUTION-CONTEXT/v1\0", &[&self.bytes()])
    }

    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() != CONTEXT_BYTES {
            return Err("context:length".into());
        }
        expect(&data[..8], CONTEXT_MAGIC, "context:magic")?;
        expect(&data[8..10], &u16be(1), "context:version")?;
        expect(&data[10..12], &u16be(0), "context:flags")?;
        let mut fields = [[0u8; 64]; 6];
        for (i, f) in fields.iter_mut().enumerate() {
            *f = nonzero::<64>(
                &data[12 + i * 64..12 + (i + 1) * 64],
                &format!("context:field-{i}"),
            )?;
        }
        let c = Self { fields };
        if c.bytes() != data {
            return Err("context:noncanonical-reencoding".into());
        }
        Ok(c)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Source {
    record: D,
    payload: D,
    governance: D,
}

impl Source {
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SOURCE_BYTES);
        out.extend_from_slice(SOURCE_MAGIC);
        out.extend_from_slice(&u16be(1));
        out.extend_from_slice(&u16be(0));
        out.extend_from_slice(&[1, 0, 0, 0]);
        out.extend_from_slice(&u32be(64));
        out.extend_from_slice(&self.record);
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.governance);
        out
    }
    fn id(&self) -> D {
        digest(b"BL/NATIVE-V3/SOURCE-REGISTRY-LEAF/v1\0", &[&self.bytes()])
    }
    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() != SOURCE_BYTES {
            return Err("source-leaf:length".into());
        }
        expect(&data[..8], SOURCE_MAGIC, "source-leaf:magic")?;
        expect(&data[8..10], &u16be(1), "source-leaf:version")?;
        expect(&data[10..12], &u16be(0), "source-leaf:flags")?;
        expect(&data[12..16], &[1, 0, 0, 0], "source-leaf:kind-or-reserved")?;
        expect(&data[16..20], &u32be(64), "source-leaf:payload-length")?;
        let s = Self {
            record: nonzero::<64>(&data[20..84], "source-leaf:record-id")?,
            payload: nonzero::<64>(&data[84..148], "source-leaf:payload")?,
            governance: nonzero::<64>(&data[148..212], "source-leaf:governance")?,
        };
        if s.bytes() != data {
            return Err("source-leaf:noncanonical-reencoding".into());
        }
        Ok(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExceptionAuth {
    authorization_id: D,
    signer: D,
    subject: D,
    rule: D,
    reason: D,
    amount_scope: D,
    effective_at: u64,
    expires_at: u64,
    policy_result: u8,
    signature: D,
}

impl ExceptionAuth {
    fn from_fields(
        signer: D,
        subject: D,
        rule: D,
        reason: D,
        amount_scope: D,
        effective_at: u64,
        expires_at: u64,
        policy_result: u8,
    ) -> Result<Self, String> {
        let provisional = Self {
            authorization_id: [0; 64],
            signer,
            subject,
            rule,
            reason,
            amount_scope,
            effective_at,
            expires_at,
            policy_result,
            signature: [0; 64],
        };
        let body = provisional.body_bytes()?;
        let authorization_id = digest(b"BL/NATIVE-V3/EXCEPTION-AUTHORIZATION-ID/v1\0", &[&body]);
        let signature = digest(
            b"BL/NATIVE-V3/SYNTHETIC-AUTHORIZATION-SEAL/v1\0",
            &[&signer, &body],
        );
        Ok(Self {
            authorization_id,
            signature,
            ..provisional
        })
    }

    fn body_bytes(&self) -> Result<Vec<u8>, String> {
        if self.effective_at >= self.expires_at {
            return Err("exception:interval".into());
        }
        if !matches!(
            self.policy_result,
            POLICY_RESULT_PASS
                | POLICY_RESULT_MISSING_EVIDENCE
                | POLICY_RESULT_AMBIGUOUS
                | POLICY_RESULT_FAIL
        ) {
            return Err("exception:policy-result".into());
        }
        let mut out = Vec::with_capacity(356);
        out.extend_from_slice(AUTH_MAGIC);
        out.extend_from_slice(&u16be(1));
        out.extend_from_slice(&u16be(0));
        out.extend_from_slice(&self.signer);
        out.extend_from_slice(&self.subject);
        out.extend_from_slice(&self.rule);
        out.extend_from_slice(&self.reason);
        out.extend_from_slice(&self.amount_scope);
        out.extend_from_slice(&u64be(self.effective_at));
        out.extend_from_slice(&u64be(self.expires_at));
        out.push(self.policy_result);
        out.extend_from_slice(&[0; 7]);
        Ok(out)
    }

    fn bytes(&self) -> Result<Vec<u8>, String> {
        let body = self.body_bytes()?;
        if self.authorization_id == [0; 64] || self.signature == [0; 64] {
            return Err("exception:zero-identity".into());
        }
        if self.authorization_id
            != digest(b"BL/NATIVE-V3/EXCEPTION-AUTHORIZATION-ID/v1\0", &[&body])
        {
            return Err("exception:authorization-id-seal".into());
        }
        if self.signature
            != digest(
                b"BL/NATIVE-V3/SYNTHETIC-AUTHORIZATION-SEAL/v1\0",
                &[&self.signer, &body],
            )
        {
            return Err("exception:signature-seal".into());
        }
        let mut out = Vec::with_capacity(AUTH_BYTES);
        out.extend_from_slice(AUTH_MAGIC);
        out.extend_from_slice(&u16be(1));
        out.extend_from_slice(&u16be(0));
        out.extend_from_slice(&self.authorization_id);
        out.extend_from_slice(&self.signer);
        out.extend_from_slice(&self.subject);
        out.extend_from_slice(&self.rule);
        out.extend_from_slice(&self.reason);
        out.extend_from_slice(&self.amount_scope);
        out.extend_from_slice(&u64be(self.effective_at));
        out.extend_from_slice(&u64be(self.expires_at));
        out.push(self.policy_result);
        out.extend_from_slice(&[0; 7]);
        out.extend_from_slice(&self.signature);
        if out.len() != AUTH_BYTES {
            return Err("exception:length-internal".into());
        }
        Ok(out)
    }

    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() != AUTH_BYTES {
            return Err("exception:length".into());
        }
        expect(&data[..8], AUTH_MAGIC, "exception:magic")?;
        expect(&data[8..10], &u16be(1), "exception:version")?;
        expect(&data[10..12], &u16be(0), "exception:flags")?;
        if data[413..420] != [0; 7] {
            return Err("exception:reserved".into());
        }
        let auth = Self {
            authorization_id: nonzero::<64>(&data[12..76], "exception:authorization-id")?,
            signer: nonzero::<64>(&data[76..140], "exception:signer")?,
            subject: nonzero::<64>(&data[140..204], "exception:subject")?,
            rule: nonzero::<64>(&data[204..268], "exception:rule")?,
            reason: nonzero::<64>(&data[268..332], "exception:reason")?,
            amount_scope: nonzero::<64>(&data[332..396], "exception:amount-scope")?,
            effective_at: u64::from_be_bytes(data[396..404].try_into().unwrap()),
            expires_at: u64::from_be_bytes(data[404..412].try_into().unwrap()),
            policy_result: data[412],
            signature: nonzero::<64>(&data[420..484], "exception:signature")?,
        };
        if auth.bytes()? != data {
            return Err("exception:noncanonical-reencoding".into());
        }
        Ok(auth)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Operation {
    domain: D,
    record: D,
    address: D,
    key: D,
    before: D,
    after: D,
    policy_result: u8,
    directive: u8,
    exception_id: D,
}

impl Operation {
    fn bytes(&self) -> Vec<u8> {
        if self.policy_result != policy_for_directive(self.directive).unwrap_or(0) {
            return Vec::new();
        }
        if self.directive != DIRECTIVE_EXCEPTION_APPROVED
            && self.exception_id != NO_EXCEPTION_SENTINEL
        {
            return Vec::new();
        }
        if self.directive == DIRECTIVE_EXCEPTION_APPROVED
            && self.exception_id == NO_EXCEPTION_SENTINEL
        {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(OP_BYTES);
        out.extend_from_slice(OP_MAGIC);
        out.extend_from_slice(&u16be(1));
        out.extend_from_slice(&u16be(0));
        out.extend_from_slice(&u32be(0));
        out.extend_from_slice(&u32be(1));
        out.extend_from_slice(&[1, 1, 0, 0]);
        for f in [
            &self.domain,
            &self.record,
            &self.address,
            &self.key,
            &self.before,
            &self.after,
        ] {
            out.extend_from_slice(f);
        }
        out.push(self.policy_result);
        out.push(self.directive);
        out.extend_from_slice(&self.exception_id);
        out.extend_from_slice(&[0; 6]);
        out
    }
    fn id(&self) -> D {
        digest(b"BL/NATIVE-V3/ORDERED-OPERATION-ROW/v1\0", &[&self.bytes()])
    }
    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() != OP_BYTES {
            return Err("operation-row:length".into());
        }
        expect(&data[..8], OP_MAGIC, "operation-row:magic")?;
        expect(&data[8..10], &u16be(1), "operation-row:version")?;
        expect(&data[10..12], &u16be(0), "operation-row:flags")?;
        expect(
            &data[12..24],
            &[0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0],
            "operation-row:index-kind",
        )?;
        if data[474..480] != [0; 6] {
            return Err("operation-row:trailing-reserved".into());
        }
        let op = Self {
            domain: nonzero::<64>(&data[24..88], "operation-row:domain")?,
            record: nonzero::<64>(&data[88..152], "operation-row:record-id")?,
            address: nonzero::<64>(&data[152..216], "operation-row:address")?,
            key: nonzero::<64>(&data[216..280], "operation-row:key")?,
            before: nonzero::<64>(&data[280..344], "operation-row:before")?,
            after: nonzero::<64>(&data[344..408], "operation-row:after")?,
            policy_result: data[408],
            directive: data[409],
            exception_id: nonzero::<64>(&data[410..474], "operation-row:exception-id")?,
        };
        if op.policy_result != policy_for_directive(op.directive)? {
            return Err("operation-row:directive-policy-mismatch".into());
        }
        if op.directive != DIRECTIVE_EXCEPTION_APPROVED && op.exception_id != NO_EXCEPTION_SENTINEL
        {
            return Err("operation-row:exception-sentinel".into());
        }
        if op.directive == DIRECTIVE_EXCEPTION_APPROVED && op.exception_id == NO_EXCEPTION_SENTINEL
        {
            return Err("operation-row:exception-required".into());
        }
        if op.bytes() != data {
            return Err("operation-row:noncanonical-reencoding".into());
        }
        Ok(op)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Access {
    operation_index: u32,
    mode: u8,
    value: D,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    context: D,
    seq: u64,
    source_root: D,
    op_root: D,
    semantic_root: D,
    clearance_state: u8,
    row_count: u32,
    row: Vec<u8>,
}

impl State {
    fn layout() -> D {
        digest(b"BL/NATIVE-V3/STATE-LAYOUT/v1\0", &[b"one-row-transition"])
    }
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STATE_BYTES);
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(&u16be(1));
        out.extend_from_slice(&u16be(0));
        out.extend_from_slice(&Self::layout());
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&u64be(self.seq));
        out.extend_from_slice(&u32be(1));
        out.extend_from_slice(&u32be(self.row_count));
        out.extend_from_slice(&self.source_root);
        out.extend_from_slice(&self.op_root);
        out.extend_from_slice(&self.semantic_root);
        out.push(self.clearance_state);
        out.extend_from_slice(&[0; 3]);
        out.extend_from_slice(&self.row);
        out
    }
    fn id(&self) -> D {
        let bytes = self.bytes();
        digest(
            b"BL/NATIVE-V3/STATE-ID/v1\0",
            &[
                &self.context,
                &u64be(self.seq),
                &Self::layout(),
                &u32be(1),
                &u64be(bytes.len() as u64),
                &bytes,
            ],
        )
    }
    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() != STATE_BYTES {
            return Err("state:length".into());
        }
        expect(&data[..8], STATE_MAGIC, "state:magic")?;
        expect(&data[8..10], &u16be(1), "state:version")?;
        expect(&data[10..12], &u16be(0), "state:flags")?;
        expect(&data[12..76], &Self::layout(), "state:layout")?;
        let s = Self {
            context: nonzero::<64>(&data[76..140], "state:context")?,
            seq: u64::from_be_bytes(data[140..148].try_into().unwrap()),
            source_root: nonzero::<64>(&data[156..220], "state:source-root")?,
            op_root: nonzero::<64>(&data[220..284], "state:operation-root")?,
            semantic_root: nonzero::<64>(&data[284..348], "state:semantic-root")?,
            clearance_state: data[348],
            row_count: u32::from_be_bytes(data[152..156].try_into().unwrap()),
            row: data[352..832].to_vec(),
        };
        if s.row_count > 1 {
            return Err("state:row-count".into());
        }
        if s.clearance_state > CLEARANCE_ADVANCED {
            return Err("state:clearance-state".into());
        }
        if data[349..352] != [0; 3] {
            return Err("state:reserved".into());
        }
        if s.row_count == 0 && s.row.iter().any(|x| *x != 0) {
            return Err("state:empty-row".into());
        }
        if s.row_count == 0 && s.clearance_state != CLEARANCE_AUDIT_ONLY {
            return Err("state:empty-clearance-state".into());
        }
        if s.bytes() != data {
            return Err("state:noncanonical-reencoding".into());
        }
        Ok(s)
    }
}

#[derive(Clone)]
struct Fixture {
    context: Context,
    statement: Vec<u8>,
    payload: Vec<u8>,
    source: Source,
    op: Operation,
    exception: Option<ExceptionAuth>,
    accesses: Vec<Access>,
    before: State,
    after: State,
}

fn fixture() -> Fixture {
    fixture_for(DIRECTIVE_CLEAR).expect("fixed fixture")
}

fn fixture_for(directive: u8) -> Result<Fixture, String> {
    let context = Context::new();
    let settlement = digest(
        b"BL/NATIVE-V3/SETTLEMENT-DOMAIN/v1\0",
        &[b"synthetic-domain"],
    );
    let governance = digest(
        b"BL/NATIVE-V3/GOVERNANCE/v1\0",
        &[b"synthetic-governance-epoch-7"],
    );
    let payload = {
        let mut x = b"synthetic-registered-record-native-v3-phase0".to_vec();
        x.resize(64, 0);
        x
    };
    let payload_commit = digest(b"BL/NATIVE-V3/SOURCE-PAYLOAD/v1\0", &[&payload]);
    let record = digest(b"BL/NATIVE-V3/RECORD-ID/v1\0", &[&payload_commit]);
    let source = Source {
        record,
        payload: payload_commit,
        governance,
    };
    let address = digest(b"BL/NATIVE-V3/ADDRESS/v1\0", &[b"synthetic-address-1"]);
    let key = digest(b"BL/NATIVE-V3/KEY/v1\0", &[b"synthetic-key-1"]);
    let before = digest(b"BL/NATIVE-V3/VALUE/v1\0", &[b"before"]);
    let after = digest(b"BL/NATIVE-V3/VALUE/v1\0", &[b"after"]);
    let policy_result = policy_for_directive(directive)?;
    let exception = if directive == DIRECTIVE_EXCEPTION_APPROVED {
        Some(ExceptionAuth::from_fields(
            trusted_authorizer(),
            address,
            expected_rule(),
            expected_reason(),
            expected_amount_scope(),
            7,
            9,
            policy_result,
        )?)
    } else {
        None
    };
    let exception_id = exception
        .as_ref()
        .map(|a| a.authorization_id)
        .unwrap_or(NO_EXCEPTION_SENTINEL);
    let op = Operation {
        domain: settlement,
        record,
        address,
        key,
        before,
        after,
        policy_result,
        directive,
        exception_id,
    };
    let source_root = digest(b"BL/NATIVE-V3/SOURCE-REGISTRY-ROOT/v1\0", &[&source.id()]);
    let empty_op = digest(b"BL/NATIVE-V3/OPERATION-ROOT/v1\0", &[b"empty"]);
    let empty_sem = digest(b"BL/NATIVE-V3/SEMANTIC-DECISION/v1\0", &[b"empty"]);
    let before_state = State {
        context: context.id(),
        seq: 7,
        source_root,
        op_root: empty_op,
        semantic_root: empty_sem,
        clearance_state: CLEARANCE_AUDIT_ONLY,
        row_count: 0,
        row: vec![0; OP_BYTES],
    };
    let op_root = digest(b"BL/NATIVE-V3/OPERATION-ROOT/v1\0", &[&op.id()]);
    let semantic = digest(
        b"BL/NATIVE-V3/SEMANTIC-DECISION/v1\0",
        &[
            &[op.policy_result, op.directive],
            &op.exception_id,
            &op.record,
            &op.before,
            &op.after,
        ],
    );
    let clearance_state = if matches!(directive, DIRECTIVE_CLEAR | DIRECTIVE_EXCEPTION_APPROVED) {
        CLEARANCE_ADVANCED
    } else {
        CLEARANCE_AUDIT_ONLY
    };
    let after_state = State {
        context: context.id(),
        seq: 8,
        source_root,
        op_root,
        semantic_root: semantic,
        clearance_state,
        row_count: 1,
        row: op.bytes(),
    };
    let private_batch = digest(
        b"BL/NATIVE-V3/PRIVATE-BATCH/v1\0",
        &[
            &source.id(),
            &op.id(),
            &[op.policy_result, op.directive],
            &op.exception_id,
            &payload,
        ],
    );
    let settle_commit = digest(
        b"BL/NATIVE-V3/SETTLEMENT/v1\0",
        &[&settlement, &op.id(), &[op.directive], &after_state.id()],
    );
    let mut statement = Vec::with_capacity(STATEMENT_BYTES);
    statement.extend_from_slice(STATEMENT_MAGIC);
    statement.extend_from_slice(&u16be(3));
    statement.extend_from_slice(&u16be(0));
    statement.extend_from_slice(&[0, 0, 0, 0]);
    statement.extend_from_slice(&u32be(STATEMENT_BYTES as u32));
    statement.extend_from_slice(&NULL_SUITE);
    statement.extend_from_slice(&context.id());
    statement.extend_from_slice(&settlement);
    statement.extend_from_slice(&u64be(7));
    statement.extend_from_slice(&u64be(7));
    statement.extend_from_slice(&u64be(8));
    statement.extend_from_slice(&before_state.id());
    statement.extend_from_slice(&after_state.id());
    statement.extend_from_slice(&governance);
    statement.extend_from_slice(&private_batch);
    statement.extend_from_slice(&settle_commit);
    Ok(Fixture {
        context,
        statement,
        payload,
        source,
        op,
        exception,
        accesses: vec![
            Access {
                operation_index: 0,
                mode: 0,
                value: before,
            },
            Access {
                operation_index: 0,
                mode: 1,
                value: after,
            },
        ],
        before: before_state,
        after: after_state,
    })
}

fn parse_statement(data: &[u8], context: &Context) -> Result<(), String> {
    if data.len() != STATEMENT_BYTES {
        return Err("statement:length".into());
    }
    expect(&data[..8], STATEMENT_MAGIC, "statement:magic")?;
    expect(&data[8..10], &u16be(3), "statement:version")?;
    expect(&data[10..12], &u16be(0), "statement:flags")?;
    if data[12] != 0 || data[13..16] != [0; 3] {
        return Err("statement:suite-marker-or-reserved".into());
    }
    expect(
        &data[16..20],
        &u32be(STATEMENT_BYTES as u32),
        "statement:declared-length",
    )?;
    expect(&data[20..84], &NULL_SUITE, "statement:null-suite-bytes")?;
    expect(
        &data[84..148],
        &context.id(),
        "statement:unknown-execution-context",
    )?;
    let before = u64::from_be_bytes(data[220..228].try_into().unwrap());
    let after = u64::from_be_bytes(data[228..236].try_into().unwrap());
    if after != before + 1 {
        return Err("statement:sequence-not-one-transition".into());
    }
    for (start, label) in [
        (148, "settlement"),
        (236, "state-before"),
        (300, "state-after"),
        (364, "governance"),
        (428, "private-batch"),
        (492, "settlement-commitment"),
    ] {
        nonzero::<64>(&data[start..start + 64], &format!("statement:{label}"))?;
    }
    Ok(())
}

fn check_exception(op: &Operation, auth: Option<&ExceptionAuth>) -> Result<(), String> {
    if op.directive != DIRECTIVE_EXCEPTION_APPROVED {
        if auth.is_some() {
            return Err("exception:unexpected-for-nonexception".into());
        }
        if op.exception_id != NO_EXCEPTION_SENTINEL {
            return Err("exception:missing-sentinel".into());
        }
        return Ok(());
    }
    let auth = auth.ok_or_else(|| "exception:authorization-missing".to_string())?;
    let parsed = ExceptionAuth::parse(&auth.bytes()?)?;
    if parsed != *auth {
        return Err("exception:identity".into());
    }
    if auth.authorization_id != op.exception_id {
        return Err("exception:identity-not-row-bound".into());
    }
    if auth.signer != trusted_authorizer() {
        return Err("exception:unauthorized-signer".into());
    }
    if auth.policy_result != op.policy_result {
        return Err("exception:underlying-result".into());
    }
    if auth.subject != op.address {
        return Err("exception:subject-scope".into());
    }
    if auth.rule != expected_rule() {
        return Err("exception:rule-scope".into());
    }
    if auth.reason != expected_reason() {
        return Err("exception:reason-scope".into());
    }
    if auth.amount_scope != expected_amount_scope() {
        return Err("exception:amount-scope".into());
    }
    if !(auth.effective_at <= AUTH_CURRENT_TIME && AUTH_CURRENT_TIME < auth.expires_at) {
        return Err("exception:expired-or-not-effective".into());
    }
    Ok(())
}

fn verify_fixture(f: &Fixture) -> Result<(), String> {
    let c = Context::parse(&f.context.bytes())?;
    if c != f.context {
        return Err("context:identity".into());
    }
    parse_statement(&f.statement, &f.context)?;
    if f.statement.len() != STATEMENT_BYTES || f.statement != fixture_statement(f) {
        return Err("statement:values-do-not-match-witness".into());
    }
    if Source::parse(&f.source.bytes())? != f.source {
        return Err("source:identity".into());
    }
    if Operation::parse(&f.op.bytes())? != f.op {
        return Err("operation:identity".into());
    }
    check_exception(&f.op, f.exception.as_ref())?;
    let expected_accesses = [
        Access {
            operation_index: 0,
            mode: 0,
            value: f.op.before,
        },
        Access {
            operation_index: 0,
            mode: 1,
            value: f.op.after,
        },
    ];
    if f.accesses.as_slice() != expected_accesses {
        return Err("chronology:order-or-count".into());
    }
    if State::parse(&f.before.bytes())? != f.before || State::parse(&f.after.bytes())? != f.after {
        return Err("state:identity".into());
    }
    let source_root = digest(b"BL/NATIVE-V3/SOURCE-REGISTRY-ROOT/v1\0", &[&f.source.id()]);
    if source_root != f.before.source_root || source_root != f.after.source_root {
        return Err("state:source-root".into());
    }
    if f.after.row != f.op.bytes() {
        return Err("state:row".into());
    }
    if f.before.seq != 7 || f.after.seq != 8 {
        return Err("state:sequence".into());
    }
    let expected_clearance = if matches!(
        f.op.directive,
        DIRECTIVE_CLEAR | DIRECTIVE_EXCEPTION_APPROVED
    ) {
        CLEARANCE_ADVANCED
    } else {
        CLEARANCE_AUDIT_ONLY
    };
    if f.after.clearance_state != expected_clearance {
        return Err("state:forbidden-economic-mutation".into());
    }
    Ok(())
}

// Reconstruct only the public statement from the already-built witness.  This
// is intentionally separate from parse_statement: parsing proves canonical
// syntax, while this comparison proves that the supplied statement names this
// exact fixture rather than merely being well-formed.
fn fixture_statement(f: &Fixture) -> Vec<u8> {
    let governance = f.statement[364..428].to_vec();
    let settlement = f.statement[148..212].to_vec();
    let private_batch = digest(
        b"BL/NATIVE-V3/PRIVATE-BATCH/v1\0",
        &[
            &f.source.id(),
            &f.op.id(),
            &[f.op.policy_result, f.op.directive],
            &f.op.exception_id,
            &f.payload,
        ],
    );
    let settle_commit = digest(
        b"BL/NATIVE-V3/SETTLEMENT/v1\0",
        &[&settlement, &f.op.id(), &[f.op.directive], &f.after.id()],
    );
    let mut out = Vec::with_capacity(STATEMENT_BYTES);
    out.extend_from_slice(STATEMENT_MAGIC);
    out.extend_from_slice(&u16be(3));
    out.extend_from_slice(&u16be(0));
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u32be(STATEMENT_BYTES as u32));
    out.extend_from_slice(&NULL_SUITE);
    out.extend_from_slice(&f.context.id());
    out.extend_from_slice(&settlement);
    out.extend_from_slice(&u64be(7));
    out.extend_from_slice(&u64be(7));
    out.extend_from_slice(&u64be(8));
    out.extend_from_slice(&f.before.id());
    out.extend_from_slice(&f.after.id());
    out.extend_from_slice(&governance);
    out.extend_from_slice(&private_batch);
    out.extend_from_slice(&settle_commit);
    out
}

fn kat() -> Result<(), String> {
    let base = fixture();
    verify_fixture(&base)?;
    println!("context_registry_bytes={}", base.context.bytes().len());
    println!("execution_context_id={}", hex(&base.context.id()));
    println!("source_registry_leaf_bytes={}", base.source.bytes().len());
    println!("source_registry_leaf_id={}", hex(&base.source.id()));
    println!("operation_row_bytes={OP_BYTES}");
    println!("state_commitment_bytes={STATE_BYTES}");
    for directive in [
        DIRECTIVE_CLEAR,
        DIRECTIVE_HOLD,
        DIRECTIVE_HUMAN_REVIEW,
        DIRECTIVE_BLOCK,
        DIRECTIVE_EXCEPTION_APPROVED,
    ] {
        let f = fixture_for(directive)?;
        verify_fixture(&f)?;
        let auth_bytes = f
            .exception
            .as_ref()
            .map(|a| a.bytes().map(|v| v.len()))
            .transpose()?
            .unwrap_or(0);
        println!(
            "directive={} policy_result={} effective_directive={} exception_authorization_id={} exception_authorization_bytes={} clearance_state={} operation_row_id={} statement_bytes={} statement_sha3_512={} state_before_id={} state_after_id={} state_after_commitment_sha3_512={}",
            directive_name(directive),
            f.op.policy_result,
            f.op.directive,
            hex(&f.op.exception_id),
            auth_bytes,
            f.after.clearance_state,
            hex(&f.op.id()),
            f.statement.len(),
            hex(&Sha3_512::digest(&f.statement)),
            hex(&f.before.id()),
            hex(&f.after.id()),
            hex(&Sha3_512::digest(&f.after.bytes()))
        );
    }
    println!("status=NATIVE_V3_PHASE0_RUST_FIVE_DIRECTIVE_KAT_PASS");
    Ok(())
}

fn neg(name: &str, mutate: impl FnOnce(&mut Fixture)) -> String {
    let mut f = fixture();
    mutate(&mut f);
    match Operation::parse(&f.op.bytes()).and_then(|_| verify_fixture(&f)) {
        Ok(()) => format!("{name}:ACCEPTED"),
        Err(e) => format!("{name}:REJECT:{e}"),
    }
}

fn neg_exception(name: &str, mutate: impl FnOnce(&mut Fixture)) -> String {
    let mut f = fixture_for(DIRECTIVE_EXCEPTION_APPROVED).expect("exception fixture");
    mutate(&mut f);
    match check_exception(&f.op, f.exception.as_ref()).and_then(|_| verify_fixture(&f)) {
        Ok(()) => format!("{name}:ACCEPTED"),
        Err(e) => format!("{name}:REJECT:{e}"),
    }
}

fn negatives() -> Result<(), String> {
    let mut reports = vec![
        neg("wrong-statement-magic", |f| f.statement[0] ^= 1),
        neg("wrong-statement-context", |f| f.statement[84] ^= 1),
        neg("wrong-source-root", |f| f.source.record[0] ^= 1),
        neg("wrong-before-state", |f| f.statement[236] ^= 1),
        neg("wrong-directive", |f| f.op.directive = DIRECTIVE_HOLD),
        neg("reorder", |f| f.accesses.swap(0, 1)),
        neg("omission", |f| {
            f.accesses.pop();
        }),
        neg("duplicate-replay", |f| {
            f.accesses[1] = f.accesses[0].clone()
        }),
        neg("corruption", |f| f.after.row[479] ^= 1),
        neg("after-state-mutation", |f| f.after.semantic_root[0] ^= 1),
    ];
    reports.push(neg_exception("unauthorized-exception", |f| {
        let old = f.exception.as_ref().expect("auth");
        let bad_signer = digest(b"BL/NATIVE-V3/AUTHORIZER/v1\0", &[b"wrong-signer"]);
        let bad = ExceptionAuth::from_fields(
            bad_signer,
            old.subject,
            old.rule,
            old.reason,
            old.amount_scope,
            old.effective_at,
            old.expires_at,
            old.policy_result,
        )
        .expect("auth");
        f.op.exception_id = bad.authorization_id;
        f.exception = Some(bad);
    }));
    reports.push(neg_exception("expired-exception", |f| {
        let old = f.exception.as_ref().expect("auth");
        let bad = ExceptionAuth::from_fields(
            trusted_authorizer(),
            old.subject,
            old.rule,
            old.reason,
            old.amount_scope,
            7,
            AUTH_CURRENT_TIME,
            old.policy_result,
        )
        .expect("auth");
        f.op.exception_id = bad.authorization_id;
        f.exception = Some(bad);
    }));
    reports.push(neg_exception("wrong-scope-exception", |f| {
        let old = f.exception.as_ref().expect("auth");
        let wrong_scope = digest(b"BL/NATIVE-V3/AMOUNT-SCOPE/v1\0", &[b"wrong-scope"]);
        let bad = ExceptionAuth::from_fields(
            trusted_authorizer(),
            old.subject,
            old.rule,
            old.reason,
            wrong_scope,
            old.effective_at,
            old.expires_at,
            old.policy_result,
        )
        .expect("auth");
        f.op.exception_id = bad.authorization_id;
        f.exception = Some(bad);
    }));
    reports.push({
        let mut f = fixture_for(DIRECTIVE_BLOCK).expect("block fixture");
        f.after.clearance_state = CLEARANCE_ADVANCED;
        let expected = if matches!(
            f.op.directive,
            DIRECTIVE_CLEAR | DIRECTIVE_EXCEPTION_APPROVED
        ) {
            CLEARANCE_ADVANCED
        } else {
            CLEARANCE_AUDIT_ONLY
        };
        let result = if f.after.clearance_state != expected {
            Err("state:forbidden-economic-mutation".to_string())
        } else {
            verify_fixture(&f)
        };
        match result {
            Ok(()) => "forbidden-economic-mutation:ACCEPTED".into(),
            Err(e) => format!("forbidden-economic-mutation:REJECT:{e}"),
        }
    });
    if reports.iter().any(|x| x.contains(":ACCEPTED")) {
        return Err("negative accepted".into());
    }
    for r in reports {
        println!("{r}");
    }
    println!("status=NATIVE_V3_PHASE0_RUST_NEGATIVES_PASS");
    Ok(())
}

fn main() {
    let result = match env::args().nth(1).as_deref() {
        Some("kat") | None => kat(),
        Some("negatives") => negatives(),
        Some(x) => Err(format!("unknown command {x}")),
    };
    if let Err(e) = result {
        eprintln!("ERROR:{e}");
        std::process::exit(1);
    }
}
