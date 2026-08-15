//! Diamond--Posen 2024/504 Construction 4.12 nucleus.
//!
//! This is an isolated, ideal-vector-oracle research experiment.  It is not a
//! Blind Ledger proof backend.  The implementation follows the published
//! large-field binary BaseFold IOP schedule: one committed vector oracle,
//! sumcheck messages, verifier-owned folding challenges, and the exact query
//! phase.  It deliberately contains no Merkle/BCS, batching, ring switch,
//! Spartan wrapper, Fiat--Shamir, ZK masking, or semantic relation.

use getrandom::fill as os_random_fill;
use sha3::{Digest, Sha3_512};
use std::env;
use std::fs;
use std::path::Path;

const FIELD_POLY: u16 = 0x11b; // DP24 Section 1.4 AES field: x^8+x^4+x^3+x+1.
const FIELD_BITS: usize = 8;
const STATEMENT_MAGIC: &[u8] = b"DP24ST01";
const PROOF_MAGIC: &[u8] = b"DP24PF01";
const TRANSCRIPT_MAGIC: &[u8] = b"DP24TR01";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct F(u8);

impl F {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    fn add(self, rhs: Self) -> Self { Self(self.0 ^ rhs.0) }
    fn sub(self, rhs: Self) -> Self { self.add(rhs) }
    fn mul(self, rhs: Self) -> Self {
        let mut a = self.0 as u16;
        let mut b = rhs.0;
        let mut p = 0u16;
        for _ in 0..FIELD_BITS {
            if b & 1 != 0 { p ^= a; }
            let carry = a & 0x80 != 0;
            a <<= 1;
            if carry { a ^= FIELD_POLY; }
            b >>= 1;
        }
        Self(p as u8)
    }
    fn pow(self, mut exp: u32) -> Self {
        let mut base = self;
        let mut out = Self::ONE;
        while exp != 0 {
            if exp & 1 != 0 { out = out.mul(base); }
            base = base.mul(base);
            exp >>= 1;
        }
        out
    }
    fn inv(self) -> Result<Self, String> {
        if self == Self::ZERO { Err("field:division-by-zero".into()) } else { Ok(self.pow(254)) }
    }
    fn div(self, rhs: Self) -> Result<Self, String> { Ok(self.mul(rhs.inv()?)) }
}

impl From<u8> for F { fn from(v: u8) -> Self { Self(v) } }

impl From<F> for u8 { fn from(v: F) -> Self { v.0 } }

fn fbytes(values: &[F]) -> Vec<u8> { values.iter().map(|v| v.0).collect() }

fn read_u16(data: &[u8], p: &mut usize, label: &str) -> Result<u16, String> {
    if data.len().saturating_sub(*p) < 2 { return Err(format!("{label}:truncated")); }
    let x = u16::from_be_bytes(data[*p..*p + 2].try_into().unwrap()); *p += 2; Ok(x)
}
fn read_u32(data: &[u8], p: &mut usize, label: &str) -> Result<u32, String> {
    if data.len().saturating_sub(*p) < 4 { return Err(format!("{label}:truncated")); }
    let x = u32::from_be_bytes(data[*p..*p + 4].try_into().unwrap()); *p += 4; Ok(x)
}
fn read_u8(data: &[u8], p: &mut usize, label: &str) -> Result<u8, String> {
    if *p >= data.len() { return Err(format!("{label}:truncated")); }
    let x = data[*p]; *p += 1; Ok(x)
}
fn read_exact<'a>(data: &'a [u8], p: &mut usize, n: usize, label: &str) -> Result<&'a [u8], String> {
    if data.len().saturating_sub(*p) < n { return Err(format!("{label}:truncated")); }
    let x = &data[*p..*p + n]; *p += n; Ok(x)
}
fn expect_bytes(actual: &[u8], wanted: &[u8], label: &str) -> Result<(), String> {
    if actual == wanted { Ok(()) } else { Err(format!("{label}:mismatch")) }
}
fn push_u16(out: &mut Vec<u8>, x: u16) { out.extend_from_slice(&x.to_be_bytes()); }
fn push_u32(out: &mut Vec<u8>, x: u32) { out.extend_from_slice(&x.to_be_bytes()); }
fn hex(data: &[u8]) -> String { data.iter().map(|b| format!("{b:02x}")).collect() }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Params {
    ell: usize,
    rate: usize,
    theta: usize,
    gamma: usize,
}

impl Params {
    // Construction 4.12, step 1: R is the RS rate, theta is the oracle-
    // skipping folding factor, and gamma is the number of query repetitions.
    fn toy() -> Self { Self { ell: 2, rate: 1, theta: 1, gamma: 4 } }
    fn validate(&self) -> Result<(), String> {
        if self.ell == 0 || self.rate == 0 || self.theta == 0 { return Err("params:zero".into()); }
        if self.ell % self.theta != 0 { return Err("params:theta-does-not-divide-ell".into()); }
        if self.ell + self.rate > FIELD_BITS { return Err("params:domain-exceeds-GF256-basis".into()); }
        Ok(())
    }
    fn stage_len(&self, stage: usize) -> usize { 1usize << (self.ell + self.rate - stage) }
    fn stage_indices(&self) -> Vec<usize> {
        let mut v = vec![0];
        let mut i = self.theta;
        while i < self.ell { v.push(i); i += self.theta; }
        v
    }
    fn bytes(&self) -> [u8; 8] { [self.ell as u8, self.rate as u8, self.theta as u8, self.gamma as u8, FIELD_BITS as u8, 0, 0, 0] }
}

fn beta(i: usize) -> F { F(1u8 << i) }

// The normalized subspace polynomials cW_i from DP24 Definition 4.1.
fn w_poly(i: usize, x: F) -> F {
    let mut y = x;
    for k in 0..i {
        let wk_at_beta = w_poly(k, beta(k));
        y = y.mul(y.add(wk_at_beta));
    }
    y
}
fn c_w(i: usize, x: F) -> Result<F, String> {
    w_poly(i, x).div(w_poly(i, beta(i)))
}

fn domain_point(params: Params, stage: usize, index: usize) -> Result<F, String> {
    let mut out = F::ZERO;
    for j in 0..(params.ell + params.rate - stage) {
        // DP24 Corollary 4.5: the stage-i basis is
        // (cW_i(beta_i), ..., cW_i(beta_{ell+R-1})).
        if (index >> j) & 1 != 0 { out = out.add(c_w(stage, beta(stage + j))?); }
    }
    Ok(out)
}

fn q_map(stage: usize, x: F) -> Result<F, String> {
    let wi = w_poly(stage, beta(stage));
    let next = w_poly(stage + 1, beta(stage + 1));
    wi.mul(wi).div(next).map(|scale| scale.mul(x).mul(x.add(F::ONE)))
}

fn check_domain(params: Params) -> Result<(), String> {
    params.validate()?;
    for stage in 0..params.ell {
        let next_len = params.stage_len(stage + 1);
        for suffix in 0..next_len {
            let x0 = domain_point(params, stage, suffix << 1)?;
            let x1 = domain_point(params, stage, (suffix << 1) | 1)?;
            if x1.sub(x0) != F::ONE { return Err(format!("domain:fiber-difference:{stage}:{suffix}")); }
            let y = domain_point(params, stage + 1, suffix)?;
            if q_map(stage, x0)? != y || q_map(stage, x1)? != y { return Err(format!("domain:q-map:{stage}:{suffix}:x0={:02x}:x1={:02x}:q0={:02x}:q1={:02x}:y={:02x}", x0.0, x1.0, q_map(stage, x0)?.0, q_map(stage, x1)?.0, y.0)); }
        }
    }
    Ok(())
}

fn novel_basis_eval(ell: usize, basis_index: usize, x: F) -> Result<F, String> {
    let mut out = F::ONE;
    for k in 0..ell {
        if (basis_index >> k) & 1 != 0 { out = out.mul(c_w(k, x)?); }
    }
    Ok(out)
}

fn commit_codeword(params: Params, t: &[F]) -> Result<Vec<F>, String> {
    if t.len() != 1usize << params.ell { return Err("commit:t-length".into()); }
    let mut out = Vec::with_capacity(params.stage_len(0));
    for index in 0..params.stage_len(0) {
        let x = domain_point(params, 0, index)?;
        let mut value = F::ZERO;
        for (j, coeff) in t.iter().enumerate() { value = value.add(coeff.mul(novel_basis_eval(params.ell, j, x)?)); }
        out.push(value);
    }
    Ok(out)
}

// The paper's Section 1.4 example supplies the coefficients a_j of the
// multilinear polynomial in the monomial basis.  Construction 4.12 places
// those same coefficients in the novel polynomial basis for the committed
// univariate encoding; the fold therefore recovers this monomial evaluation.
fn monomial_eval(t: &[F], point: &[F]) -> Result<F, String> {
    if t.len() != 1usize << point.len() { return Err("monomial:length".into()); }
    let mut out = F::ZERO;
    for (j, coeff) in t.iter().enumerate() {
        let mut monomial = F::ONE;
        for (i, x) in point.iter().enumerate() { if (j >> i) & 1 != 0 { monomial = monomial.mul(*x); } }
        out = out.add(coeff.mul(monomial));
    }
    Ok(out)
}

fn eq_extension(r: &[F], x: &[F]) -> Result<F, String> {
    if r.len() != x.len() { return Err("eq:length".into()); }
    let mut out = F::ONE;
    for (a, b) in r.iter().zip(x) { out = out.mul(F::ONE.sub(*a).mul(F::ONE.sub(*b)).add(a.mul(*b))); }
    Ok(out)
}

fn h_value(t: &[F], r: &[F], prefix: &[F], variable: F, suffix_bits: usize) -> Result<F, String> {
    let i = prefix.len();
    let mut x = prefix.to_vec(); x.push(variable);
    for j in 0..(r.len() - i - 1) { x.push(if (suffix_bits >> j) & 1 != 0 { F::ONE } else { F::ZERO }); }
    Ok(monomial_eval(t, &x)?.mul(eq_extension(r, &x)?))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Poly { coeff: [F; 3] }

impl Poly {
    fn eval(&self, x: F) -> F { self.coeff[0].add(self.coeff[1].mul(x)).add(self.coeff[2].mul(x).mul(x)) }
    fn from_h_values(h0: F, h1: F, h2: F) -> Result<Self, String> {
        let b = h1.add(h0);
        let c = h2.add(h0);
        let a2 = c.add(F(2).mul(b)).div(F(6))?;
        Ok(Self { coeff: [h0, b.add(a2), a2] })
    }
    fn bytes(&self) -> [u8; 3] { [self.coeff[0].0, self.coeff[1].0, self.coeff[2].0] }
}

fn sumcheck_poly(params: Params, t: &[F], r: &[F], prefix: &[F]) -> Result<Poly, String> {
    let mut h = [F::ZERO; 3];
    for (j, x) in [F::ZERO, F::ONE, F(2)].iter().enumerate() {
        let mut value = F::ZERO;
        for suffix in 0..(1usize << (params.ell - prefix.len() - 1)) { value = value.add(h_value(t, r, prefix, *x, suffix)?); }
        h[j] = value;
    }
    Poly::from_h_values(h[0], h[1], h[2])
}

fn fold_one(params: Params, values: &[F], stage: usize, challenge: F) -> Result<Vec<F>, String> {
    if values.len() < 2 || values.len() % 2 != 0 { return Err("fold:length".into()); }
    let mut out = Vec::with_capacity(values.len() / 2);
    for suffix in 0..values.len() / 2 {
        let x0 = domain_point(params, stage, suffix << 1)?;
        let x1 = domain_point(params, stage, (suffix << 1) | 1)?;
        let f0 = values[suffix << 1]; let f1 = values[(suffix << 1) | 1];
        let left = x1.mul(f0).sub(x0.mul(f1));
        let right = f1.sub(f0);
        // Definition 4.6 is evaluation of the degree-<2 interpolant at the
        // folding challenge: a0 + r*a1, where the matrix supplies (a0,a1).
        out.push(left.add(challenge.mul(right)));
    }
    Ok(out)
}

trait ChallengeSource {
    fn field(&mut self) -> Result<F, String>;
    fn bit(&mut self) -> Result<bool, String>;
}

struct FixedSource { bytes: Vec<u8>, pos: usize, bit_pos: usize }
impl FixedSource { fn new(bytes: Vec<u8>) -> Self { Self { bytes, pos: 0, bit_pos: 0 } } }
impl ChallengeSource for FixedSource {
    fn field(&mut self) -> Result<F, String> { let b = *self.bytes.get(self.pos).ok_or("fixed:exhausted")?; self.pos += 1; Ok(F(b)) }
    fn bit(&mut self) -> Result<bool, String> {
        let b = *self.bytes.get(self.pos).ok_or("fixed:exhausted")?;
        let bit = (b >> self.bit_pos) & 1 != 0; self.bit_pos += 1;
        if self.bit_pos == 8 { self.bit_pos = 0; self.pos += 1; }
        Ok(bit)
    }
}

struct OsSource;
impl ChallengeSource for OsSource {
    fn field(&mut self) -> Result<F, String> { let mut b = [0u8; 1]; os_random_fill(&mut b).map_err(|e| format!("os-rng:{e}"))?; Ok(F(b[0])) }
    fn bit(&mut self) -> Result<bool, String> { Ok(self.field()?.0 & 1 != 0) }
}

fn sample_index(source: &mut impl ChallengeSource, bits: usize) -> Result<usize, String> {
    let mut x = 0usize;
    for i in 0..bits { if source.bit()? { x |= 1usize << i; } }
    Ok(x)
}

const PROTOCOL_DOMAIN: &[u8] = b"DP24/C4.12/v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Statement { params: Params, domain: Vec<u8>, r: Vec<F>, s: F }

impl Statement {
    fn new(params: Params, r: Vec<F>, s: F) -> Result<Self, String> {
        params.validate()?;
        if r.len() != params.ell { return Err("statement:r-length".into()); }
        Ok(Self { params, domain: PROTOCOL_DOMAIN.to_vec(), r, s })
    }
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new(); out.extend_from_slice(STATEMENT_MAGIC); out.extend_from_slice(&self.params.bytes());
        push_u16(&mut out, self.domain.len() as u16); out.extend_from_slice(&self.domain); out.extend_from_slice(&fbytes(&self.r)); out.push(self.s.0); out
    }
    fn parse(data: &[u8]) -> Result<Self, String> {
        let mut p = 0; expect_bytes(read_exact(data, &mut p, 8, "statement:magic")?, STATEMENT_MAGIC, "statement:magic")?;
        let params = parse_params(data, &mut p)?;
        let domain_len = read_u16(data, &mut p, "statement:domain-length")? as usize;
        let domain = read_exact(data, &mut p, domain_len, "statement:domain")?.to_vec();
        if domain != PROTOCOL_DOMAIN { return Err("statement:domain".into()); }
        let mut r = Vec::with_capacity(params.ell);
        for _ in 0..params.ell { r.push(F(read_u8(data, &mut p, "statement:r")?)); }
        let s = F(read_u8(data, &mut p, "statement:s")?);
        if p != data.len() { return Err("statement:trailing".into()); }
        Self::new(params, r, s)
    }
}

fn parse_params(data: &[u8], p: &mut usize) -> Result<Params, String> {
    let raw = read_exact(data, p, 8, "params")?;
    if raw[4] != FIELD_BITS as u8 || raw[5..] != [0, 0, 0] { return Err("params:reserved".into()); }
    let params = Params { ell: raw[0] as usize, rate: raw[1] as usize, theta: raw[2] as usize, gamma: raw[3] as usize };
    params.validate()?; Ok(params)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Proof { params: Params, oracles: Vec<(usize, Vec<F>)>, polys: Vec<Poly>, c: F }

impl Proof {
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new(); out.extend_from_slice(PROOF_MAGIC); out.extend_from_slice(&self.params.bytes());
        push_u16(&mut out, self.oracles.len() as u16);
        for (stage, values) in &self.oracles { push_u16(&mut out, *stage as u16); push_u32(&mut out, values.len() as u32); out.extend_from_slice(&fbytes(values)); }
        push_u16(&mut out, self.polys.len() as u16); for poly in &self.polys { out.extend_from_slice(&poly.bytes()); }
        out.push(self.c.0); out
    }
    fn parse(data: &[u8]) -> Result<Self, String> {
        let mut p = 0; expect_bytes(read_exact(data, &mut p, 8, "proof:magic")?, PROOF_MAGIC, "proof:magic")?;
        let params = parse_params(data, &mut p)?; let count = read_u16(data, &mut p, "proof:oracle-count")? as usize;
        if count != params.ell / params.theta { return Err("proof:oracle-count".into()); }
        let mut oracles = Vec::with_capacity(count);
        for _ in 0..count {
            let stage = read_u16(data, &mut p, "proof:oracle-stage")? as usize;
            let len = read_u32(data, &mut p, "proof:oracle-length")? as usize;
            if stage >= params.ell || stage % params.theta != 0 || len != params.stage_len(stage) { return Err("proof:oracle-geometry".into()); }
            let raw = read_exact(data, &mut p, len, "proof:oracle-values")?;
            oracles.push((stage, raw.iter().copied().map(F).collect()));
        }
        let poly_count = read_u16(data, &mut p, "proof:poly-count")? as usize;
        if poly_count != params.ell { return Err("proof:poly-count".into()); }
        let mut polys = Vec::with_capacity(poly_count);
        for _ in 0..poly_count { polys.push(Poly { coeff: [F(read_u8(data, &mut p, "proof:poly")?), F(read_u8(data, &mut p, "proof:poly")?), F(read_u8(data, &mut p, "proof:poly")?)] }); }
        let c = F(read_u8(data, &mut p, "proof:c")?);
        if p != data.len() { return Err("proof:trailing".into()); }
        Ok(Self { params, oracles, polys, c })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Transcript { params: Params, statement: Vec<u8>, fold_challenges: Vec<F>, queries: Vec<usize> }

impl Transcript {
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new(); out.extend_from_slice(TRANSCRIPT_MAGIC); out.extend_from_slice(&self.params.bytes());
        push_u32(&mut out, self.statement.len() as u32); out.extend_from_slice(&self.statement);
        push_u16(&mut out, self.fold_challenges.len() as u16); out.extend_from_slice(&fbytes(&self.fold_challenges));
        push_u16(&mut out, self.queries.len() as u16); for v in &self.queries { push_u32(&mut out, *v as u32); }
        out
    }
    fn parse(data: &[u8]) -> Result<Self, String> {
        let mut p = 0; expect_bytes(read_exact(data, &mut p, 8, "transcript:magic")?, TRANSCRIPT_MAGIC, "transcript:magic")?;
        let params = parse_params(data, &mut p); let params = params?;
        let statement_len = read_u32(data, &mut p, "transcript:statement-length")? as usize;
        let statement = read_exact(data, &mut p, statement_len, "transcript:statement")?.to_vec();
        let fold_count = read_u16(data, &mut p, "transcript:fold-count")? as usize;
        if fold_count != params.ell { return Err("transcript:fold-count".into()); }
        let mut fold_challenges = Vec::with_capacity(fold_count); for _ in 0..fold_count { fold_challenges.push(F(read_u8(data, &mut p, "transcript:fold")?)); }
        let query_count = read_u16(data, &mut p, "transcript:query-count")? as usize;
        if query_count != params.gamma { return Err("transcript:query-count".into()); }
        let mut queries = Vec::with_capacity(query_count); for _ in 0..query_count { queries.push(read_u32(data, &mut p, "transcript:query")? as usize); }
        if p != data.len() { return Err("transcript:trailing".into()); }
        Ok(Self { params, statement, fold_challenges, queries })
    }
}

fn statement_for_t(params: Params, t: &[F], r: Vec<F>) -> Result<Statement, String> { Statement::new(params, r.clone(), monomial_eval(t, &r)?) }

fn fold_query_fiber(oracle: &[F], params: Params, stage: usize, challenges: &[F], suffix: usize) -> Result<F, String> {
    if challenges.len() != params.theta { return Err("query:challenge-width".into()); }
    let mut values = Vec::with_capacity(1usize << params.theta);
    for u in 0..(1usize << params.theta) { values.push(*oracle.get((suffix << params.theta) | u).ok_or("query:oracle-index")?); }
    for (offset, challenge) in challenges.iter().enumerate() {
        let current_stage = stage + offset;
        let current_suffix_bits = params.theta - offset;
        let mut next = Vec::with_capacity(values.len() / 2);
        for local in 0..values.len() / 2 {
            let x0_index = (suffix << current_suffix_bits) | (local << 1);
            let x1_index = x0_index | 1;
            let x0 = domain_point(params, current_stage, x0_index)?;
            let x1 = domain_point(params, current_stage, x1_index)?;
            let left = x1.mul(values[local << 1]).sub(x0.mul(values[(local << 1) | 1]));
            let right = values[(local << 1) | 1].sub(values[local << 1]);
            next.push(left.add(challenge.mul(right)));
        }
        values = next;
    }
    Ok(values[0])
}

// Construction 4.12, lines 1--2: the prover sends each h_i before the
// verifier samples r'_i.  The source is owned by the verifier; the prover only
// receives the sampled value after its message has been accepted.
fn prove_session(
    statement: &Statement,
    t: &[F],
    source: &mut impl ChallengeSource,
) -> Result<(Proof, Transcript), String> {
    let params = statement.params; params.validate()?; check_domain(params)?;
    if t.len() != 1usize << params.ell { return Err("prover:t-length".into()); }
    let f0 = commit_codeword(params, t)?;
    let mut current = f0.clone();
    let mut oracles = vec![(0usize, f0)];
    let mut polys = Vec::with_capacity(params.ell);
    let mut fold_challenges = Vec::with_capacity(params.ell);
    let mut prefix = Vec::with_capacity(params.ell);
    for i in 0..params.ell {
        let poly = sumcheck_poly(params, t, &statement.r, &prefix)?;
        polys.push(poly); // exact prover message before this round's challenge
        let challenge = source.field()?;
        fold_challenges.push(challenge); prefix.push(challenge);
        current = fold_one(params, &current, i, challenge)?;
        if i + 1 < params.ell && (i + 1) % params.theta == 0 { oracles.push((i + 1, current.clone())); }
    }
    let c = current[0];
    let mut queries = Vec::with_capacity(params.gamma);
    for _ in 0..params.gamma { queries.push(sample_index(source, params.ell + params.rate)?); }
    Ok((Proof { params, oracles, polys, c }, Transcript { params, statement: statement.bytes(), fold_challenges, queries }))
}

#[derive(Debug)]
struct VerifyStats { sumcheck_events: usize, query_events: usize, oracle_queries: usize }

fn verify_session(statement_bytes: &[u8], proof_bytes: &[u8], transcript_bytes: &[u8]) -> Result<VerifyStats, String> {
    let statement = Statement::parse(statement_bytes)?;
    let proof = Proof::parse(proof_bytes)?;
    let transcript = Transcript::parse(transcript_bytes)?;
    let params = statement.params;
    if proof.params != params || transcript.params != params { return Err("verify:parameter-mismatch".into()); }
    if transcript.statement != statement_bytes { return Err("verify:statement-not-verifier-owned".into()); }
    check_domain(params)?;
    let expected_stages = params.stage_indices();
    let actual_stages: Vec<usize> = proof.oracles.iter().map(|(stage, _)| *stage).collect();
    if actual_stages != expected_stages { return Err("verify:oracle-order-or-omission".into()); }
    if proof.polys.len() != params.ell || transcript.fold_challenges.len() != params.ell { return Err("verify:round-count".into()); }
    let mut s = statement.s;
    for (i, poly) in proof.polys.iter().enumerate() {
        if s != poly.eval(F::ZERO).add(poly.eval(F::ONE)) { return Err(format!("verify:sumcheck:{i}")); }
        s = poly.eval(transcript.fold_challenges[i]);
    }
    let eq = eq_extension(&statement.r, &transcript.fold_challenges)?;
    if s != eq.mul(proof.c) { return Err(format!("verify:final-evaluation:s={:02x}:eq={:02x}:c={:02x}:rprime={}", s.0, eq.0, proof.c.0, hex(&fbytes(&transcript.fold_challenges)))); }

    let oracle_for = |stage: usize| -> Result<&Vec<F>, String> {
        proof.oracles.iter().find(|(i, _)| *i == stage).map(|(_, v)| v).ok_or_else(|| "verify:missing-oracle".into())
    };
    let mut oracle_queries = 0usize;
    for (q_index, v) in transcript.queries.iter().enumerate() {
        if *v >= params.stage_len(0) { return Err(format!("verify:query-range:{q_index}")); }
        let mut prior = None;
        for stage in (0..params.ell).step_by(params.theta) {
            let oracle = oracle_for(stage)?;
            if stage > 0 {
                let expected = *oracle.get(v >> stage).ok_or("verify:query-index")?;
                if prior != Some(expected) { return Err(format!("verify:query-link:{q_index}:{stage}")); }
            }
            let suffix = v >> (stage + params.theta);
            prior = Some(fold_query_fiber(oracle, params, stage, &transcript.fold_challenges[stage..stage + params.theta], suffix)?);
            oracle_queries += 1usize << params.theta;
        }
        if prior != Some(proof.c) { return Err(format!("verify:query-final:{q_index}")); }
    }
    Ok(VerifyStats { sumcheck_events: params.ell, query_events: params.gamma, oracle_queries })
}

fn toy_witness() -> (Params, Vec<F>, Vec<F>) {
    let params = Params::toy();
    // DP24 Section 1.4 / Figure 8's published hand-checkable AES example.
    let t = vec![F(0xde), F(0xad), F(0xbe), F(0xef)];
    let r = vec![F(0xab), F(0xcd)];
    (params, t, r)
}

fn deterministic_session() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let (params, t, r) = toy_witness();
    let statement = statement_for_t(params, &t, r)?;
    let mut source = FixedSource::new(vec![0xab, 0xcd, 0xa5, 0x3c, 0x5a]);
    let (proof, transcript) = prove_session(&statement, &t, &mut source)?;
    let statement_bytes = statement.bytes(); let proof_bytes = proof.bytes(); let transcript_bytes = transcript.bytes();
    verify_session(&statement_bytes, &proof_bytes, &transcript_bytes)?;
    Ok((statement_bytes, proof_bytes, transcript_bytes))
}

fn print_kat() -> Result<(), String> {
    let (statement_bytes, proof_bytes, transcript_bytes) = deterministic_session()?;
    let statement = Statement::parse(&statement_bytes)?; let proof = Proof::parse(&proof_bytes)?; let transcript = Transcript::parse(&transcript_bytes)?;
    let f0 = &proof.oracles[0].1;
    let f1 = &proof.oracles[1].1;
    println!("status=DP24_CONSTRUCTION_4_12_DETERMINISTIC_KAT_PASS");
    println!("field=GF(2^8)_AES_poly_0x11b_basis_beta_i=x^i");
    println!("ell={} rate_R={} theta={} gamma={}", statement.params.ell, statement.params.rate, statement.params.theta, statement.params.gamma);
    println!("domain_check=PASS q_fibers_and_x1_minus_x0_1");
    println!("statement_bytes={} statement_sha3_512={}", statement_bytes.len(), hex(&Sha3_512::digest(&statement_bytes)));
    println!("claimed_eval=0x{:02x}", statement.s.0);
    println!("f0={}", hex(&fbytes(f0)));
    println!("f1={}", hex(&fbytes(f1)));
    println!("sumcheck_polys={}", proof.polys.iter().map(|p| hex(&p.bytes())).collect::<Vec<_>>().join(","));
    println!("fold_challenges={}", hex(&fbytes(&transcript.fold_challenges)));
    println!("query_indices={}", transcript.queries.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","));
    println!("c=0x{:02x}", proof.c.0);
    println!("proof_bytes={} transcript_bytes={}", proof_bytes.len(), transcript_bytes.len());
    println!("independent_verify=PASS sumcheck_events={} query_events={}", statement.params.ell, statement.params.gamma);
    Ok(())
}

fn run_os(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("run:mkdir:{e}"))?;
    let (params, t, r) = toy_witness(); let statement = statement_for_t(params, &t, r)?;
    let mut source = OsSource;
    let started = std::time::Instant::now();
    let (proof, transcript) = prove_session(&statement, &t, &mut source)?;
    let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
    let statement_bytes = statement.bytes(); let proof_bytes = proof.bytes(); let transcript_bytes = transcript.bytes();
    fs::write(dir.join("statement.bin"), &statement_bytes).map_err(|e| format!("run:statement:{e}"))?;
    fs::write(dir.join("proof.bin"), &proof_bytes).map_err(|e| format!("run:proof:{e}"))?;
    fs::write(dir.join("transcript.bin"), &transcript_bytes).map_err(|e| format!("run:transcript:{e}"))?;
    let verify_start = std::time::Instant::now();
    let stats = verify_session(&statement_bytes, &proof_bytes, &transcript_bytes)?;
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    println!("status=DP24_CONSTRUCTION_4_12_INTERACTIVE_PROOF_PASS");
    println!("challenge_authority=verifier-owned-OS-CSPRNG-before-each-fold-and-query");
    println!("statement_path={} proof_path={} transcript_path={}", dir.join("statement.bin").display(), dir.join("proof.bin").display(), dir.join("transcript.bin").display());
    println!("statement_bytes={} proof_bytes={} transcript_bytes={}", statement_bytes.len(), proof_bytes.len(), transcript_bytes.len());
    println!("prove_ms={prove_ms:.3} verify_ms={verify_ms:.3} sumcheck_events={} query_events={} oracle_queries={}", stats.sumcheck_events, stats.query_events, stats.oracle_queries);
    println!("proof_sha3_512={} transcript_sha3_512={}", hex(&Sha3_512::digest(&proof_bytes)), hex(&Sha3_512::digest(&transcript_bytes)));
    Ok(())
}

fn verify_files(dir: &Path) -> Result<(), String> {
    let statement = fs::read(dir.join("statement.bin")).map_err(|e| format!("verify:statement:{e}"))?;
    let proof = fs::read(dir.join("proof.bin")).map_err(|e| format!("verify:proof:{e}"))?;
    let transcript = fs::read(dir.join("transcript.bin")).map_err(|e| format!("verify:transcript:{e}"))?;
    let started = std::time::Instant::now(); let stats = verify_session(&statement, &proof, &transcript)?; let ms = started.elapsed().as_secs_f64() * 1000.0;
    println!("status=DP24_INDEPENDENT_VERIFIER_ACCEPT");
    println!("exit=0 verify_ms={ms:.3} sumcheck_events={} query_events={} oracle_queries={}", stats.sumcheck_events, stats.query_events, stats.oracle_queries);
    Ok(())
}

fn one_negative(label: &str, result: Result<VerifyStats, String>) -> String {
    match result { Ok(_) => format!("{label}:ACCEPTED"), Err(e) => format!("{label}:REJECT:{e}") }
}

fn negatives() -> Result<(), String> {
    let (statement, proof, transcript) = deterministic_session()?;
    let mut reports = Vec::new();

    let mut s_bad = Statement::parse(&statement)?; s_bad.s = s_bad.s.add(F::ONE); let s_bad_bytes = s_bad.bytes();
    let mut tr_bad = Transcript::parse(&transcript)?; tr_bad.statement = s_bad_bytes.clone();
    reports.push(one_negative("wrong-evaluation", verify_session(&s_bad_bytes, &proof, &tr_bad.bytes())));

    let mut p_bad = Proof::parse(&proof)?; let touched = Transcript::parse(&transcript)?.queries[0]; p_bad.oracles[0].1[touched] = p_bad.oracles[0].1[touched].add(F::ONE);
    reports.push(one_negative("wrong-commitment-oracle", verify_session(&statement, &p_bad.bytes(), &transcript)));

    let mut q_bad = Transcript::parse(&transcript)?; q_bad.queries[0] = q_bad.params.stage_len(0);
    reports.push(one_negative("wrong-query", verify_session(&statement, &proof, &q_bad.bytes())));

    let mut c_bad = Transcript::parse(&transcript)?; c_bad.fold_challenges[0] = c_bad.fold_challenges[0].add(F::ONE);
    reports.push(one_negative("wrong-transcript-challenge", verify_session(&statement, &proof, &c_bad.bytes())));

    let mut p_corrupt = Proof::parse(&proof)?; p_corrupt.polys[0].coeff[0] = p_corrupt.polys[0].coeff[0].add(F::ONE);
    reports.push(one_negative("proof-corruption", verify_session(&statement, &p_corrupt.bytes(), &transcript)));

    let mut p_truncated = proof.clone(); p_truncated.pop();
    reports.push(one_negative("proof-truncation", verify_session(&statement, &p_truncated, &transcript)));

    let mut p_handle = Proof::parse(&proof)?; p_handle.oracles[0].0 = 1;
    reports.push(one_negative("oracle-handle-reorder", verify_session(&statement, &p_handle.bytes(), &transcript)));

    for report in &reports { println!("{report}"); }
    println!("merkle-path=SKIPPED:Construction_4_12_ideal_vector_oracle_has_no_Merkle_or_BCS_path");
    if reports.iter().any(|x| x.contains(":ACCEPTED")) { return Err("negative accepted".into()); }
    println!("status=DP24_APPLICABLE_NEGATIVES_PASS rejects={} skipped_merkle=1", reports.len());
    Ok(())
}

fn security_ledger() -> Result<(), String> {
    // DP24 Theorem 4.17, Construction 4.12 bound, evaluated in the exact
    // ideal-vector-oracle model (not a concrete Merkle/BCS or ZK composition).
    let ell = 28usize; let rate = 1usize; let field_degree = 256usize; let theta = 4usize; let gamma = 324usize; let instances = 56usize;
    let first = (2f64.powi((ell + rate) as i32) + 2.0 * ell as f64) * 2f64.powi(-(field_degree as i32));
    let query_base = 0.5 + 1.0 / (2.0 * 2f64.powi(rate as i32));
    let query = query_base.powi(gamma as i32);
    let epsilon = first + query;
    let bits = -epsilon.log2();
    let union = instances as f64 * epsilon;
    let union_bits = -union.log2();
    println!("status=DP24_SECURITY_CALCULATOR_PASS");
    println!("theorem=ePrint_2024_504_Theorem_4_17");
    println!("construction=4.12 model=ideal-vector-oracle only");
    println!("ell={ell} rate_R={rate} field=L=GF(2^256) theta={theta} gamma={gamma}");
    println!("term_extraction_plus_sumcheck={first:.18e}");
    println!("term_query=(1/2+1/(2*2^R))^gamma={query:.18e}");
    println!("epsilon_single={epsilon:.18e} bits_single={bits:.9}");
    println!("instances={instances} epsilon_union={union:.18e} bits_union={union_bits:.9}");
    println!("complete_bound_available=true scope=DP24_ideal_vector_oracle_IOPCS");
    println!("concrete_merkle_binding=false concrete_BCS_QROM=false native_hiding=false semantic_composition=false atomic_product_proof=false");
    println!("toy_params_are_kat_only=true toy_security_claim=false");
    Ok(())
}

fn usage() -> ! {
    eprintln!("usage: native_v3_dp_nucleus kat|run <dir>|verify <dir>|negatives|security");
    std::process::exit(2)
}

fn main() {
    let mut args = env::args(); let _program = args.next();
    let result = match args.next().as_deref() {
        Some("kat") => print_kat(),
        Some("run") => args.next().map(|p| run_os(Path::new(&p))).unwrap_or_else(|| usage()),
        Some("verify") => args.next().map(|p| verify_files(Path::new(&p))).unwrap_or_else(|| usage()),
        Some("negatives") => negatives(),
        Some("security") => security_ledger(),
        _ => usage(),
    };
    if let Err(error) = result { eprintln!("ERROR:{error}"); std::process::exit(1); }
}
