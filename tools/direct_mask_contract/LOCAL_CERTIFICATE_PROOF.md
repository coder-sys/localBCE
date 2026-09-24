# Complete local-certificate proof record

Complete local-certificate input for the same contract phase (the earlier driver message supplied only its conclusion/query-accounting correction). This argument was completed and independently reviewed against the pinned primitive. Persist this mathematical substance, with exact source pointers, under the existing tools/direct_mask_contract/** scope; keep its query-only qualification limit explicit.

Use the same pinned primitive 392e53e2b3d5936cb9cb2681b9e2d803143b1e17, native 0bce17b884f0076f078026645bef8302b5ed1a53, ℓ 125048/m 172232 and actual x 1147/m1 506416. All current flags remain false.

## 1. Active oracle domains

One 2112-bit ideal oracle, prefix projections H0:768,H1:512,FS1:2112,FS2:832,FS3:256. Actual H0 is iv||00, length 17. H1 outer is 33*64 bytes||01, length 2113; vector inputs 128*96||01 and 256*96||01, lengths 12289/24577. FS domains are distinct and every canonical FS input contains m1 506416, so these active input sets are disjoint. FS1 parts(x,ν,m1,σ1); FS2 additionally γ1,m2,σ2; FS3 additionally γ2,m3,σ3, each actual part length-prefixed. This concerns admitted canonical x and the fixed relation/descriptor, not arbitrary generic helper arguments.

## 2. LeafBad

For each tree tweak i+6399, fixed public AES expansion of a 256-bit key k yields G_i(k,iv)=(sd(k),tail(k)) in 256+768 bits. Its commitment is c=ν*iota(sd)+tail in GF(2^768). LeafBad(iv,ν) means some tree has two keys with DIFFERENT induced sd but the same c. For each such pair, multiplication by the nonzero embedded sd difference is invertible, giving exactly one ν solution. Therefore

Prν[LeafBad] ≤ 33*choose(2^256,2)/2^768 < 33/2^256.

The bound quantifies over all keys per tree tweak; it has no 6400-leaf factor. If LeafBad is false, each commitment determines at most one induced sd, even if several leaf keys share that sd. Finite enumeration defines this extraction without adding RO queries; efficiency is not asserted for that enumeration.

## 3. Explicit chain and graph

A chain comprises H0(iv)=ν, 33 correctly positioned H1 leaf-vector rows H1(C_i)=h_i, and H1(h0||...||h32)=hcom: at most 35 distinct rows. For an explicit good-ν chain and its exact FS-fixed x,iv,ν,hcom,corrections, define G as follows. A raw α is in its domain iff its 8 grinding bits pass, actual decoder succeeds, and a fixed-length BAVC opening passes the actual Topen/opening checks with reconstructed PRE-H1 leaf vectors exactly C_i. No further oracle calls appear in this definition; it is finite deterministic opening/key enumeration against the fixed chain.

For each allowed α, actual bit reconstruction/corrections/W_CRT/six-mask packing yields Q(Δ) in K^(ℓ+6). All valid openings for that α have the same nonhidden commitment values under the same iv/tweak/ν. Good LeafBad forces identical induced nonhidden sd; reconstruction is therefore identical. Thus G={(Δ,Q(Δ))} is a well-defined graph fixed before FS1. The injective actual W_CRT map gives |G|≤S0=2^248. Actual opening feasibility is retained.

## 4. Chain-local algebraic events for a false x

Let V_γ1:K^(ℓ+6)->K^4 be the actual linear consistency hash, and h_γ2:K^m->K the actual unmasked linear constraint hash.

B1 (through FS1): some NONCOLLINEAR triple of G maps to a collinear triple under (Δ,Q)->(Δ,V_γ1(Q)). For distinct Δ1,Δ2,Δ3, put

r=(Δ2+Δ3)Q1+(Δ3+Δ1)Q2+(Δ1+Δ2)Q3.

Noncollinearity is r≠0; image collinearity is V_γ1(r)=0. The independently established universal-hash bound therefore gives

Prγ1[B1]≤choose(S0,3)*ε_v=e_KOS.

When B1 is false and m2=(tilde_u,D,d_w) is fixed, the subgraph

G_m2={(Δ,Q) in G: V_γ1(Q)=D+Δ*tilde_u}

is collinear, since every triple has collinear images. If it has at least 2 points, its entire graph lies on their unique affine line.

B2 (through FS2): require B1 false and |G_m2|≥4. Write the line Q=v+Δu and set w=u_witness+d_w. The fixed constraint vector f_x(w) is nonzero: otherwise the established bitness/padding constraints yield a valid binary witness for the false x. Define B2 by h_γ2(f_x(w))=0. The vector is fixed before FS2, hence Pr[B2]≤ε_z.

B3 (through FS3): require B1/B2 false, treating B2 false when |G_m2|≤3. The raw γ3 must decode to G_m2 and satisfy the actual verifier's final equation for fixed m3=(a0,a1,a2). If |G_m2|≤3, there are at most 3 accepting raw strings. Otherwise the final verification difference is a degree≤3 polynomial with nonzero cubic coefficient h_γ2(f_x(w)). The direct-mask term is

qbar0(Z)+Z*qbar1(Z)=vbar0+Z*(ubar0+vbar1)+Z^2*ubar1;

neither it nor a0+a1Z+a2Z² changes the cubic coefficient. A nonzero cubic has at most 3 roots. Grinding plus injective decoding therefore gives at most 3 accepting strings among ALL 2^256 raw γ3 values, so Pr[B3]≤3/2^256.

## 5. Predicate and replacement-stable local witnesses

For any finite partial oracle database D, let P(D) hold iff D contains:

(a) one LeafBad H0 row; OR

(b) two distinct active H1 inputs with equal 512-bit outputs, or two distinct FS1 inputs with equal full 2112-bit outputs, or two distinct FS2 inputs with equal full 832-bit outputs; OR

(c) an explicit matching commitment/FS chain for a false x satisfying B1,B2,or B3.

Witness sizes are 1,2,36,37,38 respectively. Every condition in a selected witness is determined by its explicit rows and fixed deterministic algorithms. Therefore EVERY D' agreeing on those rows satisfies P, even if ANY other rows are deleted/replaced/inserted. This avoids a globally preferred extraction that could change when other rows are replaced. P is monotone under inclusion.

## 6. Complete one-row insertion/replacement bound

Fix |D|≤j and P(D)=false. A newly successful certificate must contain the inserted row. Existing collision-freedom means a fixed hcom selects at most one outer row and every vector hash selects at most one vector input. Thus an existing/fixed FS input has at most one complete commitment chain.

Inserted H0: LeafBad probability 33/2^256; otherwise completing an existing FS chain must hit one of at most j explicitly stored ν targets: j/2^768.

Inserted vector H1: at most j existing H1 output collision targets plus 33j positions in existing outer inputs: 34j/2^512.

Inserted outer H1: at most j existing H1 output collision targets plus j explicit FS hcom targets: 2j/2^512.

Inserted FS1: at most j existing FS1 full-output collision targets plus j γ1 targets in existing FS2/3 inputs, plus its direct B1 event for its unique chain: 2j/2^2112+e_KOS.

Inserted FS2: analogous 2j/2^832+ε_z.

Inserted FS3: one fixed ancestor chain and terminal≤3/2^256; if no complete chain, no event.

Any other input: 0.

A single typed insertion has at most one direct algebraic round event, so take their MAXIMUM, not their sum. Using the separately verified actual hash bounds e_KOS≤3/2^256 and ε_z≤3/2^256:

δ(j)≤34j/2^512+33/2^256+max(e_KOS,ε_z,3/2^256)
     ≤102j/2^512+36/2^256.

For replacement at an existing input t, first remove that row. Monotonicity preserves P=false in D0=D\{t}; apply the same fresh-insertion bound to D0. This is the arbitrary row-replacement property needed by the supplied Lemma 10.44.

## 7. Completion/global event and exact limit

An accepted false proof supplies its complete chain using at most 38 verification rows. Either ν is LeafBad, B1 holds, B2 holds, or actual acceptance witnesses B3. Thus these rows force P. Merely outputting the actual verifier input list is a certificate and does not require seed inversion.

For the output-local-witness form of FAEST Lemma 10.44, a QUERY-ONLY reduction can select the first false accepted x from its entire finite verification history by finite exhaustive membership testing (up to 2^125048 binary witnesses), which needs no additional RO query. This selector is NOT claimed efficient. We do not replace Lemma 10.44 by an unsupported stronger final-database theorem. The resulting ideal-QROM bound permits unbounded computation between queries; it does not prove a concrete efficient SHAKE reduction.

Literal internal calls are bounded by 38A+39V+R. dmv_prove repeats H0(iv) after BAVC, and verify repeats the same H0 inside reconstruction. The soundness reduction may cache these identical CLASSICAL calls without changing the joint fixed-oracle distribution; no reprogramming occurs in this soundness game. Thus its external query count is

q0=Q+37A+38V+R,
q=q0+38 (local witness completion).

R is total FS3 candidate calls, first included. All honest provers, candidate verifications, aborts/retries and adversarial queries share this one global experiment.

Lemma 10.44 gives

Pr[some false accepted x]≤(Σ_(k=1..q) sqrt(10*(102k/2^512+36/2^256)))²
≤min(1,1020q³/2^512+360q²/2^256).

Cauchy–Schwarz and Σk≤q² give the final inequality. There is NO extra A,V,101,or 2^32 union multiplier on this already-global event. Separate state reservation obligations remain unchanged.

Source-U statistical binding, source authentication, concrete SHAKE, privacy, quantum work-model qualification and physical system gates are not supplied by this lemma.

Required source pointers: primitive direct_mask_vole.c FS encodings 515–590; commit 292/prove 1015/verify 1194 for duplicate H0; reconstruction 468–494; final mask 1277ff; vendor bavc.c 61ff leaf expansion and 202 actual tree tweak; universal_hashing.c 537ff leafhash. Keep the supplied exact universal-hash arithmetic and source references with these derived inequalities. No parameter increase, degree increase, envelope rewrite, or gate weakening follows.

## Boundary

This record is a reviewed conditional query-model proof input. It does not establish concrete efficient SHAKE security, privacy, PQ qualification, implementation correspondence, custody, deployment, production readiness, or activation.
