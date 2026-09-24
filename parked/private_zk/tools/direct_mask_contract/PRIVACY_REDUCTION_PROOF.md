# Complete direct-mask privacy reduction proof record

Driver architecture result: direct-mask privacy reduction, scoped to the actual pinned NIZK implementation. Incorporate the theorem and exact counters into the already authorized tools/direct_mask_contract/** ledger/contract phase. This is an input to that phase, not permission to set any qualification/activation flag or to invent a resource profile. Keep your exact p_good work and real wire-count correction moving; no extra broad research or heavy tests.

Verified read-only inputs: primitive 392e53e2b3d5936cb9cb2681b9e2d803143b1e17/tree 34dc614591712efd4faca0dedc064bfd63e51a92, Native circuit 0bce17b884f0076f078026645bef8302b5ed1a53/tree 0a0872d3e7ae5aefa6742921909f70b49e58566f; actual ℓ=125048, m=172232, n=ℓ+1536=126584 bit rows, row_bytes 15823, stream AES blocks 989. Wire x 1147, ν 96, m1 506416, m2 15887, m3 96, m4 10496, complete frame 534370. Product authority now clean 98a3d9ea7f156653633996170c17236db804eed7/tree 3d8d555397b86384d57fe7db8f530134026eb037; root checked its only changes from 8e820728 are STATE/CURRENT recording existing whole-suite evidence. Named technical/execution authorities unchanged.

## CLAIM AND GAME

This is adaptive multi-theorem NIZK privacy for classical, completed honest-prover requests and a quantum adversary's global random-oracle access. All honest requested pairs (x,w) satisfy the fixed relation; the simulator is given only x and the public context. A request includes every fresh BAVC commitment that later aborts. No witness/seed is reused across new proof requests. Only final proof or the prescribed abort is externally returned; timing, partial-memory/crash/recovery leakage and hostile reset of an in-progress prover are separately unqualified operational properties. Fixed public parsing errors may be returned identically. No interactive malicious-verifier theorem is silently being claimed.

Use a common 2112-bit ideal random oracle with disjoint typed inputs and output projections: H0 768, H1 512, FS1 2112, FS2 832, FS3 256. This is the same actual active-domain mapping used by the local-certificate proof. Unused suffix bits are sampled independently when programming a shorter projection.

## COUNTERS

A=all fresh honest prover invocations admitted to this proof experiment (including aborts); M≤A=fresh BAVC commitment instances actually generated. V=all ordinary verification invocations and Q=all adversarial QRO queries. R=TOTAL FS3 candidate hash calls, including the first candidate, rejected candidates, and candidates before a later abort; R is not just retries beyond the first. P≤2A+R is the number of FS reprogramming events. S=distinct fresh source commitments/root expansions; an unchanged source assertion does not increment S. An exact byte-identical retransmission itself increments none of A, M, or S, but any cryptographic operation it triggers is charged separately, including V when it is verified. Never refund a consumed event.

## STEP 1: APPLY ADAPTIVE REPROGRAMMING IN THE CAUSAL HONEST GAME

Before each honest FS1, FS2, or FS3 call, its full prefix/message is already fixed. The implementation then obtains a fresh independent 512-bit nonce. Therefore the input distribution at that exact point has pmax≤2^-512, even conditional on the entire prior history. Replace the ordinary oracle value at that sampled input by a new independent uniform answer. With qhat_r the cumulative number of ALL oracle queries before event r, charge

ε_AR ≤ min(1, Σ_(r=1..P) [sqrt(qhat_r*2^-512)+(qhat_r*2^-512)/2]).

A common conservative cap is qhist=Q+38A+39V+R (literal calls), giving

ε_AR ≤ min(1, P*[sqrt(qhist/2^512)+qhist/(2*2^512)]).

Use the exact GHHM Theorem 2.1 (Tight adaptive reprogramming in the QROM, https://arxiv.org/html/2010.15103). Its point is sampled BEFORE its fresh programmed value. We are applying it here, before the backward simulator change of variables, and do not claim that nonce entropy licenses programming an arbitrary value-dependent point.

The programmed game now has independent random γ1, γ2 and each candidate γ3. Grinding/decoder/Topen acceptance depends only on γ3's indices, not seeds or witness. Pre-sample these independent challenges and select the first candidate whose exact deterministic gate passes; preserve the same cap and abort event. Retain all programming operations, including failed candidates. If a nonce/input repeats, apply the same chronological overwrite semantics as the reprogramming game; do not pretend two different values remain simultaneously stored at one input. The AR charge covers the difference from the real fixed oracle. Actual-runtime availability still uses your fixed-oracle nonce-collision correction, not an unqualified geometric equality.

## STEP 2: FORWARD BIT-VOLE HIDING HYBRIDS

Define α_s(T,Qro) as the maximum quantum AES-256 PRP distinguishing advantage for running time at most T, at most s DISTINCT CLASSICAL input blocks to one hidden independent random-key challenge oracle, and at most Qro queries to an independent public QRO. The distinguisher may compute public AES circuits and make quantum computations; it does NOT receive superposition access to the hidden-key challenge AES oracle. This is a Q1 game, not Q2. Public IV/tweaks and adaptive, classically chosen distinct inputs are allowed. α_s is monotone in the cap s.

For the chosen 33 hidden leaves in the actual 6400-leaf heap, the union of hidden internal paths has at most

1+33*ceil(log2(6400)-1)=397

nodes. Replace the 4 AES-block expansion at each such node with independent children, in ancestor order. Previously replaced ancestor outputs make each challenged hidden key independent uniform; the key itself is never in the disclosed frontier. Unmarked subtrees keep real AES expansion.

Next replace each hidden leaf's non-EM expansion and then its long stream. The leaf expansion has 8 actual AES blocks; the conservative declared leaf budget 8*max(N_i)=2048 bounds it. Its joint output (sd,tail) is uniform, so the invertible transformation

(sd,tail) -> (sd, ν*iota(sd)+tail)

makes (sd,com) independent uniform even conditional on the public ν. The hidden stream has ceil(15823/16)=989 AES blocks. This gives at most 33 leaf hybrids and 33 stream hybrids.

PRP-to-independent-random-block switching costs at most choose(s,2)/2^128 per challenge-key hybrid, because the hidden-key oracle is queried classically. Thus the conservative direct-mask bit-hiding bound is

ε_bitMH ≤ M * [397 α_4(T*,Q*) + 33 α_2048(T*,Q*) + 33 α_989(T*,Q*)
                 + 85,297,284/2^128],

where

397*choose(4,2)+33*choose(2048,2)+33*choose(989,2)=85,297,284.

This is a conservative budget calculation, not a claim that the actual hidden leaf performs 2048 blocks. No second factor 2 is required: the simulator is DEFINED at this endpoint; we do not return through a second sequence of hybrids to an honest-seeded BAVC distribution.

An explicit witness-free way to sample that endpoint is to mark the hidden-path union, sample independent children at marked internal nodes, expand every unmarked subtree with actual AES, sample hidden (sd,com) and hidden long streams independently, and compute the usual H1 vectors/outer commitment using public ν. Disclose precisely the actual canonical frontier and hidden commitments for the chosen opening. Never invoke H5 or invent a separate high-mask hash. All fixed Topen/decoder/padding checks remain.

## STEP 3: EXACT SIX-MASK CHANGE OF VARIABLES

In that endpoint, for each tree the one hidden long stream is an independent uniform n-bit string. Its XOR with all known streams makes u_i uniform. Hence the transformation from all u_i to

u=u_0, c_i=u_0+u_i (i=1..32)

is bijective. The c_i can be sampled uniformly first; given opening, c_i, and Δ, actual reconstruction fixes q independently of u. Ordinary rows obey q=v+Δu, and packing preserves qbar_j=vbar_j+Δ*ubar_j. All six ubar_j are independent uniform elements of K=GF(2^256), since they come from disjoint 256-bit slices of uniform u. This does not assert q itself is uniform in K or ignore the 248-dimensional W_CRT image.

For a fixed true (x,w), choose d_w=w+u_w. Given q,d_w,Δ and γ1,γ2, let k0,k1,k2 be the relation's unmasked hashed homogenized coefficients. They do not depend on the six extra ubar masks. The actual three masked coefficients satisfy

a2=k2+ubar1,
a1=k1+ubar0+qbar1+Δ*ubar1,
a0=k0+qbar0+Δ*ubar0.

The map (ubar0,ubar1)->(a1,a2) is triangular with unit diagonal, for EVERY Δ including 0. It therefore produces independent uniform a1,a2. Each of the remaining four ubar masks enters exactly one tilde_u coordinate with coefficient 1; the actual VH formula is

VH_i(rows,masks)=r_i*y0+y_(i+1)+masks_(i+2).

Consequently the joint map from all six ubar masks to (a1,a2,tilde_u[4]) is block triangular/invertible. d_w, a1, a2, and all four tilde_u coordinates are jointly uniform conditional on the fixed public/reconstruction data. This is the full joint claim, not six marginal claims and not uniformity of tilde_u conditioned on D.

The simulator samples d_w, a1,a2,tilde_u uniformly. It reconstructs q and packed qbar from its real-shaped opening and c_i, sets

D=VH_γ1(q,qbar)+Δ*tilde_u,
q'=q+Δ*d_w,
B=the actual verifier relation hash at (x,q',Δ,γ2)+qbar0+Δ*qbar1,
a0=B+a1*Δ+a2*Δ^2.

It serializes the actual m2=(tilde_u[4],D[4],d_w), m3=(a0,a1,a2), and m4 opening. Truth of (x,w) makes the cubic coefficient zero, so this a0 is EXACTLY the honest masked a0 under the inverse variable map. No witness, extraction, discrete log, seed inversion, or division by Δ is needed. The simulator is also mechanically defined for any well-formed x, a fact useful for the source-commitment hybrids below.

FS inputs/nonces are the exact ones rebuilt from these messages. The equality is a change of variables in the ENTIRE already-programmed joint game, including its oracle-programming history and every failed candidate. We do not apply GHHM anew to this backward construction.

## STEP 4: SOURCE HIDING, IN THE CORRECT ORDER

First replace each real proof by the above simulator, while the real statement is true. Now its output requires only x. Only after this replacement, change the source commitment generation:

G0(r)=AES256_r(LE128(0)) || ... || AES256_r(LE128(7)) -> (K,Z),
T=U*iota(K)+Z,
Pad=G1(K)=AES256_K(LE128(2^127+j)), j=0..49,
C=V xor Pad.

Replace the whole G0 output by uniform (K,Z), then G1 by uniform blocks. K is independent uniform before the G1 game. The source's public (T,C) becomes independent uniform for any fixed well-formed public U and every V. Charge

ε_source ≤ S*[α_8(T*,Q*)+α_50(T*,Q*)+1253/2^128],

1253=choose(8,2)+choose(50,2).

Reproofs of one immutable source commitment do not cause new source replacements. Signatures and later processing depending only on public x and independent authority randomness are postprocessing; their AUTHENTICATION security and custody stay separate. No unrelated dual-commitment, signature-as-truth, or fresh-root-per-FS-retry claim is introduced.

## RESOURCE PARAMETERS, NOT AN INVENTED NUMERIC PROFILE

Each PRP hybrid reduction simulates one whole counted history and embeds ONE challenged key expansion. The coefficients 397/33/33/S count hybrids; they must not multiply each individual reduction's whole-history runtime a second time.

Use Q*≤2*qhist for a straightforward coherent overlay of at most P programmed entries on a read-only base QRO: compute the base answer, select a matching fixed input's programmed answer, then uncompute the base answer. The comparison work is O(P*L_FS) per oracle call, where L_FS is the exact maximum serialized FS-input BIT length of this fixed grammar, not frame bytes.

The simulation is efficient with no witness enumeration. Its concrete work declaration must include:

6,406,396*A AES blocks as a commit-generation upper bound,
6,373,495*V AES blocks as a reconstruction upper bound,
58*S source AES blocks,
actual fixed circuit coefficient/evaluation work,
actual linear VH/ZK hash and bit transpose/packing work,
up to R bounded canonical opening checks,
qhist exact-length SHAKE queries,
and the reversible programmed-input lookup/copy overhead.

The block counts derive from

4*(6400-1)+(8+989)*6400=6,406,396,
4*(6400-1)+(8+989)*(6400-33)=6,373,495.

A concrete T* is T_adversary plus the worst-case cost of those pinned routines and the explicit oracle-overlay algorithm for the declared (A,M,V,R,S,Q,P). Retain the subroutine cost model and primitive-advantage inputs symbolically until an actual work model is supplied; do not label measured CPU seconds or unspecified polynomial overhead as a quantum-gate bound. Numeric T*, concrete α_s values, and an actual SHAKE indistinguishability/reduction bound remain unqualified inputs.

## FINAL COMPOSITION

ε_priv ≤ min(1, ε_coins + ε_AR + ε_bitMH + ε_source + Adv_SHAKE_priv).

ε_coins is the actual joint RNG/custody deviation from fresh independent ideal randomness, never automatically 0. Adv_SHAKE_priv is an explicitly scoped concrete-SHAKE replacement assumption for the entire counted experiment; the ideal-QROM theorem does not prove it. Operational side-channel/destruction qualifications are additional gates, not consequences of this equation.

This closes the proposed simulator and explicit ideal-primitive reduction argument. It does NOT supply a numeric 128-bit product-security claim. Keep source parameter statistical binding, computational authenticity/soundness, privacy, availability, and operational qualification as their own ledgers. No extra 101 or 2^32 factor on the already global QROM event; keep the separately required 101-unit state reservation contract until a reviewed accounting change is implemented.

## Boundary

This record is a completed conditional privacy reduction for the pinned query model. It does not establish numeric 128-bit security, concrete SHAKE/AES advantages, a complete runtime/work declaration, PQ qualification, implementation correspondence, custody, deployment, production readiness, or activation.
