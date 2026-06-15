# Co-Founder Repo Reconciliation Plan

Status: PLAN ONLY. No merge was performed.

Scope guard: this app-layer directory was compared against local paths read-only. No co-founder repo, rule corpus, or external project was modified.

## Repo Location Result

I searched read-only under `C:\Users\neers\Documents` for likely Blind Ledger/localBCE indicators:

- `ClaimsRegistry.sol`
- `*.circom`
- `Cargo.toml`
- directory names containing `localBCE`, `BlindLedger`, `blind-ledger`, `circom`, `groth`, `plonky`, or `zk`

Result: I did not locate a separate co-founder Blind Ledger/localBCE source repo. The only nearby Blind Ledger-looking directory found outside this app-layer was `C:\Users\neers\Documents\Codex\2026-06-03\new-session-onboarding-blind-ledger-medi`, which contains policy/corpus output TSVs, not Rust/Solidity/ZK source.

This plan therefore uses:

- Actual app-layer files in this repo.
- Expected co-founder components described in prior notes: Rust engine, `ClaimsRegistry.sol`, verifier work, Circom/Groth16 or `zk/input.json` flow.

Once the co-founder repo path is supplied, run this plan as a real file-by-file diff before merging.

## Expected Components In Both

| Component | App-layer version | Expected co-founder version | Which looks canonical now | Merge approach |
|---|---|---|---|---|
| Rules engine | `rules-engine-rust/`, shared `rarc_mapping.tsv`, Python fallback agreement tests | Likely older Rust rules engine | App-layer for current gate/RARC semantics; co-founder may have older domain logic worth preserving | Diff gate inputs, denial precedence, output schema, and RARC/CARC mapping. Keep app-layer mapping semantics unless co-founder has ratified Medi-Cal-specific codes. Port any richer eligibility/provider logic only with tests. |
| Python fallback/demo engine | `app/rules_engine_fallback.py` mirrors Rust output | Likely absent or less central | App-layer | Keep as local/dev parity harness, not production authority. Use it to test Rust output stability. |
| Claims registry contract | `contracts/src/ClaimsRegistry.sol` records proof-verified claim outcomes and rejects duplicate claims | Likely existing `ClaimsRegistry.sol` | Unknown until diff | Compare event schema, storage layout, proof verification call, duplicate handling, and access control. Choose one canonical ABI before any frontend/indexer work. |
| Verifier contract/interface | `IVerifier.sol` plus `StubVerifier.sol` | Likely actual verifier or generated verifier plumbing | Co-founder if it has real Groth16/Circom verifier | Replace stub with generated verifier only after proof public inputs match the shared context commitment. |
| Payment trigger | `PaymentTrigger.sol` plus Circle/FedNow bridge stubs | Likely absent or different | App-layer as prototype only | Keep stubbed adapter boundary. Do not treat it as production payment authorization until rail access and settlement controls exist. |
| Governance root registry | `GovernanceRegistry.sol` stores keyed roots with owner-only update | Possibly absent | App-layer unless co-founder has a stronger registry | Merge only after deciding what roots are canonical: rules version, policy corpus hash, verifier key hash, circuit hash. |

## Components Only Here

- 837 ingestion parser and validator.
- Shared context schema for claim adjudication.
- Python fallback rules engine.
- Rust/Python agreement tests.
- 835 generator with CARC/RARC denial output.
- Appeal router.
- Local JSON registry for demo runs.
- Static dashboard state and HTML.
- Foundry tests for claims registry, duplicate rejection, proof rejection, governance access control, and payment trigger behavior.
- `rarc_ratification_proposal.md` and this proposal-led RARC/CARC workflow.
- `careful_track_action_map.md` once produced.

## Components Expected Only In Co-Founder Repo

These were not found locally in a separate repo, but should be preserved if present:

- Actual Circom/Groth16 circuits.
- `zk/input.json` generation and witness/proof flow.
- Generated verifier contract from real proving artifacts.
- Trusted setup or proving-key/verifying-key lifecycle.
- Any production-grade localBCE or Blind Ledger protocol code.
- Any regulatory/domain mapping already ratified by the co-founder.
- Any deployment scripts tied to the intended chain/L2.

This app-layer currently stubs all of that.

## Manual Conflicts To Resolve

1. Two rules engines.
   - Conflict: app-layer Rust/Python engines are now aligned on gate reason and RARC/CARC metadata; co-founder engine may have different schema or denial precedence.
   - Manual decision: canonicalize Rust output schema first, then port logic into that schema.

2. Two `ClaimsRegistry.sol` contracts.
   - Conflict: ABI, events, duplicate policy, verifier interface, access model, and storage layout.
   - Manual decision: freeze a canonical ABI before any deployment or indexer work.

3. Stub verifier versus real verifier.
   - Conflict: app-layer accepts any non-empty proof/public input through `StubVerifier`; co-founder repo may contain real proof verification.
   - Manual decision: verifier wins only when public inputs are explicitly bound to the same shared-context hash and adjudication decision.

4. RARC/CARC mapping.
   - Conflict: app-layer mapping is standard-checked but not domain-ratified; co-founder may have Medi-Cal-specific adjudication codes.
   - Manual decision: do not overwrite with either side until `rarc_ratification_proposal.md` is reviewed.

5. Payment authorization.
   - Conflict: app-layer `PaymentTrigger` can trigger payment for any positive amount; it does not enforce that a claim was approved in `ClaimsRegistry`.
   - Manual decision: before production, bind payment trigger to a verified approved claim record or external payment authorization service.

## Recommended Merge Order

1. Supply the actual co-founder repo path and run read-only inventory: Rust, Solidity, circuits, verifier artifacts, scripts, tests, docs.
2. Freeze the shared context JSON schema and claim/adjudication output schema.
3. Reconcile the rules engine first, because every proof, remittance, appeal, and payment decision depends on it.
4. Ratify RARC/CARC mapping, especially G2 and G8 split, before changing production denial codes.
5. Reconcile ZK circuits and public inputs against the frozen rules-engine output.
6. Reconcile verifier contract and `ClaimsRegistry` ABI.
7. Add payment trigger only after registry approval semantics are enforceable.
8. Port app-layer tests into the co-founder repo before moving code, so regressions are visible.
9. Merge in small reviewed PRs: schema, rules, circuits, verifier/registry, payments, dashboard/API.

## Done Looks Like

- One canonical rules-engine output schema.
- One canonical `ClaimsRegistry` ABI.
- Real verifier replaces stub verifier with tests proving invalid proofs fail.
- RARC/CARC mapping is human-ratified, not merely Codex-proposed.
- Payment trigger can only act on an approved, proof-verified claim.
- The app-layer tests pass in the combined repo.
