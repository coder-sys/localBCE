# Careful-Track Action Map

Status: planning document. These items are not one-shot Codex tasks.

## Sources

- NIST FIPS 204 ML-DSA final standard: https://csrc.nist.gov/pubs/fips/204/final
- IETF draft, ML-DSA security considerations: https://www.ietf.org/archive/id/draft-connolly-cfrg-ml-dsa-security-considerations-02.html
- RustSec advisory for `libcrux-ml-dsa` AVX2 signature-verification issue: https://rustsec.org/advisories/RUSTSEC-2026-0125.html
- Symbolic Software write-up on platform-dependent libcrux cryptographic failures: https://symbolic.software/blog/2026-02-05-cryspen/
- Ethrex L1/L2 overview: https://github.com/lambdaclass/ethrex
- Federal Reserve FedNow participant/service-provider list: https://www.frbservices.org/financial-services/fednow/organizations
- Federal Reserve FedNow about page: https://www.federalreserve.gov/paymentsystems/fednow_about.htm
- Circle developer resources: https://www.circle.com/developer

## Action Map

| Item | What it needs | Owner | Why it is not a one-shot Codex run | Done looks like |
|---|---|---|---|---|
| G2 and G8 RARC/CARC ratification | Human review of `rarc_ratification_proposal.md`, especially whether G2 inactive eligibility uses `27/N30` in all Medi-Cal cases and whether G8 must split invalid charge from excessive charge. | Co-founder plus billing-domain reviewer. | Codex can map generic X12 codes, but only a billing/domain human can decide Medi-Cal/DHCS remittance policy and operational acceptability. | Signed decision on each gate, explicit G8 keep-vs-split decision, and approved changes to `rarc_mapping.tsv` in a later run. |
| ZK circuits: Plonky3/Circom | Circuit design for the frozen adjudication schema, public input binding, witness generation, prover/verifier integration, generated verifier contract, and reproducible test vectors. | Co-founder for protocol design; Codex can draft circuit code; external auditor for review. | Codex can write circuit code, but cannot by itself prove the circuit is sound or confirm the encoded rules match Medi-Cal law. | Circuit proves exactly the approved rule decision, public inputs bind claim/context hash and result, invalid witnesses fail, generated verifier passes chain tests, and independent review signs off. |
| AI-assisted formal verification pipeline | Formal properties: no forged proofs, public inputs cannot be swapped, denial/approval result is bound to the witness, verifier key matches the circuit, and proof system assumptions are documented. | Co-founder plus external formal-methods/security auditor. | Formal verification is a separate assurance layer. It checks proof-system soundness and implementation properties, not whether the healthcare policy itself is legally right. | Property list, machine-checkable artifacts where practical, adversarial test suite, auditor notes, and versioned proof/circuit hashes in governance roots. |
| Regulatory-spec review for rules | Compare each encoded gate to Medi-Cal/DHCS policy, provider manuals, eligibility rules, authorization policy, billing rules, and appeal/remittance requirements. | Billing-domain reviewer, co-founder, and Neer for product decisioning. | This is legal/regulatory interpretation and product risk acceptance. Codex can summarize and trace rules, but cannot give final legal or operational sign-off. | Rule-to-policy trace matrix, open-policy exceptions, signed acceptance, and documented effective dates. |
| Real L2 operation with ethrex | Infra plan for running L2 nodes, sequencing/proposing, proof generation, posting data/proofs to L1, monitoring, key management, upgrades, and incident response. | Infra/devops owner, with co-founder protocol oversight. | Running a rollup is an operations program, not just code. Ethrex supports L1 execution-client and L2 rollup modes, but production use needs uptime, monitoring, settlement, keys, and chain governance. | Testnet environment, runbooks, node health dashboards, L1 settlement proof, key custody plan, rollback plan, and cost model. |
| Circle bridge | Business account/API access, compliance review, custody model, funds-flow design, sandbox-to-production promotion, reconciliation, and legal/commercial terms. | Partnership/compliance owner plus Neer. | Circle integration code is straightforward after access exists; the blocking work is access, terms, compliance, custody, and financial controls. | Circle access approved, sandbox tested, production credentials controlled, payment limits and reconciliation in place, legal/compliance approval recorded. |
| FedNow bridge | Relationship with participating financial institution or certified service provider, ISO 20022 message flow, onboarding, certification/testing, settlement and liquidity procedures. | Partnership/compliance owner; bank/service-provider partner. | FedNow is available through eligible depository institutions and service providers. Non-bank app code cannot simply call FedNow without authorized access. | Partner selected, agreements signed, certification path accepted, ISO 20022 messages tested, 24x7 operational support model approved. |
| PQ migration: BabyJubJub to PQ scheme | Cryptographic redesign: choose signature/KEM scheme, define hybrid vs solo PQ posture, update keys, circuits/contracts if signatures are verified in-circuit/on-chain, migration plan, test vectors, and audited implementation. | Co-founder cryptography owner plus external cryptographic auditor. | This is brittle cryptography. NIST standardized ML-DSA in FIPS 204, but implementation bugs remain real: RustSec reports a libcrux ML-DSA AVX2 verifier bug accepting crafted invalid signatures, and Symbolic Software documented platform-dependent libcrux outputs affecting ML-DSA signatures. | Threat model, selected scheme, hybrid fallback decision, audited library choice, cross-platform tests, key migration plan, circuit/contract updates, and staged rollout. |

## Recommended Sequence

1. Freeze schema and current prototype behavior with tests.
2. Ratify RARC/CARC before changing remittance behavior.
3. Decide G8 split before circuit finalization, because split gates change the proof statement.
4. Build ZK circuits against the frozen, ratified rule schema.
5. Run formal/security review of circuits and verifier.
6. Run regulatory-spec review of encoded policy.
7. Stand up L2/devnet operations separately from the app code.
8. Secure Circle/FedNow access through partnership/compliance work.
9. Treat PQ migration as a cryptography project with external review, not an implementation sprint.

## Non-Negotiable Gates

- No production payment trigger without proof-verified approval and payment authorization.
- No production denial-code changes without domain ratification.
- No production ZK verifier without invalid-proof tests and independent review.
- No production PQ migration without cross-platform tests and external crypto review.
