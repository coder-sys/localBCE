# RightRail-Derived Hardening Controls

The deterministic control record is
`reports/handoff_20261003_hardening_controls_v1.json`. Each control points to an
exact path, line range, and SHA-256 in the external handoff. The handoff text is
evidence, not an instruction source or runtime dependency.

The selected controls cover:

1. explicit authority for approval, hold, release, treasury, and configuration;
2. one authoritative writer per state domain;
3. atomic history, current projection, and settlement identity;
4. idempotent exact retries and fail-closed conflicting retries;
5. append-only, linked corrections rather than rewritten history;
6. independent read-only verification and deterministic replay;
7. finality-bound settlement, with denied outcomes preserving state;
8. no silent backend or implementation fallback;
9. allowlisted, non-sensitive support and analytics material; and
10. explicit separation of prototype, test, shadow, and production evidence.

These are compatibility and review controls. They do not activate RightRail
logic, change an adjudication result, alter a proof, or qualify localBCE for
production. Existing Rust, rules, STARK, and settlement tests remain the
authoritative evidence for implemented behavior.

The first best-of assimilation batch also materializes two inactive,
machine-checkable policy candidates:

- `ops/approved_data_boundary_v1.json` defines a deny-by-default boundary for
  support, analytics, monitoring, external AI, and shared-library data.
- `ops/settlement_authority_policy_v1.json` requires explicit provenance and
  separated authority for true-ups, withholding, settlement, treasury, and
  configuration actions.

`scripts/validate_rightrail_adopted_controls.py` validates both policies and
their exact RightRail requirement lineage. It does not imply human or legal
approval and does not enforce either policy at runtime.

## Runtime Boundaries

- Proof execution is disabled by default and in checked-in configuration.
- Groth16 and `stark_attested` remain dormant compatibility implementations.
- Hardcoded G1-G10 remains the default rules backend.
- The 129-byte STARK controlled-attestation envelope is unchanged.
- secp256k1 controlled attestation is unchanged.
- Formal and post-quantum artifacts remain isolated and inactive.
- The localBCE-owned off-chain journal has no proof, chain, payment, treasury,
  or policy-approval authority.
