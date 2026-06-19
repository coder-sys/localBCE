# Monitoring And Audit Events

Status: planning scaffold. The active repo does not yet include production
monitoring automation.

## Minimum Future Alerts

- Any failed production readiness check is critical.
- Any verifier artifact hash change is critical.
- Any settlement with payment greater than approved amount must page.
- Any stale nullifier root submission must page.
- Any rule ratification failure must block executable rule export.
- Any root approval or governance role change must create an audit ticket.

## Active Prototype Events To Watch

- Rust adjudication failures.
- Groth16 proof generation failures.
- On-chain submission failures.
- Missing or unexpected transaction hashes.
- Duplicate claim rejections.
- Deployment JSON generation failures.

## Retention Targets

- Contract events: retain for the full compliance period.
- Rules extraction logs: retain source URL, content hash, extractor notes, and
  review status.
- Key rotations: retain old/new roots, proposal id, signer set, and activation
  time.
- STARK planning artifacts: retain bridge input, witness plan, compatibility
  report, and gap plan for audit review when generated.

