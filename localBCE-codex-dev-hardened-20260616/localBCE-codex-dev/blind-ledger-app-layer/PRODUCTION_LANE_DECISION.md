# Production Lane Decision

Decision: native STARK settlement is the only supported production lane.

The package keeps local STARK and Cairo-native work, but production readiness
must remain closed until a real audited verifier artifact is supplied and the
artifact hash is pinned.

## Acceptance Criteria

- STARK-field commitments from app layer through settlement public inputs.
- Native verifier artifact hash pinned and validated.
- No legacy proof wrapper anchor.
- Governance, oracle/source, key custody, data availability, monitoring, and
  launch blocker manifests validated.
- All buildable tests pass.
