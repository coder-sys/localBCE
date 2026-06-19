# Native STARK Redeploy Workflow

Deploy only after:

- verifier source hashes match the verifier pin manifest,
- the public input schema is frozen and reviewed,
- governance addresses and timelock are validated,
- oracle/source manifests are ratified,
- key custody and rotation procedures are signed off,
- operational readiness validation passes with non-placeholder values.

After any verifier or public-input change, update the verifier pin manifest,
rerun operational validation, rerun the buildable checks, and rebuild the clean
release zip. There is no packaged test-verifier deployment path.
