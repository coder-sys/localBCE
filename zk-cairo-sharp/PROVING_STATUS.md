# Cairo proving status

The Cairo implementation is retained as historical semantic and differential evidence. It is not the selected BL-PQ512 production proof backend and cannot authorize a database transition.

Current architecture uses the native Rust candidate verifier followed by an atomic database state transition. No L2 or Solidity settlement boundary is required.

Open before production:

- select and independently audit the exact proof suite;
- qualify the native verifier and parser;
- qualify production database atomicity, recovery, and anti-rollback;
- qualify HSM/FIPS custody and signer rotation;
- retain fixed-shape privacy and the exact V2 statement;
- keep `production_usable=false` until separate activation.
