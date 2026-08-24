# Production configuration checklist

Status: nonactivating checklist; no production qualification is claimed.

1. From the checkout root, run `python -m tools.ops_authority` and
   `python -m tools.qualification_gate inspect`.
2. Run the existing release-manifest gate and source-inventory check at the reviewed commit.
3. Run the causal qualification, Queue, Composition, Longfellow, Mirror operational-owner and
   recovery/export tests, followed by the privacy-artifact scan.
4. Verify the exact release, verifier executable, schema/program, governance, source, custody, and
   receiver identities. No environment-root, deleted readiness module, or legacy compatibility
   sentinel is a production configuration.
5. Measure the complete native process tree on the pinned CPU-only laptop: resident memory must be
   at most the exact 5,000,000,000 decimal-byte cap, with no proving-attributable swap or
   pagefile growth; retain the raw resource evidence and cleanup result.
6. After evidence closes the six qualification blockers, rerun
   `python -m tools.qualification_gate require-production`. Only after all eight blockers close,
   the qualified pin is production-usable, and the receiver/connectors are approved, run
   `python -m tools.qualification_gate require-activation`.

The current inspect command is expected to pass coherently while both require commands fail closed.
Live credentials, source authorization, receiver endpoints, and state operations are supplied only
after the corresponding authority and external review gates close.
