# Synthetic vectors

`synthetic-vectors-v1.json` contains 26 fictional request/bundle cases with manually specified aggregate outcome, bundle issues, fixed rule order, and missing-fact list. The bundle template omits only its self-referential `contentDigest`; `tests/helpers.py` applies the case mutation, canonicalizes the remaining bundle members, computes SHA-256, and then encodes the canonical test bytes.

The vectors exercise PASS, MISSING, HUMAN_CHECK, missing fact enumeration, inclusive/exclusive date and amount boundaries, source completeness/conflict/replay/freshness, scope mismatch, publication, expiry, withdrawal, real-use rejection, and changed rule version. Every bundle remains `UNAPPROVED_SYNTHETIC_FIXTURE`; the vectors are not an authority catalog.

Three architecture acceptance areas remain explicitly unexercised: package install/update, durable recovery, and rollback. This child intentionally has no installer, signature/revocation authority, persistence, or provider data source, so vectors cannot establish those behaviors. See `../docs/PRODUCTION_BACKLOG.md`.
