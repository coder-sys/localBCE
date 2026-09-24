# Provider App production and integration backlog

This list records dependencies that this synthetic child cannot decide or
prove. Completing the local vectors does not close any production item.

1. **Issuer authority and rule rights.** Name each real rule issuer; obtain
   permission to use and distribute each artifact; define a verifiable
   publication, signature, version, effective-date, expiry, supersession, and
   withdrawal contract. An issuer-owned rule bundle must fail closed on wrong
   digest, unknown key, revoked key, unsupported semantics, or stale authority.
2. **Provider and payer scope.** Select an adopting provider, payer/state
   program, approved use, exact local environment, permitted check scope, and
   responsibility for the final review. No such party or profile is selected
   by this child.
3. **Claim and source schemas.** Approve bounded versioned field schemas,
   code-system versions, units, date semantics, provenance, source identity,
   record/version references, correction lineage, completeness cutoffs,
   freshness policy, replay behavior, and outage behavior with actual owners.
   The invented enums in this child cannot be mapped to real clinical or
   payer policy by implication.
4. **Identity and local authorization.** Bind an authenticated provider
   principal, role, tenant, and revocation result from a provider-controlled
   identity system before reading claim data. Define local storage and API
   enforcement; caller-provided role or provider identifiers are not authority.
5. **Trusted time and rule verification.** Bind effective-date checks to a
   provider-approved clock; verify issuer signatures and publication rights
   before evaluation. Protect against clock rollback, expired catalogs, key
   revocation, and unsupported rollback packages.
6. **User workflow and ordinary submission.** Integrate with a selected local
   billing workflow, display the exact rule/source/software versions and
   uncertainty, and preserve provider review. Claims continue only through
   the provider's existing approved submission channel. The app cannot create
   a submission action or payer determination.
7. **Privacy, custody, and operations.** Complete provider-specific privacy,
   security, retention/deletion, access logging, key custody, local backup and
   restore, secure update, rollback, incident response, and support review.
   Prove that corporate support, analytics, telemetry, crash reports, and
   update traffic receive zero PHI and no persistent linkable claim
   fingerprint. No such route is implemented in this child.
8. **Lean compilation and semantic assurance.** The child now has a
   versioned bounded argument entrypoint and a Python adapter with Lean
   4.33.1 and source checks. The parser and semantics are split into smaller
   source units, but the new model split is source-only and uncompiled. The
   r5 guarded build stopped at the unchanged process cap after compiling
   only `Semantics`; no executable hash or differential tests exist for the
   current revision. The guarded executable build, hash pin, and tests must be
   recorded in `STATE.md` before claiming local agreement. Theorem/axiom review,
   independent kernel checking, a proof of parser-to-Lean normalization, and
   provider-profile resource evidence remain open.
9. **Independent reconstruction.** The original vector suite checks the
   independent checker against all 26 canonical Python results. The new Lean
   adapter also requires an empty checker diff before comparing the modeled
   result projection. Guarded Lean vector and negative-case evidence must be
   recorded in `STATE.md`; broader mutation cases for bundle digest,
   effective interval, scope, and withdrawal still require their own
   authorized fixtures and review.
10. **Bounded full-path profile.** Select and measure the actual provider
    profile, including parsing, local source reads, evaluation, independent
    check, optional provider-owned retention, startup, update, rollback, and
    recovery. Current byte/count limits are synthetic adapter bounds, not an
    SLA or capacity claim.
11. **Independent acceptance and adoption.** Obtain provider security/privacy
    and operational acceptance, independent assurance, contractual support
    terms, commercial terms, and an adoption decision for the exact release.
    Adoption remains a separate gate from the first government service.

No item above can be marked complete using synthetic vectors alone.
