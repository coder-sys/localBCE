# Historical evidence

Superseded architecture narratives were removed from the live documentation set on 2026-08-14.
The active-core deletion pass on 2026-08-15 also removed 21 unreferenced compatibility markers.
Git history and retained source archives preserve their exact bytes.

Legacy filenames that are still imported or asserted by regression code contain a short retirement
marker. Those markers are compatibility aids only; they are not architecture, security, execution,
or release authority.

The removed 2026-08-15 marker group covered the unused binary-field handoff/proving notes,
BL-PQ512 A12/build/hash-pad/S09/throughput notes, decisive-composition and old proving/privacy
notes, dated handoff/phase logs, old production-candidate and backend-decision markers, and the
Wave 1A/Wave 2/Wave 4 narrative markers. No current source, test, manifest, or protected boundary
consumed those paths. Referenced markers remain only until their owning legacy regression lane is
replaced and deleted; they are not current authority.

Use `ARCHITECTURE.md`, `docs/NATIVE_V3_ARCHITECTURE.md`,
`docs/DATABASE_ZK_ARCHITECTURE.md`, `STATE.md`, and `CURRENT_TASK.md` for the current system.

The root `WAVE2_HANDOFF_2026-07-26.md` checkpoint was superseded by those current authority
records and retired from the live source baseline. Its exact 12,916-byte UTF-8 blob remains
recoverable in Git commit `20c409b6f546085120542e294e1868e878c56cf8` (SHA-256
`5a4de0ca15f5ce75b5dc3f6cff47d81f976c00cc9b20fb279a2d7212ade9f572`). It is intentionally
excluded from the current release manifest and must not be treated as current authority.
