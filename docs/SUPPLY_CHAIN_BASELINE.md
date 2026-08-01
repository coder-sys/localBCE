# Blind Ledger supply-chain foundation baseline

Current proof-topology note (2026-07-22): the release candidate must pin and reconcile the semantic
STARK, shared-bus PCS, Boolean GKR circuit/compiler, masking/simulator, and atomic verifier defined
by `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. Existing S-two, Cairo, and RISC Zero pins are
historical/differential inputs and cannot serve as the final heterogeneous module identity.

Updated: 2026-07-19

Status: **Python dependency boundary qualified; wider S11 inventory remains incomplete and is not
release evidence.**

Under `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`, the remaining S11/O12 compiler, native, container,
license, SBOM, reproducibility, and release work is internal engineering. External auditors review
the completed release; they are not required to construct its dependency boundary.

The wider multi-language supply-chain baseline is incomplete and not release evidence.

The Wave 1A workspace now has a local Git root whose initial commit
`84468714eb486b12d1f196a2d1b7622266a6d194` contains exactly the 609 files and bytes from the sealed
R33 source manifest. The commit uses the local neutral identity `Codex Local Baseline
<codex-local@localhost>`, has no configured remote, and does not claim provenance before R33. An
older July 10 Blind Ledger repository was not attached because it tracked only 178 files and matched
only 72 current files byte-for-byte. This local baseline enables exact working-tree diff review; it
does not replace artifact hashes, upstream provenance, or release reproducibility evidence.

This baseline records only facts visible in the synthetic development workspace, including inputs
used by the selected `BL-PQ512-v1` target's reference and differential components. Unsealed R26
stage JSON records adding official `rustfmt` and `clippy` components to an already installed, exact
Windows nightly toolchain; it records no application-dependency upgrade, new lockfile resolution,
or manifest rewrite. R26 has no terminal manifest or terminal seal; R28 later requalified the
applicable current source/tooling boundary under its own terminal evidence. Unknown provenance and
licenses remain `NOASSERTION`; they are not inferred.

The accompanying machine-readable inventories are `docs/SBOM.foundation.spdx.json` and the
complete reviewed Python logical-package inventory `docs/SBOM.python.spdx.json`. Exact Python
platform artifact identities are governed by `requirements/locks/python-artifacts.lock.json`.

## Evidence rules

- A source pin is distinct from an observed installed version.
- A direct manifest pin is distinct from a complete transitive lock with artifact hashes.
- A lockfile checksum identifies the reviewed lockfile bytes, not every downloaded package artifact.
- A vendored tree hash or commit is recorded only when existing repository evidence supplies it.
- Reproducibility is not claimed until a clean offline build from reviewed inputs produces matching
  artifacts and independent readback succeeds.

## Recorded toolchains

The latest execution log records the following installed tools. These observations are not all
repository-enforced pins.

| Tool | Observed or build-selected version | Repository pin status |
| --- | --- | --- |
| Python | 3.14.4 | Enforced by the canonical Python artifact manifest and offline installer for CPython on Windows/Linux x86-64 |
| pip | Windows 26.0.1; Linux 25.1.1 | Exact per-platform installer versions enforced before package installation |
| Windows rustc/cargo | 1.96.0 | A test names this toolchain; no root rules-engine toolchain file |
| WSL rustc/cargo | 1.97.0 | Observed only; formatter differs from governed source |
| WSL nightly rustc | 1.90.0-nightly (2025-07-13) | S-two file requests `nightly-2025-07-14` |
| Scarb/Cairo | 2.18.0 | Observed; `cairo_execute` manifest range is `>=2.18.0` |
| Forge | 1.7.1 | Observed only |
| Solidity compiler | Foundry-configured and build-observed 0.8.24; standalone PATH `solc` 0.8.35 | 0.8.24 is pinned in both Foundry configurations; the unrelated PATH executable is not the accepted build input |
| Node | 24.16.0 | Observed only; no JavaScript package lock is present |

Unsealed R26 stage JSON reports use of the already installed `nightly-2025-07-14-x86_64-pc-windows-msvc` toolchain and the
owner-authorized official command `rustup component add` to install only `rustfmt` and `clippy` for
that exact toolchain. The resulting installed component inventory is `cargo`, `clippy`, `rust-std`,
`rustc`, and `rustfmt` for `x86_64-pc-windows-msvc`. Observed versions are Cargo
`1.90.0-nightly (eabb4cd92 2025-07-09)`, rustc `1.90.0-nightly (e9182f195 2025-07-13)`, Clippy
`0.1.90 (e9182f195b 2025-07-13)`, and rustfmt `1.8.0-nightly (e9182f195b 2025-07-13)`. Windows
S-two wrapper format, check, strict-Clippy, and test gates then passed. The final format gate is
package-scoped so it verifies the local wrapper without rewriting the pinned vendored upstream
tree; vendor bytes are checked separately by integrity hashes. R28 terminally requalified the
applicable state. This closes only the observed local tool-component gap; it does not close S11 or
constitute a reproducible-build qualification.

## Reviewed input hashes

These SHA-256 values were read from the current source bytes. They must be regenerated and compared
at each reviewed run; they are not immutable release pins by themselves.

| Input | SHA-256 | Boundary |
| --- | --- | --- |
| `requirements.txt` | `EDA95DF33668EC01F5E2510B7AA75FEB03A00F481F156D0A655D988D15BDC140` | Non-installable compatibility marker; old online-resolution path disabled |
| `requirements-dev.txt` | `A661109F7B40536E8E338C722E1F3D34B01711FE099618924016D86F70478FA3` | Non-installable compatibility marker; old online-resolution path disabled |
| `requirements/inputs/production.in` | `2050A155100500D97530DA85D2205EEDDD08FE5CA64702FE8AF12DB256A48902` | Four exact direct production declarations; not an installation input |
| `requirements/inputs/development.in` | `F33E88E3CFA20BDDEA42CCA8C32B862896EE8F5F006D556E194B90BB093C54B8` | Six exact direct development declarations; not an installation input |
| `requirements/locks/cp314-linux_x86_64-development.lock` | `8621000886C629D35D6B6F87952C344609114CC80ECF9F92A27B1335A3D80ABC` | 26 exact transitive packages; per-wheel pip SHA-256 hashes |
| `requirements/locks/cp314-linux_x86_64-production.lock` | `081C3FE192E59A51B63ECD8C727D0A33217319C74D1C661B31BAE522C16C7ED4` | 18 exact transitive packages; per-wheel pip SHA-256 hashes |
| `requirements/locks/cp314-win_amd64-development.lock` | `75890E1EA4529BCD9F64AA6B4EB1050ECAFAC333D7CFCCCB00DC5FB988E52729` | 26 exact transitive packages; per-wheel pip SHA-256 hashes |
| `requirements/locks/cp314-win_amd64-production.lock` | `02A78AF3E0AA561BBECE3EC9F564568E13150B2CEFF90A8B7198DB27DAF9DBC8` | 18 exact transitive packages; per-wheel pip SHA-256 hashes |
| `requirements/locks/python-artifacts.lock.json` | `877771819CAE97CA055C1654099CB1A4296DE3A93C517BFFEAB1843CCE75BB26` | Canonical platform manifest: filename, size, official URL, version, license, SHA-256, and SHA3-512 |
| `docs/SBOM.python.spdx.json` | `5B50546F69C55CCC65B869598BF5200A7F261DFBA5D5C92514801159820C7EB7` | SPDX 2.3 logical-package inventory reconciled to all 26 reviewed Python packages |
| `rules-engine-rust/Cargo.lock` | `41F3EA56CF81155CFFBF915A52DB129686EA62B497DC6057676079BEB7B43068` | Cargo registry versions/checksums captured by lock v4 |
| `app/batch/poseidon_helper/Cargo.lock` | `16361544525B678209E42802CB3D8B7AC0F682D54AA6AE2B98125377AD8AC8D0` | Cargo registry versions/checksums captured by lock v4 |
| `experiments/bl_pq512_crypto_core/Cargo.lock` | `F5FE2606A295772D25CAC08F16384C9138D93E0903AF822BA95CD4EB5398A433` | R32 isolated `no_std` Fp16/SHA3-512 substrate; exact `sha3=0.10.9` resolution |
| `experiments/stwo_batch_air/Cargo.lock` | `D8136C780F28D9503E979AA895DAEE51D63B293EE414E739AD1D6FFA660B402F` | Experimental S-two wrapper dependencies |
| `experiments/risc0_privacy_v2/Cargo.lock` | `2D4B81A46864741474432DE6C01FCE0AAA119E7D10F96B29788CB3C0A7C084A7` | RISC Zero experimental workspace resolution; not a production selection |
| `experiments/risc0_privacy_v2/methods/guest/Cargo.lock` | `F8B76FE443668B989FC71C2C310755CC5A79F8C14F292B92F44DEFFD4B1342C6` | Nested RISC Zero guest resolution; not a separate production selection |
| `experiments/stwo_batch_air/vendor/stwo-aeceb74/Cargo.lock` | `F245C0DFCB724F1D40DCACE6B3D58C8827F2D647C7CB22FA02A1026F985E62D5` | Vendored upstream S-two workspace resolution |
| `experiments/stwo_batch_air/vendor/stwo-aeceb74/ensure-verifier-no_std/Cargo.lock` | `7EFC72ECC6FAB4CF014AD5676200FAB10B7528CB75800C6EF2507C1EC184A342` | Vendored no-std verifier-check resolution |
| `zk-cairo-sharp/Scarb.lock` | `FF53F3FF8C739DFE844C38E2A72347AAEAAE257F27BCCDC2217938B60BD19588` | Root-package-only lock; dependency resolution is absent and the unbounded manifest dependency is not closed |
| Vendored S-two `LICENSE` | `6FC3AE0CC00EEAC4C08B33D060CE3725438DCDE152DC571E08F3D8E6F86B3B8F` | Existing provenance document identifies Apache-2.0 |

This is the complete current governed native-language source-lock inventory: eight `Cargo.lock` files and one
`Scarb.lock`, plus the four Python artifact locks and their canonical dual-hash
manifest above. Generated caches, build targets, rollback copies, wheelhouses, and release-tree
copies are not source locks and are deliberately excluded. Lock coverage does not make the wider
multi-language baseline a complete reproducible build.

## Reviewed Python dependency boundary

| Direct package | Declaration version | Locked transitive boundary |
| --- | --- | --- |
| `fastapi` | `0.136.3` | Included in both 18-package production locks and both 26-package development locks |
| `uvicorn` | `0.49.0` | Included in both production and development platform locks |
| `cryptography` | `49.0.0` | Exact reviewed Windows and Linux wheels bound by SHA-256 and SHA3-512 |
| `pqcrypto` | `0.4.0` | Exact reviewed Windows and Linux wheels bound by SHA-256 and SHA3-512 |
| `pytest` | `9.0.3` | Included only in both development platform locks |
| `httpx` | `0.28.1` | Included only in both development platform locks |

R30 closes validated finding `R25-C01` for the supported CPython 3.14.4 Windows x86-64 and Linux
x86-64/glibc >= 2.28 targets. The exact qualified 26-package development graph and 18-package
production subset were preserved without upgrades. All 52 platform artifact records reconcile to
official PyPI wheel metadata and local bytes; every artifact has independent SHA-256 and SHA3-512
identities. Fresh Windows and Linux virtual environments installed the development graph entirely
offline, passed `pip check`, matched the exact installed graph, and emitted create-only canonical
attestations. `tools.locked_python_dependencies` contains no acquisition code and fails before pip
on interpreter, platform, pip, manifest, lock, wheel set, wheel bytes, metadata, or environment
drift. `docs/PYTHON_DEPENDENCY_LOCKING.md` defines the review and rotation contract.

## Rust, Cairo, and proof components

| Component | Existing evidence | Open reproducibility issue |
| --- | --- | --- |
| Rules engine | Package `0.1.0`; Cargo lock v4; R34 requalified Windows Rust 1.96 format, locked/offline checks, strict Clippy, and 48 tests | No repository toolchain pin; manifest uses broad `serde` ranges |
| Poseidon helper | Package `0.1.0`; Cargo lock v4; `starknet-crypto 0.8.1` manifest entry; R28 requalified the known-answer test and exact differential | Compiler/toolchain not pinned locally; a local target hash is not reproducible-build evidence |
| BL-PQ512 crypto core | Package `0.1.0`; Rust 1.96.0 toolchain pin; lock v4; exact `sha3=0.10.9` with default features disabled; R35 passes format, locked/offline check, `no_default_features`/`no_std` check, strict Clippy over all targets, and 51 library tests plus zero-test binaries in the short run-owned target. Coverage includes OODS, scalar Circle-FRI, cross-domain SHA3-512 PCS, the Wave 1A dimension mirror, the cross-language K512 FRI schedule, direct Circle evaluation, canonical quotient split/mask, and independent SHA3-512 permutation/shape KATs. | Scalar branch-minimized theorem substrate only; no constant-time/SIMD qualification, complete application hash-port/interaction/AIR/prover/verifier integration, independent release build, complete transitive license reconciliation, or production module identity. The Windows 1.96 distribution lacks `rustdoc.exe`; the crate contains zero doctest fences. |
| S-two experiment | Repository provenance pins upstream commit `aeceb74c58184d7886ebd7f34a7453fee714ca40`, source tree `debdb3804a656654016896c4d292293fe07ccff3`, archive SHA-256 `AF979C0BA6F6D1F1BCFDF4AB8D6B444E83F65FC2C6471BF404CCE5B063C329E6`, and a local allocator patch; R34 requalified the owned wrapper's pinned-nightly format, locked/offline check, strict Clippy, 25 unit/binary tests, one allocator integration test, and zero-doctest compile without modifying the vendor | Local patch is not upstream or independently audited; one local binary is not reproducible-build evidence and this is not the future isolated ZK fork |
| RISC Zero experiment | Direct `risc0-zkvm` and `risc0-build` version `3.0.5`; Cargo lock v4; R34 requalified the 48-test model plus the fresh and hash-pinned exact differentials | One local artifact is not reproducible-build evidence; the toolchain file still says only `stable`, and the foundation SBOM does not yet reconcile every locked transitive package and license |
| Cairo statement | Package `0.1.0`; observed Scarb/Cairo 2.18.0; R34 requalified a fresh serialized format/build/10-declaration pass | `cairo_execute >=2.18.0` is unbounded and the packaged Scarb lock does not resolve it |
| Solidity tests | Foundry configuration pins `solc 0.8.24`; R34 used the 9,398,784-byte cached compiler with SHA-256 `580ee56b61bbcaad953117e1e4a0874d90e6af5cb4ce4359571d7da25f6620e9` and passed 23 tests offline | Forge executable is observed, not source-pinned |
| `forge-std` | App-layer documentation points to sibling vendored source and license files outside this run's authorized path | License, upstream commit, source-tree hash, and archive provenance are `NOASSERTION` until an authorized provenance check captures them |

The first attempt recorded in unsealed R26 stage JSON selected a fresh Poseidon-helper target beneath an overlong
workspace temporary path and failed during helper compilation, before any cross-language result was
compared. The first concurrent Scarb build also panicked in a generated target with ``prelude` is
not a core submodule``. After the owner explicitly authorized tooling repair, the run used an
existing verified run-owned Poseidon target and fresh serialized Scarb targets. The known-answer
test, exact differential, and final Cairo gates passed. No application source, manifest, lockfile,
dependency version, compiler version, or proof parameter changed as part of those recoveries.

## License inventory boundary

| Component | Declared or observed license | Evidence boundary |
| --- | --- | --- |
| Vendored S-two | Apache-2.0 | Vendored `LICENSE` and existing provenance document |
| RISC Zero experiment copy | Apache-2.0 | `experiments/risc0_privacy_v2/LICENSE` |
| Vendored `forge-std` | `NOASSERTION` in this foundation SBOM | The asserted sibling license files were outside the exact authorized workspace and were not independently read in this run |
| Portal fonts | SIL Open Font License 1.1 | `portal_shared/FONT_SOURCES.md`; individual font-file license payloads are not embedded |
| Blind Ledger application source | `NOASSERTION` | No top-level project license is present |
| Reviewed Python graph | MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, Apache-2.0 OR BSD-2-Clause, Apache-2.0 OR BSD-3-Clause, MPL-2.0, and PSF-2.0 as applicable | Reconciled from exact reviewed wheel METADATA for all 26 logical packages in `docs/SBOM.python.spdx.json`; legal conclusions remain `NOASSERTION` |
| Remaining Cargo packages | `NOASSERTION` in this foundation SBOM | License metadata remains unresolved outside the Python closure |

## Reproducible-build input checklist

S11 remains open until a reviewed baseline pins or explicitly inventories:

1. exact source manifest and source hash;
2. exact compiler, linker, standard library, target triple, and build flags for every language;
3. continued requalification of the completed Python locks on every supported platform whenever any governed input rotates;
4. every Cargo and Scarb resolution without generating or changing locks during qualification;
5. Foundry and Forge upstream/build identity, not only the Solidity compiler;
6. vendored dependency commits, source trees, local patches, licenses, and complete tree hashes;
7. the semantic-STARK sibling commit plus the shared-bus/GKR compiler and reviewed patch series;
8. verifier source, binary, schema, suite, and full-width artifact identity;
9. operating-system/container image and native library identities needed for deterministic output;
10. an SPDX or CycloneDX SBOM generated deterministically and reconciled against all manifests;
11. clean offline rebuilds into unique out-of-source directories;
12. artifact readback hashes and an exact release allowlist.

## Current SBOM limitations

`docs/SBOM.foundation.spdx.json` remains an intentionally broad foundation inventory, while
`docs/SBOM.python.spdx.json` is the reconciled Python sub-inventory:

- the foundation file lists the direct Python inputs and the major proof/build components;
- the Python file lists all 26 logical packages, exact versions, declared licenses, and purls;
- the canonical Python artifact manifest separately binds all reviewed platform filenames, sizes,
  acquisition URLs, SHA-256 values, and SHA3-512 values;
- it does not claim a complete transitive dependency graph, even where a Cargo lock is present;
- outside the reviewed Python boundary, it uses `NOASSERTION` for unverified licenses, suppliers,
  source locations, and versions;
- it records the S-two commit because existing repository provenance provides it;
- it does not invent a `forge-std` version or commit;
- it does not represent S07-S09 proof-suite selections.

Passing the focused structural tests means only that this draft is internally honest and remains
aligned with the inspected manifests. It is not a reproducible-build qualification or release SBOM.
