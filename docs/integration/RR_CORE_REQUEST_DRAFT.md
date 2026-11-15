# Draft: request to the RightRail maintainers (rr-core)

Draft for the owner to send, 2026-11-15. Not sent by Claude.

---

Hello,

localBCE vendors RightRail and is adding two gate rules from its own rulebook. We have four requests.

1. **Git history for trunk `fc89f9e5ceaacfbfb0cb50173a4fd870e3872a3f`.** We imported it from the GitHub zip of `rightrail-main` (archive comment `fc89f9e5`, zip SHA-256 `1afbc74dc3cf3f5a97c494a196f0c0e0a2d3938abdd16c76b8ce09d36ba0ab71`), so we have no history. Could you send a git bundle or clone access that contains `fc89f9e5`, and also `b99355cc` and `7cae185e`? Without it we cannot offer changes back as pull requests.

2. **The pinned ML-DSA-87 signer.** `rust/gate_mldsa87/rr_gate_mldsa87.sha256` pins `a1a6e9e45b11be50792fe2f797fb4510d892662cec652a65c92a238e15686141`. Its README says reproducing it needs the original builder's CARGO_HOME path, MSVC 14.44.35207 and Windows SDK 10.0.26100.0, which we cannot match. Could you send the pinned `rr_gate_mldsa87.exe` itself? About 246 trunk tests, the throughput digests and the vector regeneration need it.

3. **Two more feeds in frame version 2 (ENGINE_V3 §17/§19).** We want to carry two member reference feeds in the request frame:
   - eligibility (SNAPSHOT/v1 kind 7): `member 32 ‖ aid 21 ‖ level u8 ‖ start u32 ‖ stop u32`, 62 bytes per row in §19 style;
   - share of cost (SNAPSHOT/v1 kind 8): `member 32 ‖ month u32 ‖ cents u64 ‖ met u8`, 45 bytes per row.
   Would you take these two feeds into your frame v2 when you build it? If not, we plan to build `FRAME/v3` as "your specified v2 plus these two feeds", with `CONTEXT/v2`, and an answer header version 3 whose leaf and record reason fields are u64, with reason bits numbered by `Reason.idx` and the two leaf-only codes at bits 62 and 63.

4. **Reserving numbers.** If we build it ourselves, please treat `FRAME/v3`, `CONTEXT/v2`, answer header version 3, `READ-SET/v5`, `READ-SET/v6`, `READ-ELIGIBILITY/v2` and `READ-SHARE-OF-COST/v2` as taken by this layout, so our tags do not collide with yours.

The full design is in localBCE `docs/integration/TRUNK_STEP2_FRAME_DESIGN.md` on branch `codex/rightrail-trunk`.

Thank you.
