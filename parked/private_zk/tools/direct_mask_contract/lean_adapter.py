"""Fail-closed adapter for the compiled Lean finite-arithmetic certificate.

The adapter deliberately does not build or substitute for Lean during normal
calculator execution. Tests may call ``build_formal_arithmetic_for_test``;
that helper reuses the existing guarded shared-host runner. Production-facing
calls require a fixed artifact receipt, a replacement-checked executable, and
one bounded invocation for each cap or runtime counter case.
"""

from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import stat
import tempfile
import threading
import time
from typing import Any, Callable, Iterator, Mapping, Sequence


class FormalArithmeticError(RuntimeError):
    """The Lean executable or its checkable result was unavailable or invalid."""


PRODUCT_ROOT = Path(__file__).resolve().parents[2]
FORMAL_ROOT = PRODUCT_ROOT / "formal" / "lean"
FORMAL_BINARY = FORMAL_ROOT / ".lake" / "build-v2" / "bin" / "blind_security_arithmetic_v2.exe"
ARTIFACT_RECEIPT = FORMAL_ROOT / "artifact_receipt.v2.json"
MODULE_PROVENANCE_RECEIPT = FORMAL_ROOT / "module_provenance.v1.json"
PINNED_TOOLCHAIN = "leanprover/lean4:v4.33.1"
BUILD_ID = "BL-SECURITY-ARITHMETIC-20260922-V2"
SCHEMA_ID = "BLSECAR02/v2"
EXPECTED_RECEIPT_SHA256 = "2e1bde1e70e3492e361a4d725bafa23e48053f9804ec510566234886cbaa3367"
EXPECTED_BINARY_RELATIVE_PATH = "formal/lean/.lake/build-v2/bin/blind_security_arithmetic_v2.exe"
EXPECTED_BUILD_DIRECTORY = "formal/lean/.lake/build-v2"
MODULE_PROVENANCE_SCHEMA_ID = "BLSECAR-LEAN-PROVENANCE/v1"
MODULE_PROVENANCE_VERSION = 1
# Final pin intentionally unset until the isolated rebuild, checker input
# closure, resolved native dependencies, and separate checker run are reviewed.
EXPECTED_MODULE_PROVENANCE_SHA256: str | None = None
MODULE_PROVENANCE_MAX_BYTES = 4 * 1024 * 1024
MAX_LINK_INPUT_BYTES = 512 * 1024 * 1024
IMPORT_GRAPH_FORMAT = "lean-olean-import-graph/v1"
IMPORT_GRAPH_SCRIPT_RELATIVE_PATH = "tools/direct_mask_contract/olean_imports.lean"
IMPORT_GRAPH_ROOTS = (
    "BlindLedger.Theorems",
    "BlindLedger.SecurityExecutable",
    "Lean",
)
EXPECTED_LINK_TARGET_TRIPLE = "x86_64-w64-windows-gnu"
EXPECTED_LINK_TARGET_FINGERPRINT = "360db333d006d911"
EXPECTED_LINK_COMPILER_ID = (
    "Lean 4.33.1, commit 819816b2e0a3bf405af45ae5c7af2491d8f5bee6"
)
EXPECTED_LINK_COMPILER_FINGERPRINT = "0051240b7c23c453"
EXPECTED_LINK_EXE_ARGUMENT = (
    "LeanExe.exeOnlyLinkArgs: #[-Wl,--whole-archive, -lleanmanifest, "
    "-Wl,--no-whole-archive]"
)
EXPECTED_LINK_EXE_ARGUMENT_FINGERPRINT = "d9dc93f51f923c09"
EXPECTED_MODULE_LINK_LIBRARIES_FINGERPRINT = "00000000000006bb"
EXPECTED_MODULE_LINK_ARGUMENT = "Module.moreLinkArgs: #[-Wl,--no-insert-timestamp]"
EXPECTED_MODULE_LINK_ARGUMENT_FINGERPRINT = "d6f50e436b171473"
EXPECTED_LINK_RESPONSE_RELATIVE_PATH = (
    f"{EXPECTED_BUILD_DIRECTORY}/bin/blind_security_arithmetic_v2.exe.rsp"
)
EXPECTED_LINK_TRACE_RELATIVE_PATH = (
    f"{EXPECTED_BUILD_DIRECTORY}/bin/blind_security_arithmetic_v2.exe.trace"
)
EXPECTED_LINKER_DRIVER_RELATIVE_PATH = "bin/clang.exe"
EXPECTED_LINKER_RELATIVE_PATH = "bin/ld.lld.exe"
EXPECTED_LINK_RESPONSE_TAIL = (
    "-Wl,--whole-archive", "-lleanmanifest", "-Wl,--no-whole-archive",
    "-Wl,--no-insert-timestamp", "-L", "<LEAN_LIB>", "--sysroot", "<TOOLCHAIN>",
    "-L", "<TOOLCHAIN_LIB>", "-Wl,-Bstatic", "-lgmp", "-luv", "-lpsapi",
    "-luser32", "-ladvapi32", "-liphlpapi", "-luserenv", "-lws2_32",
    "-ldbghelp", "-lole32", "-lshell32", "-lssl", "-lcrypto", "-lunwind",
    "-Wl,-Bdynamic", "-lcrypt32", "-lgdi32", "-fuse-ld=lld",
    "-Wl,--start-group", "-lleancpp", "-lLean", "-Wl,--end-group", "-lStd",
    "-Wl,--start-group", "-lInit", "-lleanrt", "-Wl,--end-group", "-lc++",
    "-lc++abi", "-lLake", "-lgmp", "-luv", "-lpsapi", "-luser32",
    "-ladvapi32", "-liphlpapi", "-luserenv", "-lws2_32", "-ldbghelp",
    "-lole32", "-lshell32", "-lssl", "-lcrypto", "-lcrypt32", "-lgdi32",
    "-lucrtbase", "-Wl,--stack,104857600", "-licu", "-Wl,--gc-sections",
    "-lm", "-lbcrypt", "-pthread",
)
EXPECTED_CHECKER_MODULE = "BlindLedger.Theorems"
PROJECT_MODULE_IMPORTS: dict[str, tuple[str, ...]] = {
    "BlindLedger.Arithmetic": ("Std", "Lean.Elab.Tactic.Omega"),
    "BlindLedger.RowBoundsSupport": ("BlindLedger.Arithmetic",),
    "BlindLedger.RowBoundsTerms": ("BlindLedger.RowBoundsSupport",),
    "BlindLedger.RowBoundsH0": ("BlindLedger.RowBoundsTerms",),
    "BlindLedger.RowBoundsH1": ("BlindLedger.RowBoundsTerms",),
    "BlindLedger.RowBoundsH1Outer": ("BlindLedger.RowBoundsTerms",),
    "BlindLedger.RowBoundsFS1": ("BlindLedger.RowBoundsTerms",),
    "BlindLedger.RowBoundsFS2": ("BlindLedger.RowBoundsTerms",),
    "BlindLedger.RowBoundsFS3": ("BlindLedger.RowBoundsTerms",),
    "BlindLedger.RowBoundsZero": ("BlindLedger.RowBoundsFS3",),
    "BlindLedger.RowBounds": (
        "BlindLedger.RowBoundsH0",
        "BlindLedger.RowBoundsH1",
        "BlindLedger.RowBoundsH1Outer",
        "BlindLedger.RowBoundsFS1",
        "BlindLedger.RowBoundsFS2",
        "BlindLedger.RowBoundsFS3",
        "BlindLedger.RowBoundsZero",
    ),
    "BlindLedger.WidthBoundsDefinitions": ("BlindLedger.RowBounds",),
    "BlindLedger.WidthBoundsCaps": ("BlindLedger.WidthBoundsDefinitions",),
    "BlindLedger.WidthBounds": ("BlindLedger.WidthBoundsCaps",),
    "BlindLedger.Theorems": (
        "BlindLedger.Arithmetic",
        "BlindLedger.RowBounds",
        "BlindLedger.WidthBounds",
    ),
    "BlindLedger.SecurityExecutable": ("BlindLedger.Theorems",),
}
LINK_MODULE_ORDER = (
    "BlindLedger.SecurityExecutable",
    "BlindLedger.Arithmetic",
    "BlindLedger.RowBoundsSupport",
    "BlindLedger.RowBoundsTerms",
    "BlindLedger.RowBoundsH0",
    "BlindLedger.RowBoundsH1",
    "BlindLedger.RowBoundsH1Outer",
    "BlindLedger.RowBoundsFS1",
    "BlindLedger.RowBoundsFS2",
    "BlindLedger.RowBoundsFS3",
    "BlindLedger.RowBoundsZero",
    "BlindLedger.RowBounds",
    "BlindLedger.WidthBoundsDefinitions",
    "BlindLedger.WidthBoundsCaps",
    "BlindLedger.WidthBounds",
    "BlindLedger.Theorems",
)


def _project_module_closure(target: str) -> tuple[str, ...]:
    if target not in PROJECT_MODULE_IMPORTS:
        raise RuntimeError(f"unknown pinned project module={target}")
    found: set[str] = set()

    def visit(module: str) -> None:
        if module in found:
            return
        found.add(module)
        for imported in PROJECT_MODULE_IMPORTS[module]:
            if imported in PROJECT_MODULE_IMPORTS:
                visit(imported)

    visit(target)
    return tuple(sorted(found))


CHECKER_PROJECT_MODULES = _project_module_closure(EXPECTED_CHECKER_MODULE)
# These are direct source import roots, not a derived closure for the system
# Lean library. The pinned provenance sidecar must carry a separately reviewed
# complete closure before its hash can be enabled.
TOOLCHAIN_IMPORT_ROOTS = tuple(
    sorted(
        {
            imported
            for module in CHECKER_PROJECT_MODULES
            for imported in PROJECT_MODULE_IMPORTS[module]
            if imported not in PROJECT_MODULE_IMPORTS
        }
    )
)


def _valid_module_name(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*", value, re.ASCII
    ) is not None


def _parse_olean_import_graph(
    raw_json: str,
) -> tuple[dict[str, tuple[str, ...]], dict[str, str]]:
    try:
        payload = json.loads(
            raw_json, object_pairs_hook=_strict_json_object, parse_constant=_reject_json_constant
        )
    except (ValueError, json.JSONDecodeError) as exc:
        raise _fail(f"module_provenance_import_graph_invalid={exc}") from exc
    _exact_keys(payload, {"format", "roots", "modules"}, "module_provenance.import_graph")
    if payload["format"] != IMPORT_GRAPH_FORMAT or payload["roots"] != list(IMPORT_GRAPH_ROOTS):
        raise _fail("module_provenance_import_graph_identity_mismatch")
    nodes = payload["modules"]
    if not isinstance(nodes, list):
        raise _fail("module_provenance_import_graph_modules_array_required")
    graph: dict[str, tuple[str, ...]] = {}
    paths: dict[str, str] = {}
    ordered_names: list[str] = []
    for record in nodes:
        _exact_keys(record, {"name", "path", "imports"}, "module_provenance.import_graph.module")
        name = record["name"]
        path = record["path"]
        imports = record["imports"]
        if not _valid_module_name(name) or not isinstance(path, str) or not path:
            raise _fail("module_provenance_import_graph_module_identity_invalid")
        if not isinstance(imports, list) or any(not _valid_module_name(item) for item in imports):
            raise _fail(f"module_provenance_import_graph_imports_invalid={name}")
        if len(set(imports)) != len(imports) or name in graph:
            raise _fail(f"module_provenance_import_graph_duplicate={name}")
        graph[name] = tuple(imports)
        paths[name] = path
        ordered_names.append(name)
    if ordered_names != sorted(ordered_names):
        raise _fail("module_provenance_import_graph_order_invalid")
    if not set(IMPORT_GRAPH_ROOTS) <= set(graph):
        raise _fail("module_provenance_import_graph_root_missing")
    if any(imported not in graph for imports in graph.values() for imported in imports):
        raise _fail("module_provenance_import_graph_edge_missing")
    return graph, paths


def _import_graph_closure(graph: Mapping[str, Sequence[str]], root: str) -> set[str]:
    reachable: set[str] = set()

    def visit(module: str) -> None:
        if module in reachable:
            return
        imports = graph.get(module)
        if imports is None:
            raise _fail(f"module_provenance_import_graph_module_missing={module}")
        reachable.add(module)
        for imported in imports:
            visit(imported)

    visit(root)
    return reachable
THEOREM_MANIFEST_ENCODING = "comma-separated-lean-identifiers/v1"
EXPECTED_THEOREM_MANIFEST = (
    "cap_adaptive_square_lt_remaining_square",
    "cap_counters_well_formed",
    "cap_qrom_bound_lt_quarter",
    "cap_theorem_bundle",
    "p_cap_exact",
    "p_mono",
    "q_alg_cap_exact",
    "q_alg_mono",
    "q_eff_cap_exact",
    "q_eff_completion_accounting",
    "q_eff_mono",
    "q_hist_cap_exact",
    "q_hist_mono",
    "remaining_nonnegative_on_admissible",
    "row_bounds_certificate_bundle",
    "row_bounds_one_max_e3",
    "row_bounds_one_simplified",
    "row_bounds_simplified",
    "row_bounds_zero_max_e3",
    "row_bounds_zero_simplified",
    "switching_counted_once_at_caps",
    "theoremManifest_count",
    "width384_cap_row_terms_le_e3",
    "width384_delta_cap_all_k",
    "width384_direct_constant_gate",
    "width384_partition",
    "width512_cap_row_terms_le_e3",
    "width512_delta_cap_all_k",
    "width512_direct_constant_gate",
    "width512_partition",
    "width_delta_all_k_bundle",
    "width_partition_bundle",
)
EXPECTED_THEOREM_MANIFEST_COUNT = 32
THEOREM_MANIFEST_NAME_RE = re.compile(r"^[a-z][A-Za-z0-9_]*$", re.ASCII)
if (
    len(EXPECTED_THEOREM_MANIFEST) != EXPECTED_THEOREM_MANIFEST_COUNT
    or len(set(EXPECTED_THEOREM_MANIFEST)) != EXPECTED_THEOREM_MANIFEST_COUNT
    or any(not THEOREM_MANIFEST_NAME_RE.fullmatch(name) for name in EXPECTED_THEOREM_MANIFEST)
):
    raise RuntimeError("invalid pinned v2 theorem manifest")
RECEIPT_SOURCE_PATHS = (
    "formal/lean/BlindLedger.lean",
    "formal/lean/BlindLedger/Arithmetic.lean",
    "formal/lean/BlindLedger/RowBoundsSupport.lean",
    "formal/lean/BlindLedger/RowBoundsTerms.lean",
    "formal/lean/BlindLedger/RowBoundsH0.lean",
    "formal/lean/BlindLedger/RowBoundsH1.lean",
    "formal/lean/BlindLedger/RowBoundsH1Outer.lean",
    "formal/lean/BlindLedger/RowBoundsFS1.lean",
    "formal/lean/BlindLedger/RowBoundsFS2.lean",
    "formal/lean/BlindLedger/RowBoundsFS3.lean",
    "formal/lean/BlindLedger/RowBoundsZero.lean",
    "formal/lean/BlindLedger/RowBounds.lean",
    "formal/lean/BlindLedger/WidthBoundsDefinitions.lean",
    "formal/lean/BlindLedger/WidthBoundsCaps.lean",
    "formal/lean/BlindLedger/WidthBounds.lean",
    "formal/lean/BlindLedger/AxiomCheck.lean",
    "formal/lean/BlindLedger/SecurityExecutable.lean",
    "formal/lean/BlindLedger/Theorems.lean",
    "formal/lean/lean-toolchain",
    "formal/lean/lakefile.toml",
    "formal/lean/lake-manifest.json",
    "tools/direct_mask_contract/manifest_v2.json",
)
EXPECTED_GUARD_RELATIVE_PATH = "../pq-wide-seed-native-20260913/build-filter-native/run_guarded_v3.ps1"
EXPECTED_GUARD_SHA256 = "55a9655ffd4f4cb4ea779d1e6fe67507cc875d7bad0ac52db128e964b5581e3d"
PROVENANCE_GUARD_RELATIVE_PATH = "../pq-wide-seed-native-20260913/build-filter-native/run_guarded_v4.ps1"
PROVENANCE_GUARD_SHA256 = "57f9ec8aefe1d0e281b3bb0d76f2f057c8295f99afdd04305dfc777703ed99fb"
EXPECTED_GUARD_MUTEX = r"Local\BlindLedgerDirectMaskBuild20260907"
EXPECTED_PHYSICAL_RESERVE_BYTES = 3_221_225_472
EXPECTED_PHYSICAL_RESERVE_TOLERANCE_PERCENT = 32
EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES = 2_190_433_321
EXPECTED_PROCESS_TREE_CAP_BYTES = 2_000_000_000
# Security provenance rebuild start floor: physical floor + historic peak private bytes
# (1,411,237,144) + 512 MiB headroom.
PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES = 4_138_541_377
MAX_RECEIPT_BYTES = 65_536
MAX_OUTPUT_BYTES = 2_000_000
MAX_BUILD_OUTPUT_BYTES = 8_000_000
MAX_HASH_BYTES = 256 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
PIPE_CHUNK_BYTES = 64 * 1024
CAP_CACHE_MAXSIZE = 1
RUNTIME_CACHE_MAXSIZE = 64
ROW_CACHE_MAXSIZE = 64
OWNED_PROCESS_STOP_GRACE_SECONDS = 35.0
OWNED_PROCESS_TERMINATION_TIMEOUT_SECONDS = 5.0
GUARDED_FORMAL_MODULES = frozenset({
    "BlindLedger/Arithmetic.lean",
    "BlindLedger/RowBoundsSupport.lean",
    "BlindLedger/RowBoundsTerms.lean",
    "BlindLedger/RowBoundsH0.lean",
    "BlindLedger/RowBoundsH1.lean",
    "BlindLedger/RowBoundsH1Outer.lean",
    "BlindLedger/RowBoundsFS1.lean",
    "BlindLedger/RowBoundsFS2.lean",
    "BlindLedger/RowBoundsFS3.lean",
    "BlindLedger/RowBoundsZero.lean",
    "BlindLedger/RowBounds.lean",
    "BlindLedger/WidthBoundsDefinitions.lean",
    "BlindLedger/WidthBoundsCaps.lean",
    "BlindLedger/WidthBounds.lean",
    "BlindLedger/Theorems.lean",
    "BlindLedger/SecurityExecutable.lean",
})
PINNED_LEAN = Path.home() / ".elan" / "toolchains" / "leanprover--lean4---v4.33.1" / "bin" / "lean.exe"
PINNED_LAKE = Path.home() / ".elan" / "toolchains" / "leanprover--lean4---v4.33.1" / "bin" / "lake.exe"
PINNED_LEANCHECKER = Path.home() / ".elan" / "toolchains" / "leanprover--lean4---v4.33.1" / "bin" / "leanchecker.exe"
PINNED_PWSH = Path(
    r"C:\Users\neers\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe"
)
WINDOWS_TASKKILL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
EXISTING_GUARD = (
    PRODUCT_ROOT.parent / "pq-wide-seed-native-20260913" / "build-filter-native" / "run_guarded_v3.ps1"
)
PROVENANCE_GUARD = (
    PRODUCT_ROOT.parent / "pq-wide-seed-native-20260913" / "build-filter-native" / "run_guarded_v4.ps1"
)

COUNTER_FIELDS = (
    "Q", "A", "V", "M", "E_U", "S", "R0", "R2", "R3",
    "h0_first", "h0_accepted", "h0_rejected", "h0_aborted", "h0_oracle_evaluations",
    "fs2_first", "fs2_accepted", "fs2_rejected", "fs2_aborted", "fs2_oracle_evaluations",
    "fs3_first", "fs3_accepted", "fs3_rejected", "fs3_aborted", "fs3_oracle_evaluations",
)
BOOLEAN_FIELDS = (
    "one_commitment_per_attempt", "source_generation_admitted", "U96_nonzero",
    "source_coins_independent", "source_cap_enforced",
)
FRACTION_FIELDS = {
    "uncapped", "bound", "half_success_probe_bound", "linear_term", "remaining", "sqrt_term",
    "target", "bit_switching", "source_switching", "combined_switching_at_caps", "source_binding",
    "e0", "eKOS", "e2", "e3", "max_constant", "h0_completion", "e_leaf_v3", "direct_max",
    "h0_bound", "h1_vector_bound", "h1_outer_bound", "fs1_bound", "fs2_bound", "fs3_bound",
    "delta_cap", "delta_linear_weight", "delta_sum_upper", "soundness_bound",
    "generator_privacy_bound", "seed_collision_term", "epsilon_ar_upper_bound", "source_alpha_ceiling",
    "H0_leaf_bad_or_completion", "H1_vector", "H1_outer", "FS1", "FS2", "FS3",
    "other_typed_input", "maximum_row_bound", "simplified_replacement_bound",
}
BOOL_FIELDS = {
    "q_overhead_lt_2^55", "bound_lt_one_quarter", "half_success_probe_lt_one_half",
    "q_hist_lt_cap_ratio", "sqrt_square_lt_remaining_square", "remaining_nonnegative",
    "combined_switching_available", "max_is_e3", "e3_ge_e0", "e3_ge_eKOS", "e3_ge_e2",
    "density_a_lt_2^17", "density_m_minus_1_lt_2^18", "e3_ge_e_leaf_v3",
    "simplified_bound_holds", "delta_cap_is_constant_for_all_k",
}
NATURAL_FIELDS = {
    "q_alg", "q_eff", "q", "q_alg_overhead", "q_overhead", "half_success_probe_q",
    "half_success_probe_q_eff", "P_upper_bound", "q_hist", "q_hist_overhead",
    "sqrt_radicand", "q_star_without_overlay", "manifest_count", "width", "j",
    "seed_width_bits", "seed_width_bytes", "r", "nu_bits", "active_h0_bits",
    "h0_squeeze_bytes", "nu_serialized_bytes", "commitment_bytes", "leaf_output_bits",
    "leaf_output_bytes", "stream_blocks_per_row", "frontier_seed_bytes", "m4_bytes",
    "frame_bytes", "frame_delta", "h0_input_bytes", "h1_vector_128_input_bytes",
    "h1_vector_256_input_bytes", "h1_outer_input_bytes", "fs_uhash_bytes",
    "tree_child_queries_per_commitment", "generator_H_queries_per_commitment",
    "generator_H_queries_at_caps", "verifier_generator_H_queries_per_verification",
    "verifier_generator_H_queries_at_caps", "candidate_q_hist_at_caps", "candidate_q_alg_at_caps",
    "candidate_qP", "candidate_q_eff_at_caps", "candidate_q_H_at_caps",
    "candidate_total_public_RO_queries_at_caps", "secret_seed_count_at_caps", "hybrid_count_at_caps",
    "fs1_bytes", "fs2_bytes", "fs3_bytes", "fs1_bits", "fs2_bits", "fs3_bits",
    "program_points", "table_entry_bits", "table_memory_bits", "table_memory_bytes",
    "scan_units_per_forward", "scan_history_units", "scan_forward_reverse_units",
}

HEADER_TAG = "BL-SECURITY-ARITHMETIC/2"
HEADER_PASS_FIELDS = frozenset({"schema", "result", "mode", "build_id", "toolchain"})
HEADER_REJECT_FIELDS = frozenset({"schema", "result", "mode", "build_id", "toolchain", "error"})
THEOREM_FIELDS = frozenset({
    "manifest_count", "manifest_names", "manifest_count_proof", "cap_bundle", "width_bundle", "completion_accounting",
    "row_bounds_bundle", "row_bounds_simplified", "width384_delta_cap_all_k",
    "width512_delta_cap_all_k", "width_delta_all_k_bundle", "crypto_primitives_custody_operations",
})
COUNTERS_RECORD_FIELDS = frozenset(COUNTER_FIELDS + BOOLEAN_FIELDS)
CONSTANT_RECORD_FIELDS = frozenset({
    "e0", "eKOS", "e2", "e3", "max_constant", "max_is_e3", "e3_ge_e0", "e3_ge_eKOS",
    "e3_ge_e2", "density_a_lt_2^17", "density_m_minus_1_lt_2^18",
})
QROM_RUNTIME_FIELDS = frozenset({"q_alg", "q_eff", "q", "uncapped", "bound"})
QROM_CAP_FIELDS = frozenset({
    "q_alg", "q_eff", "q", "q_alg_overhead", "q_overhead", "uncapped", "bound",
    "q_overhead_lt_2^55", "bound_lt_one_quarter", "half_success_probe_q",
    "half_success_probe_q_eff", "half_success_probe_bound", "half_success_probe_lt_one_half",
})
PRIVACY_RECORD_FIELDS = frozenset({
    "P_upper_bound", "q_hist", "q_hist_overhead", "q_star_without_overlay", "q_hist_lt_cap_ratio",
    "linear_term", "remaining", "remaining_nonnegative", "sqrt_radicand", "sqrt_term",
    "sqrt_square_lt_remaining_square", "target", "bit_switching", "source_switching",
    "combined_switching_at_caps", "combined_switching_available", "source_binding",
})
WIDTH_RECORD_FIELDS = frozenset({
    "width", "seed_width_bits", "seed_width_bytes", "r", "nu_bits", "active_h0_bits",
    "h0_squeeze_bytes", "nu_serialized_bytes", "commitment_bytes", "leaf_output_bits",
    "leaf_output_bytes", "stream_blocks_per_row", "frontier_seed_bytes", "m4_bytes", "frame_bytes",
    "frame_delta", "h0_input_bytes", "h1_vector_128_input_bytes", "h1_vector_256_input_bytes",
    "h1_outer_input_bytes", "fs_uhash_bytes", "tree_child_queries_per_commitment",
    "generator_H_queries_per_commitment", "generator_H_queries_at_caps",
    "verifier_generator_H_queries_per_verification", "verifier_generator_H_queries_at_caps",
    "candidate_q_hist_at_caps", "candidate_q_alg_at_caps", "candidate_qP", "candidate_q_eff_at_caps",
    "candidate_q_H_at_caps", "candidate_total_public_RO_queries_at_caps", "secret_seed_count_at_caps",
    "hybrid_count_at_caps", "h0_completion", "e_leaf_v3", "eKOS", "e2", "e3", "direct_max",
    "e3_ge_e_leaf_v3", "e3_ge_eKOS", "e3_ge_e2", "direct_constant_max_name", "h0_bound",
    "h1_vector_bound", "h1_outer_bound", "fs1_bound", "fs2_bound", "fs3_bound", "delta_cap_name",
    "delta_cap_is_constant_for_all_k", "delta_cap", "delta_linear_weight", "delta_sum_upper",
    "soundness_bound", "generator_privacy_bound", "seed_collision_term", "epsilon_ar_upper_bound",
    "source_alpha_ceiling", "source_switching", "fs1_bytes", "fs2_bytes", "fs3_bytes", "fs1_bits",
    "fs2_bits", "fs3_bits", "program_points", "table_entry_bits", "table_memory_bits",
    "table_memory_bytes", "scan_units_per_forward", "scan_history_units", "scan_forward_reverse_units",
})
ROW_RECORD_FIELDS = frozenset({
    "j", "H0_leaf_bad_or_completion", "H1_vector", "H1_outer", "FS1", "FS2", "FS3",
    "other_typed_input", "maximum_row_bound", "simplified_replacement_bound", "simplified_bound_holds",
})
STRING_TOKEN_RE = re.compile(r"^[^;=\r\n\t ]+$", re.ASCII)
NATURAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
FRACTION_RE = re.compile(r"^(?:0|-[1-9][0-9]*|[1-9][0-9]*)/(?:[1-9][0-9]*)$")
REJECT_ERRORS = frozenset({
    "counters-not-well-formed", "runtime-arity", "natural-number-parse", "boolean-parse",
    "row-arity", "argument-shape",
})


def _fail(message: str) -> FormalArithmeticError:
    return FormalArithmeticError(message)


def _parse_bool(value: str, field: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise _fail(f"field={field}: invalid_bool={value!r}")


def _parse_natural(value: str, field: str) -> int:
    if not NATURAL_RE.fullmatch(value):
        raise _fail(f"field={field}: invalid_natural={value!r}")
    try:
        return int(value, 10)
    except ValueError as exc:
        raise _fail(f"field={field}: invalid_natural={value!r}") from exc


def _parse_fraction(value: str, field: str) -> tuple[int, int]:
    if not FRACTION_RE.fullmatch(value):
        raise _fail(f"field={field}: invalid_fraction={value!r}")
    numerator, denominator = value.split("/", 1)
    try:
        return int(numerator, 10), int(denominator, 10)
    except ValueError as exc:
        raise _fail(f"field={field}: invalid_fraction={value!r}") from exc


def _parse_records(stdout: str) -> dict[str, list[dict[str, str]]]:
    try:
        encoded_size = len(stdout.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise _fail("stdout_not_utf8") from exc
    if not stdout or encoded_size > MAX_OUTPUT_BYTES:
        raise _fail(f"stdout_size_invalid={encoded_size}")
    records: dict[str, list[dict[str, str]]] = {}
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if not line:
            raise _fail(f"line={line_number}: blank_line")
        pieces = line.split(";")
        tag = pieces[0]
        if not tag or not STRING_TOKEN_RE.fullmatch(tag):
            raise _fail(f"line={line_number}: invalid_tag={tag!r}")
        fields: dict[str, str] = {}
        for piece in pieces[1:]:
            if piece.count("=") != 1:
                raise _fail(f"line={line_number}: malformed_field={piece!r}")
            key, value = piece.split("=", 1)
            if not key or key in fields or not STRING_TOKEN_RE.fullmatch(key):
                raise _fail(f"line={line_number}: malformed_field={piece!r}")
            fields[key] = value
        records.setdefault(tag, []).append(fields)
    return records


def _typed_record(record: Mapping[str, str]) -> dict[str, Any]:
    typed: dict[str, Any] = {}
    for field, raw_value in record.items():
        if field in COUNTER_FIELDS or field in NATURAL_FIELDS:
            typed[field] = _parse_natural(raw_value, field)
        elif field in BOOLEAN_FIELDS or field in BOOL_FIELDS:
            typed[field] = _parse_bool(raw_value, field)
        elif field in FRACTION_FIELDS:
            typed[field] = _parse_fraction(raw_value, field)
        else:
            if not STRING_TOKEN_RE.fullmatch(raw_value):
                raise _fail(f"field={field}: invalid_string={raw_value!r}")
            typed[field] = raw_value
    return typed


def _validate_record_shape(tag: str, record: Mapping[str, str], expected: frozenset[str]) -> None:
    actual = frozenset(record)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise _fail(f"record={tag}: fields_mismatch;missing={missing!r};unknown={unknown!r}")


def _validate_result(stdout: str, stderr: str, mode: str) -> dict[str, Any]:
    if stderr:
        raise _fail(f"stderr_nonempty={stderr!r}")
    if mode not in {"cap", "runtime", "row", "unknown"}:
        raise _fail(f"mode_invalid={mode!r}")
    records = _parse_records(stdout)
    headers = records.get(HEADER_TAG, [])
    if len(headers) != 1:
        raise _fail(f"header_count={len(headers)}")
    header = headers[0]
    result_value = header.get("result")
    header_fields = HEADER_PASS_FIELDS if result_value == "PASS" else HEADER_REJECT_FIELDS
    _validate_record_shape(HEADER_TAG, header, header_fields)
    expected = {"schema": SCHEMA_ID, "mode": mode, "build_id": BUILD_ID, "toolchain": PINNED_TOOLCHAIN}
    for field, value in expected.items():
        if header.get(field) != value:
            raise _fail(f"header_{field}_mismatch={header.get(field)!r}")
    if result_value not in {"PASS", "REJECT"}:
        raise _fail(f"header_result_invalid={result_value!r}")
    if result_value == "REJECT":
        if set(records) != {HEADER_TAG}:
            raise _fail(f"reject_extra_records={sorted(set(records) - {HEADER_TAG})!r}")
        if header.get("error") not in REJECT_ERRORS:
            raise _fail(f"header_error_invalid={header.get('error')!r}")
    else:
        if mode == "cap":
            expected_records = {
                HEADER_TAG: (HEADER_PASS_FIELDS, 1), "THEOREMS": (THEOREM_FIELDS, 1),
                "COUNTERS": (COUNTERS_RECORD_FIELDS, 1), "CONSTANTS": (CONSTANT_RECORD_FIELDS, 1),
                "QROM": (QROM_CAP_FIELDS, 1), "PRIVACY": (PRIVACY_RECORD_FIELDS, 1),
                "WIDTH": (WIDTH_RECORD_FIELDS, 2),
            }
        elif mode == "runtime":
            expected_records = {
                HEADER_TAG: (HEADER_PASS_FIELDS, 1), "THEOREMS": (THEOREM_FIELDS, 1),
                "COUNTERS": (COUNTERS_RECORD_FIELDS, 1), "QROM": (QROM_RUNTIME_FIELDS, 1),
                "PRIVACY": (PRIVACY_RECORD_FIELDS, 1),
            }
        elif mode == "row":
            expected_records = {
                HEADER_TAG: (HEADER_PASS_FIELDS, 1), "THEOREMS": (THEOREM_FIELDS, 1),
                "ROW": (ROW_RECORD_FIELDS, 1),
            }
        else:
            raise _fail("unknown_mode_pass")
        if set(records) != set(expected_records):
            raise _fail(f"record_tags_mismatch;actual={sorted(records)!r};expected={sorted(expected_records)!r}")
        for tag, (fields, count) in expected_records.items():
            values = records[tag]
            if len(values) != count:
                raise _fail(f"{tag}_count={len(values)};expected={count}")
            for record in values:
                _validate_record_shape(tag, record, fields)
    typed_records = {
        tag: [_typed_record(record) for record in values]
        for tag, values in records.items()
    }
    return {"header": _typed_record(header), "records": typed_records}


def _required_record(result: Mapping[str, Any], tag: str, *, index: int = 0) -> dict[str, Any]:
    values = result["records"].get(tag, [])
    if len(values) <= index:
        raise _fail(f"record_missing={tag}[{index}]")
    return values[index]


def _validate_theorem_manifest(theorems: Mapping[str, Any]) -> list[str]:
    expected = list(EXPECTED_THEOREM_MANIFEST)
    if len(expected) != EXPECTED_THEOREM_MANIFEST_COUNT:
        raise _fail("adapter_theorem_manifest_contract_invalid")
    expected_set = set(expected)
    declared_count = theorems.get("manifest_count")
    encoded_names = theorems.get("manifest_names")
    if not isinstance(encoded_names, str) or not encoded_names:
        raise _fail("theorem_manifest_names_missing")
    names = encoded_names.split(",")
    if any(not THEOREM_MANIFEST_NAME_RE.fullmatch(name) for name in names):
        raise _fail("theorem_manifest_name_encoding_invalid")
    seen: set[str] = set()
    duplicate_names: set[str] = set()
    for name in names:
        if name in seen:
            duplicate_names.add(name)
        else:
            seen.add(name)
    duplicates = sorted(duplicate_names)
    if duplicates:
        raise _fail(f"theorem_manifest_duplicate_names={duplicates!r}")
    actual_set = set(names)
    extras = sorted(actual_set - expected_set)
    if extras:
        raise _fail(f"theorem_manifest_extra_names={extras!r}")
    missing = [name for name in expected if name not in actual_set]
    if missing:
        raise _fail(f"theorem_manifest_omitted_names={missing!r}")
    if not isinstance(declared_count, int) or isinstance(declared_count, bool):
        raise _fail(f"theorem_manifest_count_invalid={declared_count!r}")
    if declared_count != EXPECTED_THEOREM_MANIFEST_COUNT:
        raise _fail(
            f"theorem_manifest_count_mismatch={declared_count};expected={EXPECTED_THEOREM_MANIFEST_COUNT}"
        )
    if len(names) != declared_count:
        raise _fail(f"theorem_manifest_name_count_mismatch={len(names)};declared={declared_count}")
    if names != expected:
        raise _fail("theorem_manifest_order_mismatch")
    return names


def _normalise_result(
    result: dict[str, Any], mode: str, *, require_pass: bool, binary_sha256: str
) -> dict[str, Any]:
    if require_pass and result["header"].get("result") != "PASS":
        error = result["header"].get("error", "lean-rejected-without-error")
        raise _fail(f"lean_result_rejected={error}")
    if result["header"].get("result") == "REJECT":
        return result
    output: dict[str, Any] = {
        "header": result["header"],
        "theorems": _required_record(result, "THEOREMS"),
        "binary_sha256": binary_sha256,
    }
    output["theorems"]["manifest_names"] = _validate_theorem_manifest(output["theorems"])
    theorem_expectations: dict[str, Any] = {
        "manifest_count": EXPECTED_THEOREM_MANIFEST_COUNT, "manifest_count_proof": "PROVED_THEOREM_TERM",
        "cap_bundle": "PROVED_THEOREM_TERM", "width_bundle": "PROVED_THEOREM_TERM",
        "completion_accounting": "PROVED_THEOREM_TERM", "row_bounds_bundle": "PROVED_THEOREM_TERM",
        "row_bounds_simplified": "PROVED_THEOREM_TERM", "width384_delta_cap_all_k": "PROVED_THEOREM_TERM",
        "width512_delta_cap_all_k": "PROVED_THEOREM_TERM", "width_delta_all_k_bundle": "PROVED_THEOREM_TERM",
        "crypto_primitives_custody_operations": "EXTERNAL_PREMISES",
    }
    for field, expected in theorem_expectations.items():
        if output["theorems"].get(field) != expected:
            raise _fail(
                f"theorem_{field}_mismatch={output['theorems'].get(field)!r};expected={expected!r}"
            )
    if mode == "row":
        output["row"] = _required_record(result, "ROW")
        return output
    output["counters"] = _required_record(result, "COUNTERS")
    output["qrom"] = _required_record(result, "QROM")
    output["privacy"] = _required_record(result, "PRIVACY")
    if mode == "cap":
        output["constants"] = _required_record(result, "CONSTANTS")
        widths = result["records"]["WIDTH"]
        output["widths"] = {str(record["width"]): record for record in widths}
        if set(output["widths"]) != {"384", "512"}:
            raise _fail(f"WIDTH_keys={sorted(output['widths'])!r}")
    return output


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key={key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"nonfinite_json={value}")


def _exact_keys(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(f"receipt_{name}_object_required")
    actual = set(value)
    if not all(isinstance(key, str) for key in actual) or actual != expected:
        raise _fail(
            f"receipt_{name}_keys_mismatch;actual={sorted(map(str, actual))!r};expected={sorted(expected)!r}"
        )
    return value


def _hash_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise _fail(f"receipt_{name}_sha256_invalid={value!r}")
    return value


def _load_artifact_receipt() -> tuple[dict[str, Any], str]:
    if _path_is_link_or_reparse(ARTIFACT_RECEIPT) or not ARTIFACT_RECEIPT.is_file():
        raise _fail(f"artifact_receipt_missing_or_link={ARTIFACT_RECEIPT}")
    try:
        raw = ARTIFACT_RECEIPT.read_bytes()
    except OSError as exc:
        raise _fail(f"artifact_receipt_read_failed={exc}") from exc
    if len(raw) > MAX_RECEIPT_BYTES:
        raise _fail(f"artifact_receipt_too_large={len(raw)}")
    digest = hashlib.sha256(raw).hexdigest()
    if EXPECTED_RECEIPT_SHA256 is None:
        raise _fail("artifact_receipt_hash_unpinned")
    if digest != EXPECTED_RECEIPT_SHA256:
        raise _fail(f"artifact_receipt_hash_mismatch={digest}")
    try:
        receipt = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_json_object, parse_constant=_reject_json_constant
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise _fail(f"artifact_receipt_invalid_json={exc}") from exc
    _exact_keys(
        receipt,
        {
            "receipt_version", "build_id", "schema_id", "toolchain", "binary",
            "source_sha256", "theorem_manifest", "guard", "tools", "build_lock",
        },
        "root",
    )
    if receipt["receipt_version"] != 2:
        raise _fail(f"receipt_version_invalid={receipt['receipt_version']!r}")
    if receipt["build_id"] != BUILD_ID or receipt["schema_id"] != SCHEMA_ID:
        raise _fail("receipt_contract_identity_mismatch")
    if receipt["toolchain"] != PINNED_TOOLCHAIN:
        raise _fail(f"receipt_toolchain_mismatch={receipt['toolchain']!r}")
    binary = _exact_keys(receipt["binary"], {"relative_path", "sha256", "size"}, "binary")
    if binary["relative_path"] != EXPECTED_BINARY_RELATIVE_PATH:
        raise _fail(f"receipt_binary_path_mismatch={binary['relative_path']!r}")
    _hash_text(binary["sha256"], "binary")
    if not isinstance(binary["size"], int) or isinstance(binary["size"], bool) or binary["size"] <= 0:
        raise _fail(f"receipt_binary_size_invalid={binary['size']!r}")
    theorem_manifest = _exact_keys(
        receipt["theorem_manifest"], {"encoding", "count", "names"}, "theorem_manifest"
    )
    if theorem_manifest["encoding"] != THEOREM_MANIFEST_ENCODING:
        raise _fail("receipt_theorem_manifest_encoding_mismatch")
    if theorem_manifest["count"] != EXPECTED_THEOREM_MANIFEST_COUNT:
        raise _fail("receipt_theorem_manifest_count_mismatch")
    if theorem_manifest["names"] != list(EXPECTED_THEOREM_MANIFEST):
        raise _fail("receipt_theorem_manifest_names_mismatch")
    sources = receipt["source_sha256"]
    if not isinstance(sources, dict) or set(sources) != set(RECEIPT_SOURCE_PATHS):
        raise _fail("receipt_source_set_mismatch")
    for relative_path, value in sources.items():
        if not isinstance(relative_path, str) or "\\" in relative_path or relative_path.startswith("../"):
            raise _fail(f"receipt_source_path_invalid={relative_path!r}")
        _hash_text(value, f"source.{relative_path}")
    guard = _exact_keys(
        receipt["guard"],
        {
            "relative_path", "sha256", "mutex_name", "physical_reserve_bytes",
            "effective_free_floor_bytes", "tolerance_percent", "process_tree_cap_bytes",
        },
        "guard",
    )
    if guard["relative_path"] != EXPECTED_GUARD_RELATIVE_PATH:
        raise _fail(f"receipt_guard_path_mismatch={guard['relative_path']!r}")
    _hash_text(guard["sha256"], "guard")
    if guard["sha256"] != EXPECTED_GUARD_SHA256:
        raise _fail(f"receipt_guard_hash_mismatch={guard['sha256']!r};expected={EXPECTED_GUARD_SHA256!r}")
    if guard["mutex_name"] != EXPECTED_GUARD_MUTEX:
        raise _fail(f"receipt_guard_mutex_mismatch={guard['mutex_name']!r}")
    if guard["physical_reserve_bytes"] != EXPECTED_PHYSICAL_RESERVE_BYTES:
        raise _fail("receipt_guard_reserve_mismatch")
    if guard["effective_free_floor_bytes"] != EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES:
        raise _fail("receipt_guard_effective_floor_mismatch")
    if guard["tolerance_percent"] != EXPECTED_PHYSICAL_RESERVE_TOLERANCE_PERCENT:
        raise _fail("receipt_guard_tolerance_mismatch")
    if guard["process_tree_cap_bytes"] != EXPECTED_PROCESS_TREE_CAP_BYTES:
        raise _fail("receipt_guard_process_cap_mismatch")
    tools = _exact_keys(receipt["tools"], {"lean", "lake", "leanchecker", "pwsh"}, "tools")
    for tool_name in tools:
        tool = _exact_keys(tools[tool_name], {"sha256", "size"}, f"tools.{tool_name}")
        _hash_text(tool["sha256"], f"tools.{tool_name}")
        if not isinstance(tool["size"], int) or isinstance(tool["size"], bool) or tool["size"] <= 0:
            raise _fail(f"receipt_tools.{tool_name}.size_invalid={tool['size']!r}")
    build_lock = _exact_keys(
        receipt["build_lock"],
        {
            "binary_relative_path", "source_root", "source_file_count", "manifest_entry_count",
            "build_directory", "guard_mode", "guard_mutex", "max_output_bytes",
        },
        "build_lock",
    )
    if build_lock != {
        "binary_relative_path": EXPECTED_BINARY_RELATIVE_PATH,
        "source_root": "formal/lean",
        "source_file_count": len(RECEIPT_SOURCE_PATHS),
        "manifest_entry_count": EXPECTED_THEOREM_MANIFEST_COUNT,
        "build_directory": EXPECTED_BUILD_DIRECTORY,
        "guard_mode": "Command",
        "guard_mutex": EXPECTED_GUARD_MUTEX,
        "max_output_bytes": MAX_OUTPUT_BYTES,
    }:
        raise _fail("receipt_build_lock_mismatch")
    return receipt, digest


def _path_is_link_or_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise _fail(f"artifact_path_lstat_failed={path};error={exc}") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _module_source_relative_path(module: str) -> str:
    return f"formal/lean/{module.replace('.', '/')}.lean"


def _module_output_relative_path(
    module: str, kind: str, *, build_directory: str = EXPECTED_BUILD_DIRECTORY
) -> str:
    stem = module.replace(".", "/")
    if kind == "olean":
        return f"{build_directory}/lib/lean/{stem}.olean"
    if kind == "generated_c":
        return f"{build_directory}/ir/{stem}.c"
    if kind == "native_object":
        return f"{build_directory}/ir/{stem}.c.o.noexport"
    raise RuntimeError(f"unknown pinned module output kind={kind}")


def _link_response_relative_path(build_directory: str) -> str:
    return f"{build_directory}/bin/blind_security_arithmetic_v2.exe.rsp"


def _link_trace_relative_path(build_directory: str) -> str:
    return f"{build_directory}/bin/blind_security_arithmetic_v2.exe.trace"


def _binary_relative_path(build_directory: str) -> str:
    return f"{build_directory}/bin/blind_security_arithmetic_v2.exe"


def _module_artifact_record(
    record: Any,
    *,
    expected_relative_path: str,
    root: Path,
    label: str,
    verify_files: bool,
    max_bytes: int = MAX_HASH_BYTES,
) -> tuple[str, str, int, Path]:
    artifact = _exact_keys(record, {"relative_path", "sha256", "size"}, label)
    if artifact["relative_path"] != expected_relative_path:
        raise _fail(
            f"{label}_path_mismatch={artifact['relative_path']!r};expected={expected_relative_path!r}"
        )
    expected_hash = _hash_text(artifact["sha256"], label)
    expected_size = artifact["size"]
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size <= 0:
        raise _fail(f"{label}_size_invalid={expected_size!r}")
    candidate = root / Path(expected_relative_path)
    if not verify_files:
        return expected_relative_path, expected_hash, expected_size, candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _fail(f"{label}_missing_or_link={candidate};error={exc}") from exc
    if resolved != candidate:
        raise _fail(f"{label}_resolved_path_mismatch={resolved};expected={candidate}")
    if _path_is_link_or_reparse(candidate):
        raise _fail(f"{label}_missing_or_link={candidate}")
    actual_hash, actual_size = _hash_file(
        candidate, label, expected_size=expected_size, max_bytes=max_bytes
    )
    if actual_hash != expected_hash:
        raise _fail(f"{label}_hash_mismatch={actual_hash};expected={expected_hash}")
    return expected_relative_path, actual_hash, actual_size, candidate


def _link_input_artifacts(
    records: Any,
    *,
    product_root: Path,
    toolchain_root: Path,
    build_directory: str,
    label: str,
    verify_files: bool,
) -> tuple[tuple[str, str, int, Path], ...]:
    if not isinstance(records, list) or len(records) <= len(LINK_MODULE_ORDER):
        raise _fail(f"{label}_array_invalid")
    result: list[tuple[str, str, int, Path]] = []
    project_objects: list[str] = []
    for index, record in enumerate(records):
        item = _exact_keys(record, {"root", "relative_path", "sha256", "size"}, label)
        root_kind = item["root"]
        relative_path = item["relative_path"]
        pure_relative = PurePosixPath(relative_path) if isinstance(relative_path, str) else None
        if (
            not isinstance(root_kind, str)
            or root_kind not in {"product", "toolchain"}
            or not isinstance(relative_path, str)
            or not relative_path
            or "\\" in relative_path
            or pure_relative is None
            or pure_relative.is_absolute()
            or not pure_relative.parts
            or ":" in pure_relative.parts[0]
            or any(part in {"", ".", ".."} for part in pure_relative.parts)
        ):
            raise _fail(f"{label}_path_invalid={index}")
        if root_kind == "product":
            if index >= len(LINK_MODULE_ORDER):
                raise _fail(f"{label}_unexpected_product_input={index}")
            module = LINK_MODULE_ORDER[index]
            expected_path = _module_output_relative_path(
                module, "native_object", build_directory=build_directory
            )
            if relative_path != expected_path:
                raise _fail(f"{label}_project_object_order_mismatch={index}")
            root = product_root
            project_objects.append(module)
        else:
            if index < len(LINK_MODULE_ORDER):
                raise _fail(f"{label}_project_objects_incomplete={index}")
            root = toolchain_root
        artifact = _module_artifact_record(
            {key: item[key] for key in ("relative_path", "sha256", "size")},
            expected_relative_path=relative_path,
            root=root,
            label=f"{label}[{index}]",
            verify_files=verify_files,
            max_bytes=MAX_LINK_INPUT_BYTES,
        )
        result.append(artifact)
    if project_objects != list(LINK_MODULE_ORDER):
        raise _fail(f"{label}_project_object_set_mismatch")
    return tuple(result)


def _link_input_trace_hash(records: Sequence[Mapping[str, Any]]) -> str:
    payload = [
        [record["root"], record["relative_path"], record["sha256"], record["size"]]
        for record in records
    ]
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _link_input_signature(records: Sequence[Mapping[str, Any]]) -> tuple[tuple[Any, ...], ...]:
    signature: list[tuple[Any, ...]] = []
    for index, record in enumerate(records):
        path = (
            f"$PROJECT_OBJECT:{LINK_MODULE_ORDER[index]}"
            if index < len(LINK_MODULE_ORDER) and record["root"] == "product"
            else f"$TOOLCHAIN/{record['relative_path']}"
        )
        signature.append((path, record["sha256"], record["size"]))
    return tuple(signature)


def _formal_working_directory_relative(build_directory: str) -> str:
    if build_directory == EXPECTED_BUILD_DIRECTORY:
        return "formal/lean"
    return PurePosixPath(build_directory).parent.parent.as_posix()


def _validate_link_input_trace_run(
    record: Any,
    *,
    label: str,
    response_relative_path: str,
    working_directory_record: str,
    linker_driver: Mapping[str, Any],
    linker: Mapping[str, Any],
    traced_inputs: Sequence[Mapping[str, Any]],
) -> None:
    run = _exact_keys(
        record,
        {
            "run_suffix", "driver_path", "driver_sha256", "driver_size",
            "linker_path", "linker_sha256", "linker_size", "arguments",
            "working_directory", "child_exit", "outer_guard_exit", "guard_cleanup",
            "mutex_released", "guard_relative_path", "guard_sha256", "guard_policy_version",
            "guard_stdout_sha256", "guard_stderr_sha256", "input_trace_sha256",
            "minimum_start_free_bytes",
        },
        label,
    )
    if (
        not isinstance(run["run_suffix"], str)
        or not re.fullmatch(
            r"lean-security-link-input-trace-[0-9]+-(?:discover|locked)",
            run["run_suffix"],
            re.ASCII,
        )
        or run["driver_path"] != str(PINNED_LEAN.parent / "clang.exe")
        or run["driver_sha256"] != linker_driver["sha256"]
        or run["driver_size"] != linker_driver["size"]
        or run["linker_path"] != str(PINNED_LEAN.parent / "ld.lld.exe")
        or run["linker_sha256"] != linker["sha256"]
        or run["linker_size"] != linker["size"]
        or run["arguments"] != [
            "-o", "<temporary-output>", f"@{response_relative_path}", "-Wl,-t"
        ]
        or run["working_directory"] != working_directory_record
    ):
        raise _fail(f"{label}_identity_mismatch")
    for field in ("child_exit", "outer_guard_exit"):
        value = run[field]
        if not isinstance(value, int) or isinstance(value, bool) or value != 0:
            raise _fail(f"{label}_{field}_mismatch={value!r}")
    if run["guard_cleanup"] != "PASS" or run["mutex_released"] is not True:
        raise _fail(f"{label}_cleanup_mismatch")
    if (
        run["guard_relative_path"] != PROVENANCE_GUARD_RELATIVE_PATH
        or run["guard_sha256"] != PROVENANCE_GUARD_SHA256
        or run["guard_policy_version"] != "v4"
    ):
        raise _fail(f"{label}_guard_identity_mismatch")
    if (
        not isinstance(run["minimum_start_free_bytes"], int)
        or isinstance(run["minimum_start_free_bytes"], bool)
        or run["minimum_start_free_bytes"] != PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES
    ):
        raise _fail(f"{label}_minimum_start_free_bytes_mismatch")
    for field in (
        "driver_sha256", "linker_sha256", "guard_sha256", "guard_stdout_sha256",
        "guard_stderr_sha256", "input_trace_sha256",
    ):
        _hash_text(run[field], f"{label}.{field}")
    if (
        not isinstance(run["driver_size"], int)
        or isinstance(run["driver_size"], bool)
        or run["driver_size"] <= 0
        or not isinstance(run["linker_size"], int)
        or isinstance(run["linker_size"], bool)
        or run["linker_size"] <= 0
    ):
        raise _fail(f"{label}_driver_size_invalid")
    if run["input_trace_sha256"] != _link_input_trace_hash(traced_inputs):
        raise _fail(f"{label}_input_trace_mismatch")


def _expected_olean_roles(root: Path, stem_relative: str, label: str) -> set[str]:
    main = root / Path(stem_relative + ".olean")
    server = root / Path(stem_relative + ".olean.server")
    private = root / Path(stem_relative + ".olean.private")
    for candidate in (main, server, private):
        if _path_is_link_or_reparse(candidate):
            raise _fail(f"{label}_missing_or_link={candidate}")
    if not main.is_file():
        raise _fail(f"{label}_missing_or_link={main}")
    roles = {"olean"}
    if server.exists():
        if not server.is_file():
            raise _fail(f"{label}_not_file={server}")
        roles.add("server")
    if private.exists():
        if not private.is_file():
            raise _fail(f"{label}_not_file={private}")
        if "server" not in roles:
            raise _fail(f"{label}_private_without_server={private}")
        roles.add("private")
    return roles


def _verify_link_response(
    path: Path, *, build_directory: str, toolchain_root: Path
) -> tuple[str, ...]:
    return _validate_link_response_arguments(
        _read_link_response_arguments(path),
        build_directory=build_directory,
        toolchain_root=toolchain_root,
    )


def _read_link_response_arguments(path: Path) -> tuple[str, ...]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        if not lines or any(not line for line in lines):
            raise ValueError("empty_response_line")
        arguments = [json.loads(line) for line in lines]
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise _fail(f"module_provenance_link_response_invalid={path};error={exc}") from exc
    if any(not isinstance(argument, str) for argument in arguments):
        raise _fail("module_provenance_link_response_argument_invalid")
    return tuple(arguments)


def _validate_link_response_arguments(
    arguments: Sequence[str], *, build_directory: str, toolchain_root: Path
) -> tuple[str, ...]:
    if any(not isinstance(argument, str) for argument in arguments):
        raise _fail("module_provenance_link_response_argument_invalid")
    expected_objects = [
        str(
            (
                PRODUCT_ROOT
                / Path(
                    _module_output_relative_path(
                        module, "native_object", build_directory=build_directory
                    )
                )
            ).resolve()
        ).casefold()
        for module in LINK_MODULE_ORDER
    ]
    actual_objects = arguments[: len(expected_objects)]
    if not all(isinstance(argument, str) for argument in actual_objects) or [
        argument.casefold() for argument in actual_objects
    ] != expected_objects:
        raise _fail("module_provenance_link_response_object_order_mismatch")
    tail = arguments[len(expected_objects):]
    if len(tail) != len(EXPECTED_LINK_RESPONSE_TAIL):
        raise _fail("module_provenance_link_response_argument_count_mismatch")
    normalized_tail: list[str] = []
    expected_paths = {
        5: (toolchain_root / "lib" / "lean", "<LEAN_LIB>"),
        7: (toolchain_root, "<TOOLCHAIN>"),
        9: (toolchain_root / "lib", "<TOOLCHAIN_LIB>"),
    }
    for index, (actual, expected) in enumerate(
        zip(tail, EXPECTED_LINK_RESPONSE_TAIL, strict=True)
    ):
        path_entry = expected_paths.get(index)
        if path_entry is None:
            if actual != expected:
                raise _fail(f"module_provenance_link_response_argument_mismatch={index}")
            normalized_tail.append(actual)
            continue
        expected_path, token = path_entry
        try:
            resolved_actual = Path(actual).resolve(strict=True)
            resolved_expected = expected_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise _fail(f"module_provenance_link_response_search_path_invalid={index};error={exc}") from exc
        if resolved_actual != resolved_expected or _path_is_link_or_reparse(expected_path):
            raise _fail(f"module_provenance_link_response_search_path_mismatch={index}")
        normalized_tail.append(token)
    normalized = [f"$PROJECT_OBJECT:{module}" for module in LINK_MODULE_ORDER]
    normalized.extend(normalized_tail)
    return tuple(normalized)


def _link_fingerprint(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{16}", value, re.ASCII) is None:
        raise _fail(label)
    return value


def _verify_link_trace(path: Path, *, build_directory: str) -> dict[str, Any]:
    try:
        trace = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise _fail(f"module_provenance_link_trace_invalid={path};error={exc}") from exc
    logs = trace.get("log") if isinstance(trace, dict) else None
    if not isinstance(logs, list) or not logs or not all(
        isinstance(item, dict) and isinstance(item.get("message"), str) for item in logs
    ):
        raise _fail("module_provenance_link_trace_log_invalid")
    expected_binary = str(
        (PRODUCT_ROOT / Path(_binary_relative_path(build_directory))).resolve()
    ).casefold()
    expected_response = str(
        (PRODUCT_ROOT / Path(_link_response_relative_path(build_directory))).resolve()
    ).casefold()
    expected_linker = str(PINNED_LEAN.parent / "clang.exe").casefold()
    if not any(
        expected_linker in item["message"].casefold()
        and expected_binary in item["message"].casefold()
        and ("@" + expected_response) in item["message"].casefold()
        for item in logs
    ):
        raise _fail("module_provenance_link_trace_command_mismatch")
    inputs = trace.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise _fail("module_provenance_link_trace_inputs_invalid")
    if any(
        not isinstance(entry, list)
        or len(entry) != 2
        or not isinstance(entry[0], str)
        for entry in inputs
    ):
        raise _fail("module_provenance_link_trace_input_entry_invalid")
    expected_input_names = {
        "BlindLedger.SecurityExecutable:linkInfo",
        EXPECTED_LINK_EXE_ARGUMENT,
        EXPECTED_LINK_COMPILER_ID,
        EXPECTED_LINK_TARGET_TRIPLE,
    }
    input_by_name: dict[str, Any] = {}
    for entry in inputs:
        name = entry[0]
        if name in input_by_name:
            raise _fail("module_provenance_link_trace_inputs_duplicate")
        input_by_name[name] = entry[1]
    if len(inputs) != 4 or set(input_by_name) != expected_input_names:
        raise _fail("module_provenance_link_trace_input_set_mismatch")

    target_fingerprint = _link_fingerprint(
        input_by_name[EXPECTED_LINK_TARGET_TRIPLE],
        "module_provenance_link_trace_target_triple_mismatch",
    )
    if target_fingerprint != EXPECTED_LINK_TARGET_FINGERPRINT:
        raise _fail("module_provenance_link_trace_target_triple_mismatch")
    compiler_fingerprint = _link_fingerprint(
        input_by_name[EXPECTED_LINK_COMPILER_ID],
        "module_provenance_link_trace_compiler_identity_mismatch",
    )
    if compiler_fingerprint != EXPECTED_LINK_COMPILER_FINGERPRINT:
        raise _fail("module_provenance_link_trace_compiler_identity_mismatch")
    exe_arguments_fingerprint = _link_fingerprint(
        input_by_name[EXPECTED_LINK_EXE_ARGUMENT],
        "module_provenance_link_trace_executable_arguments_mismatch",
    )
    if exe_arguments_fingerprint != EXPECTED_LINK_EXE_ARGUMENT_FINGERPRINT:
        raise _fail("module_provenance_link_trace_executable_arguments_mismatch")

    dependencies = input_by_name["BlindLedger.SecurityExecutable:linkInfo"]
    if not isinstance(dependencies, list) or len(dependencies) != 3:
        raise _fail("module_provenance_link_trace_dependencies_invalid")
    dependency_by_name: dict[str, Any] = {}
    for dependency in dependencies:
        if (
            not isinstance(dependency, list)
            or len(dependency) != 2
            or not isinstance(dependency[0], str)
            or dependency[0] in dependency_by_name
        ):
            raise _fail("module_provenance_link_trace_dependencies_invalid")
        dependency_by_name[dependency[0]] = dependency[1]
    if set(dependency_by_name) != {
        "Module.moreLinkObjs",
        "Module.moreLinkLibs",
        EXPECTED_MODULE_LINK_ARGUMENT,
    }:
        raise _fail("module_provenance_link_trace_dependencies_invalid")
    if _link_fingerprint(
        dependency_by_name["Module.moreLinkLibs"],
        "module_provenance_link_trace_libraries_mismatch",
    ) != EXPECTED_MODULE_LINK_LIBRARIES_FINGERPRINT:
        raise _fail("module_provenance_link_trace_libraries_mismatch")
    module_arguments_fingerprint = _link_fingerprint(
        dependency_by_name[EXPECTED_MODULE_LINK_ARGUMENT],
        "module_provenance_link_trace_module_arguments_mismatch",
    )
    if module_arguments_fingerprint != EXPECTED_MODULE_LINK_ARGUMENT_FINGERPRINT:
        raise _fail("module_provenance_link_trace_module_arguments_mismatch")

    object_group = dependency_by_name["Module.moreLinkObjs"]
    if not isinstance(object_group, list):
        raise _fail("module_provenance_link_trace_objects_missing_or_duplicate")
    if any(
        not isinstance(entry, list)
        or len(entry) != 2
        or not isinstance(entry[0], str)
        or not entry[0]
        for entry in object_group
    ):
        raise _fail("module_provenance_link_trace_object_entry_invalid")
    object_fingerprints = [
        _link_fingerprint(
            entry[1], "module_provenance_link_trace_object_entry_invalid"
        )
        for entry in object_group
    ]
    actual_paths = [entry[0].casefold() for entry in object_group]
    expected_paths = [
        str(
            (
                PRODUCT_ROOT
                / Path(
                    _module_output_relative_path(
                        module, "native_object", build_directory=build_directory
                    )
                )
            ).resolve()
        ).casefold()
        for module in LINK_MODULE_ORDER
    ]
    if actual_paths != expected_paths:
        raise _fail("module_provenance_link_trace_object_order_mismatch")
    if len(set(actual_paths)) != len(actual_paths):
        raise _fail("module_provenance_link_trace_objects_missing_or_duplicate")
    return {
        "compiler_id": EXPECTED_LINK_COMPILER_ID,
        "compiler_fingerprint": compiler_fingerprint,
        "target_triple": EXPECTED_LINK_TARGET_TRIPLE,
        "target_fingerprint": target_fingerprint,
        "executable_arguments_fingerprint": exe_arguments_fingerprint,
        "module_libraries_fingerprint": EXPECTED_MODULE_LINK_LIBRARIES_FINGERPRINT,
        "module_arguments_fingerprint": module_arguments_fingerprint,
        "object_fingerprints": tuple(object_fingerprints),
    }


def _compare_link_trace_identities(original: Mapping[str, Any], reproduced: Mapping[str, Any]) -> None:
    if original != reproduced:
        raise _fail("module_provenance_link_trace_fingerprint_reproduction_mismatch")


def _module_olean_artifacts(
    records: Any,
    *,
    module: str,
    relative_stem: str,
    root: Path,
    label: str,
    verify_files: bool,
) -> tuple[tuple[str, str, int, Path], ...]:
    if not isinstance(records, list):
        raise _fail(f"{label}_olean_artifacts_array_required")
    roles: dict[str, Any] = {}
    for record in records:
        item = _exact_keys(record, {"role", "relative_path", "sha256", "size"}, label)
        role = item["role"]
        if not isinstance(role, str) or role in roles:
            raise _fail(f"{label}_olean_role_duplicate_or_invalid={role!r}")
        roles[role] = item
    if "olean" not in roles or not set(roles) <= {"olean", "server", "private"}:
        raise _fail(f"{label}_olean_roles_invalid={sorted(roles)!r}")
    expected_roles = (
        _expected_olean_roles(root, relative_stem, label) if verify_files else set(roles)
    )
    if set(roles) != expected_roles:
        raise _fail(
            f"{label}_olean_roles_mismatch;actual={sorted(roles)!r};expected={sorted(expected_roles)!r}"
        )
    verified: list[tuple[str, str, int, Path]] = []
    for role in ("olean", "server", "private"):
        if role not in expected_roles:
            continue
        suffix = ".olean" if role == "olean" else f".olean.{role}"
        expected_path = f"{relative_stem}{suffix}"
        checked = _module_artifact_record(
            {
                key: roles[role][key]
                for key in ("relative_path", "sha256", "size")
            },
            expected_relative_path=expected_path, root=root,
            label=f"{label}.{module}.{role}", verify_files=verify_files,
        )
        verified.append(checked)
    return tuple(verified)


def _validate_module_provenance_receipt(
    provenance: Any,
    receipt: Mapping[str, Any],
    receipt_hash: str,
    *,
    verify_files: bool,
    derived_import_graph: Mapping[str, Sequence[str]] | None = None,
    derived_import_paths: Mapping[str, str] | None = None,
    derived_import_graph_sha256: str | None = None,
) -> tuple[str, tuple[tuple[str, str, int], ...], tuple[Path, ...], str, str]:
    _exact_keys(
        provenance,
        {
            "receipt_version", "schema_id", "build_id", "artifact_receipt_sha256",
            "toolchain", "source_sha256", "tools", "binary", "build_result",
            "checker", "inspector", "link", "modules", "toolchain_modules",
        },
        "module_provenance.root",
    )
    version = provenance["receipt_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != MODULE_PROVENANCE_VERSION:
        raise _fail(f"module_provenance_version_invalid={version!r}")
    if provenance["schema_id"] != MODULE_PROVENANCE_SCHEMA_ID:
        raise _fail(f"module_provenance_schema_mismatch={provenance['schema_id']!r}")
    if provenance["build_id"] != BUILD_ID or provenance["toolchain"] != PINNED_TOOLCHAIN:
        raise _fail("module_provenance_identity_mismatch")
    if provenance["artifact_receipt_sha256"] != receipt_hash:
        raise _fail(
            "module_provenance_stale_receipt="
            f"{provenance['artifact_receipt_sha256']!r};expected={receipt_hash!r}"
        )
    source_hashes = provenance["source_sha256"]
    if not isinstance(source_hashes, dict) or source_hashes != receipt["source_sha256"]:
        raise _fail("module_provenance_source_set_or_hash_mismatch")
    if provenance["tools"] != receipt["tools"]:
        raise _fail("module_provenance_tool_identity_mismatch")
    binary = _exact_keys(provenance["binary"], {"relative_path", "sha256", "size"}, "module_provenance.binary")
    if binary != receipt["binary"]:
        raise _fail("module_provenance_binary_mismatch")

    build_result = _exact_keys(
        provenance["build_result"],
        {
            "rebuild_mode", "rebuild_directory", "lake_target", "lake_rehash",
            "lake_exit", "axiom_check_exit", "checker_exit", "guard_exit",
            "guard_cleanup", "mutex_released", "guard_relative_path", "guard_sha256",
            "guard_policy_version", "binary_reproduced",
            "all_outputs_reproduced", "reproduced_binary",
            "output_inventory_sha256", "guard_run_suffix", "stdout_sha256", "stderr_sha256",
            "minimum_start_free_bytes",
        },
        "module_provenance.build_result",
    )
    if build_result["rebuild_mode"] != "isolated-empty-build-directory":
        raise _fail("module_provenance_rebuild_mode_mismatch")
    if (
        build_result["guard_relative_path"] != PROVENANCE_GUARD_RELATIVE_PATH
        or build_result["guard_sha256"] != PROVENANCE_GUARD_SHA256
        or build_result["guard_policy_version"] != "v4"
    ):
        raise _fail("module_provenance_guard_identity_mismatch")
    _hash_text(build_result["guard_sha256"], "module_provenance.guard")
    rebuild_directory = build_result["rebuild_directory"]
    if not isinstance(rebuild_directory, str) or not re.fullmatch(
        r"formal/lean/\.lake/module-provenance-[A-Za-z0-9-]+/workspace/\.lake/build-v2",
        rebuild_directory,
        re.ASCII,
    ):
        raise _fail(f"module_provenance_rebuild_directory_invalid={rebuild_directory!r}")
    if build_result["lake_target"] != "blind_security_arithmetic_v2":
        raise _fail("module_provenance_lake_target_mismatch")
    if build_result["lake_rehash"] is not True or build_result["mutex_released"] is not True:
        raise _fail("module_provenance_build_flag_mismatch")
    if build_result["guard_cleanup"] != "PASS":
        raise _fail("module_provenance_guard_cleanup_mismatch")
    if (
        not isinstance(build_result["minimum_start_free_bytes"], int)
        or isinstance(build_result["minimum_start_free_bytes"], bool)
        or build_result["minimum_start_free_bytes"] != PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES
    ):
        raise _fail("module_provenance_minimum_start_free_bytes_mismatch")
    for field in ("lake_exit", "axiom_check_exit", "checker_exit", "guard_exit"):
        value = build_result[field]
        if not isinstance(value, int) or isinstance(value, bool) or value != 0:
            raise _fail(f"module_provenance_{field}_mismatch={value!r}")
    if build_result["binary_reproduced"] is not True or build_result["all_outputs_reproduced"] is not True:
        raise _fail("module_provenance_outputs_not_reproduced")
    reproduced_binary = _module_artifact_record(
        build_result["reproduced_binary"],
        expected_relative_path=_binary_relative_path(rebuild_directory),
        root=PRODUCT_ROOT.resolve(strict=True),
        label="module_provenance.reproduced_binary",
        verify_files=verify_files,
    )
    if (
        reproduced_binary[1] != receipt["binary"]["sha256"]
        or reproduced_binary[2] != receipt["binary"]["size"]
    ):
        raise _fail("module_provenance_reproduced_binary_mismatch")
    verified_artifacts: list[tuple[str, str, int]] = [reproduced_binary[:3]]
    if not isinstance(build_result["guard_run_suffix"], str) or not re.fullmatch(
        r"lean-security-module-provenance-[0-9]+", build_result["guard_run_suffix"], re.ASCII
    ):
        raise _fail("module_provenance_guard_run_suffix_invalid")
    _hash_text(build_result["stdout_sha256"], "module_provenance.build_stdout")
    _hash_text(build_result["stderr_sha256"], "module_provenance.build_stderr")

    checker = _exact_keys(
        provenance["checker"],
        {
            "target_module", "replay_mode", "checked_modules",
            "loaded_project_modules", "loaded_toolchain_modules",
            "toolchain_import_roots", "inspection_roots", "run",
        },
        "module_provenance.checker",
    )
    checker_scope = {
        field: checker[field]
        for field in (
            "target_module", "replay_mode", "checked_modules",
            "loaded_project_modules", "toolchain_import_roots", "inspection_roots",
        )
    }
    if checker_scope != {
        "target_module": EXPECTED_CHECKER_MODULE,
        "replay_mode": "imported-environment-replay",
        "checked_modules": [EXPECTED_CHECKER_MODULE],
        "loaded_project_modules": list(CHECKER_PROJECT_MODULES),
        "toolchain_import_roots": list(TOOLCHAIN_IMPORT_ROOTS),
        "inspection_roots": list(IMPORT_GRAPH_ROOTS),
    }:
        raise _fail("module_provenance_checker_scope_mismatch")
    loaded_toolchain_modules = checker["loaded_toolchain_modules"]
    if (
        not isinstance(loaded_toolchain_modules, list)
        or any(not _valid_module_name(module) for module in loaded_toolchain_modules)
        or loaded_toolchain_modules != sorted(set(loaded_toolchain_modules))
    ):
        raise _fail("module_provenance_checker_toolchain_modules_invalid")
    loaded_project_module_set = set(checker["loaded_project_modules"])
    loaded_toolchain_module_set = set(loaded_toolchain_modules)
    checker_run = _exact_keys(
        checker["run"],
        {
            "run_suffix", "executable_path", "executable_sha256", "executable_size",
            "arguments", "working_directory", "lean_path", "child_exit",
            "outer_guard_exit", "guard_cleanup", "mutex_released",
            "guard_relative_path", "guard_sha256", "guard_policy_version",
            "guard_stdout_sha256", "guard_stderr_sha256",
            "input_manifest_sha256", "input_inventory_sha256", "import_graph_sha256",
            "minimum_start_free_bytes",
        },
        "module_provenance.checker.run",
    )
    checker_tool = receipt["tools"]["leanchecker"]
    if (
        checker_run["executable_path"] != str(PINNED_LEANCHECKER)
        or checker_run["executable_sha256"] != checker_tool["sha256"]
        or checker_run["executable_size"] != checker_tool["size"]
        or checker_run["arguments"] != [EXPECTED_CHECKER_MODULE]
        or checker_run["working_directory"] != "formal/lean"
        or checker_run["lean_path"] != "formal/lean/.lake/build-v2/lib/lean"
    ):
        raise _fail("module_provenance_checker_run_identity_mismatch")
    if not isinstance(checker_run["run_suffix"], str) or not re.fullmatch(
        r"lean-security-independent-checker-[0-9]+", checker_run["run_suffix"], re.ASCII
    ):
        raise _fail("module_provenance_checker_run_suffix_invalid")
    for field in ("child_exit", "outer_guard_exit"):
        value = checker_run[field]
        if not isinstance(value, int) or isinstance(value, bool) or value != 0:
            raise _fail(f"module_provenance_checker_{field}_mismatch={value!r}")
    if checker_run["guard_cleanup"] != "PASS" or checker_run["mutex_released"] is not True:
        raise _fail("module_provenance_checker_guard_cleanup_mismatch")
    if (
        not isinstance(checker_run["minimum_start_free_bytes"], int)
        or isinstance(checker_run["minimum_start_free_bytes"], bool)
        or checker_run["minimum_start_free_bytes"] != PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES
    ):
        raise _fail("module_provenance_checker_minimum_start_free_bytes_mismatch")
    if (
        checker_run["guard_relative_path"] != PROVENANCE_GUARD_RELATIVE_PATH
        or checker_run["guard_sha256"] != PROVENANCE_GUARD_SHA256
        or checker_run["guard_policy_version"] != "v4"
    ):
        raise _fail("module_provenance_checker_guard_identity_mismatch")
    for field in (
        "executable_sha256", "guard_sha256", "guard_stdout_sha256", "guard_stderr_sha256",
        "input_manifest_sha256", "input_inventory_sha256", "import_graph_sha256",
    ):
        _hash_text(checker_run[field], f"module_provenance.checker.{field}")
    if (
        not isinstance(checker_run["executable_size"], int)
        or isinstance(checker_run["executable_size"], bool)
        or checker_run["executable_size"] <= 0
    ):
        raise _fail("module_provenance_checker_executable_size_invalid")

    product_root = PRODUCT_ROOT.resolve(strict=True)
    toolchain_root = PINNED_LEAN.parent.parent.resolve(strict=True)
    inspector = _exact_keys(
        provenance["inspector"], {"script", "roots", "run"}, "module_provenance.inspector"
    )
    if inspector["roots"] != list(IMPORT_GRAPH_ROOTS):
        raise _fail("module_provenance_inspector_roots_mismatch")
    inspector_script = _module_artifact_record(
        inspector["script"],
        expected_relative_path=IMPORT_GRAPH_SCRIPT_RELATIVE_PATH,
        root=product_root,
        label="module_provenance.inspector.script",
        verify_files=verify_files,
    )
    inspector_run = _exact_keys(
        inspector["run"],
        {
            "run_suffix", "executable_path", "executable_sha256", "executable_size",
            "arguments", "working_directory", "lean_path", "child_exit",
            "outer_guard_exit", "guard_cleanup", "mutex_released",
            "guard_relative_path", "guard_sha256", "guard_policy_version",
            "guard_stdout_sha256", "guard_stderr_sha256", "graph_sha256",
            "minimum_start_free_bytes",
        },
        "module_provenance.inspector.run",
    )
    lean_tool = receipt["tools"]["lean"]
    if (
        inspector_run["executable_path"] != str(PINNED_LEAN)
        or inspector_run["executable_sha256"] != lean_tool["sha256"]
        or inspector_run["executable_size"] != lean_tool["size"]
        or inspector_run["arguments"] != ["--run", "../../tools/direct_mask_contract/olean_imports.lean"]
        or inspector_run["working_directory"] != "formal/lean"
        or inspector_run["lean_path"] != "formal/lean/.lake/build-v2/lib/lean"
    ):
        raise _fail("module_provenance_inspector_run_identity_mismatch")
    if not isinstance(inspector_run["run_suffix"], str) or not re.fullmatch(
        r"lean-security-import-graph-[0-9]+", inspector_run["run_suffix"], re.ASCII
    ):
        raise _fail("module_provenance_inspector_run_suffix_invalid")
    for field in ("child_exit", "outer_guard_exit"):
        value = inspector_run[field]
        if not isinstance(value, int) or isinstance(value, bool) or value != 0:
            raise _fail(f"module_provenance_inspector_{field}_mismatch={value!r}")
    if inspector_run["guard_cleanup"] != "PASS" or inspector_run["mutex_released"] is not True:
        raise _fail("module_provenance_inspector_guard_cleanup_mismatch")
    if (
        not isinstance(inspector_run["minimum_start_free_bytes"], int)
        or isinstance(inspector_run["minimum_start_free_bytes"], bool)
        or inspector_run["minimum_start_free_bytes"] != PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES
    ):
        raise _fail("module_provenance_inspector_minimum_start_free_bytes_mismatch")
    if (
        inspector_run["guard_relative_path"] != PROVENANCE_GUARD_RELATIVE_PATH
        or inspector_run["guard_sha256"] != PROVENANCE_GUARD_SHA256
        or inspector_run["guard_policy_version"] != "v4"
    ):
        raise _fail("module_provenance_inspector_guard_identity_mismatch")
    for field in (
        "executable_sha256", "guard_sha256", "guard_stdout_sha256",
        "guard_stderr_sha256", "graph_sha256"
    ):
        _hash_text(inspector_run[field], f"module_provenance.inspector.{field}")
    if inspector_run["graph_sha256"] != checker_run["import_graph_sha256"]:
        raise _fail("module_provenance_checker_import_graph_mismatch")
    if (
        not isinstance(inspector_run["executable_size"], int)
        or isinstance(inspector_run["executable_size"], bool)
        or inspector_run["executable_size"] <= 0
    ):
        raise _fail("module_provenance_inspector_executable_size_invalid")

    modules = provenance["modules"]
    if not isinstance(modules, list) or [
        record.get("name") if isinstance(record, dict) else None for record in modules
    ] != list(LINK_MODULE_ORDER):
        raise _fail("module_provenance_module_order_or_set_mismatch")
    verified_artifacts.append(inspector_script[:3])
    checker_paths: list[Path] = []
    for record, module in zip(modules, LINK_MODULE_ORDER, strict=True):
        _exact_keys(
            record,
            {
                "name", "source_path", "source_sha256", "imports", "olean_imports",
                "olean_files", "generated_c", "native_object",
                "reproduced_olean_files", "reproduced_generated_c", "reproduced_native_object",
            },
            f"module_provenance.modules.{module}",
        )
        source_path = _module_source_relative_path(module)
        if record["source_path"] != source_path:
            raise _fail(f"module_provenance_source_path_mismatch={module}")
        if record["source_sha256"] != receipt["source_sha256"].get(source_path):
            raise _fail(f"module_provenance_source_hash_mismatch={module}")
        if record["imports"] != list(PROJECT_MODULE_IMPORTS[module]):
            raise _fail(f"module_provenance_imports_mismatch={module}")
        olean_imports = record["olean_imports"]
        if (
            not isinstance(olean_imports, list)
            or any(not _valid_module_name(name) for name in olean_imports)
            or len(set(olean_imports)) != len(olean_imports)
            or not set(record["imports"]) <= set(olean_imports)
        ):
            raise _fail(f"module_provenance_olean_imports_invalid={module}")
        local_oleans = _module_olean_artifacts(
            record["olean_files"], module=module,
            relative_stem=_module_output_relative_path(module, "olean")[:-len(".olean")],
            root=product_root, label="module_provenance.local", verify_files=verify_files,
        )
        reproduced_oleans = _module_olean_artifacts(
            record["reproduced_olean_files"], module=module,
            relative_stem=_module_output_relative_path(
                module, "olean", build_directory=rebuild_directory
            )[:-len(".olean")],
            root=product_root, label="module_provenance.reproduced", verify_files=verify_files,
        )
        original_olean_signature = tuple(
            (Path(relative_path).name, digest, size)
            for relative_path, digest, size, _ in local_oleans
        )
        reproduced_olean_signature = tuple(
            (Path(relative_path).name, digest, size)
            for relative_path, digest, size, _ in reproduced_oleans
        )
        if original_olean_signature != reproduced_olean_signature:
            raise _fail(f"module_provenance_reproduced_olean_mismatch={module}")
        for relative_path, digest, size, path in local_oleans:
            verified_artifacts.append((relative_path, digest, size))
            if module in loaded_project_module_set:
                checker_paths.append(path)
        verified_artifacts.extend(item[:3] for item in reproduced_oleans)
        for kind, reproduced_field in (
            ("generated_c", "reproduced_generated_c"),
            ("native_object", "reproduced_native_object"),
        ):
            original = _module_artifact_record(
                record[kind],
                expected_relative_path=_module_output_relative_path(module, kind),
                root=product_root,
                label=f"module_provenance.local.{module}.{kind}",
                verify_files=verify_files,
            )
            reproduced = _module_artifact_record(
                record[reproduced_field],
                expected_relative_path=_module_output_relative_path(
                    module, kind, build_directory=rebuild_directory
                ),
                root=product_root,
                label=f"module_provenance.reproduced.{module}.{kind}",
                verify_files=verify_files,
            )
            if original[1:3] != reproduced[1:3]:
                raise _fail(f"module_provenance_reproduced_output_mismatch={module}.{kind}")
            verified_artifacts.extend((original[:3], reproduced[:3]))

    link = _exact_keys(
        provenance["link"],
        {
            "entry_module", "target_triple", "module_order", "response_file",
            "response_arguments", "reproduced_response_arguments",
            "link_trace", "reproduced_response_file", "reproduced_link_trace",
            "linker_driver", "linker", "resolved_inputs", "reproduced_resolved_inputs",
            "link_input_trace_run", "reproduced_link_input_trace_run",
        },
        "module_provenance.link",
    )
    if link["entry_module"] != "BlindLedger.SecurityExecutable":
        raise _fail("module_provenance_link_entry_mismatch")
    if link["target_triple"] != EXPECTED_LINK_TARGET_TRIPLE:
        raise _fail("module_provenance_target_triple_mismatch")
    if link["module_order"] != list(LINK_MODULE_ORDER):
        raise _fail("module_provenance_link_order_mismatch")
    response_arguments = link["response_arguments"]
    reproduced_response_arguments = link["reproduced_response_arguments"]
    if (
        not isinstance(response_arguments, list)
        or not isinstance(reproduced_response_arguments, list)
        or any(not isinstance(argument, str) for argument in response_arguments)
        or any(not isinstance(argument, str) for argument in reproduced_response_arguments)
    ):
        raise _fail("module_provenance_link_response_argument_vector_invalid")
    response = _module_artifact_record(
        link["response_file"],
        expected_relative_path=_link_response_relative_path(EXPECTED_BUILD_DIRECTORY),
        root=product_root, label="module_provenance.link.response_file", verify_files=verify_files,
    )
    verified_artifacts.append(response[:3])
    reproduced_response = _module_artifact_record(
        link["reproduced_response_file"],
        expected_relative_path=_link_response_relative_path(rebuild_directory),
        root=product_root,
        label="module_provenance.link.reproduced_response_file",
        verify_files=verify_files,
    )
    verified_artifacts.append(reproduced_response[:3])
    link_trace = _module_artifact_record(
        link["link_trace"],
        expected_relative_path=_link_trace_relative_path(EXPECTED_BUILD_DIRECTORY),
        root=product_root, label="module_provenance.link.trace", verify_files=verify_files,
    )
    verified_artifacts.append(link_trace[:3])
    reproduced_link_trace = _module_artifact_record(
        link["reproduced_link_trace"],
        expected_relative_path=_link_trace_relative_path(rebuild_directory),
        root=product_root,
        label="module_provenance.link.reproduced_trace",
        verify_files=verify_files,
    )
    verified_artifacts.append(reproduced_link_trace[:3])
    original_response_args = _validate_link_response_arguments(
        response_arguments,
        build_directory=EXPECTED_BUILD_DIRECTORY,
        toolchain_root=toolchain_root,
    )
    reproduced_response_args = _validate_link_response_arguments(
        reproduced_response_arguments,
        build_directory=rebuild_directory,
        toolchain_root=toolchain_root,
    )
    if original_response_args != reproduced_response_args:
        raise _fail("module_provenance_link_response_reproduction_mismatch")
    if verify_files:
        verified_original_response_args = _verify_link_response(
            response[3], build_directory=EXPECTED_BUILD_DIRECTORY, toolchain_root=toolchain_root
        )
        verified_reproduced_response_args = _verify_link_response(
            reproduced_response[3], build_directory=rebuild_directory, toolchain_root=toolchain_root
        )
        if verified_original_response_args != verified_reproduced_response_args:
            raise _fail("module_provenance_link_response_reproduction_mismatch")
        if (
            _read_link_response_arguments(response[3]) != tuple(response_arguments)
            or _read_link_response_arguments(reproduced_response[3])
            != tuple(reproduced_response_arguments)
        ):
            raise _fail("module_provenance_link_response_record_mismatch")
        original_trace_identity = _verify_link_trace(
            link_trace[3], build_directory=EXPECTED_BUILD_DIRECTORY
        )
        reproduced_trace_identity = _verify_link_trace(
            reproduced_link_trace[3], build_directory=rebuild_directory
        )
        _compare_link_trace_identities(original_trace_identity, reproduced_trace_identity)
    linker_driver = _module_artifact_record(
        link["linker_driver"],
        expected_relative_path=EXPECTED_LINKER_DRIVER_RELATIVE_PATH,
        root=toolchain_root,
        label="module_provenance.link.linker_driver",
        verify_files=verify_files,
    )
    linker = _module_artifact_record(
        link["linker"],
        expected_relative_path=EXPECTED_LINKER_RELATIVE_PATH,
        root=toolchain_root,
        label="module_provenance.link.linker",
        verify_files=verify_files,
    )
    verified_artifacts.append((f"toolchain/{linker_driver[0]}", *linker_driver[1:3]))
    verified_artifacts.append((f"toolchain/{linker[0]}", *linker[1:3]))
    resolved_inputs = link["resolved_inputs"]
    reproduced_resolved_inputs = link["reproduced_resolved_inputs"]
    original_link_inputs = _link_input_artifacts(
        resolved_inputs,
        product_root=product_root,
        toolchain_root=toolchain_root,
        build_directory=EXPECTED_BUILD_DIRECTORY,
        label="module_provenance.link.resolved_inputs",
        verify_files=verify_files,
    )
    reproduced_link_inputs = _link_input_artifacts(
        reproduced_resolved_inputs,
        product_root=product_root,
        toolchain_root=toolchain_root,
        build_directory=rebuild_directory,
        label="module_provenance.link.reproduced_resolved_inputs",
        verify_files=verify_files,
    )
    if _link_input_signature(resolved_inputs) != _link_input_signature(reproduced_resolved_inputs):
        raise _fail("module_provenance_link_input_reproduction_mismatch")
    for record, artifact in zip(resolved_inputs, original_link_inputs, strict=True):
        verified_artifacts.append((f"{record['root']}/{artifact[0]}", artifact[1], artifact[2]))
    for record, artifact in zip(reproduced_resolved_inputs, reproduced_link_inputs, strict=True):
        verified_artifacts.append((f"{record['root']}/{artifact[0]}", artifact[1], artifact[2]))
    _validate_link_input_trace_run(
        link["link_input_trace_run"],
        label="module_provenance.link.link_input_trace_run",
        response_relative_path=_link_response_relative_path(EXPECTED_BUILD_DIRECTORY),
        working_directory_record=_formal_working_directory_relative(EXPECTED_BUILD_DIRECTORY),
        linker_driver={"sha256": linker_driver[1], "size": linker_driver[2]},
        linker={"sha256": linker[1], "size": linker[2]},
        traced_inputs=resolved_inputs,
    )
    _validate_link_input_trace_run(
        link["reproduced_link_input_trace_run"],
        label="module_provenance.link.reproduced_link_input_trace_run",
        response_relative_path=_link_response_relative_path(rebuild_directory),
        working_directory_record=_formal_working_directory_relative(rebuild_directory),
        linker_driver={"sha256": linker_driver[1], "size": linker_driver[2]},
        linker={"sha256": linker[1], "size": linker[2]},
        traced_inputs=reproduced_resolved_inputs,
    )

    toolchain_modules = provenance["toolchain_modules"]
    if not isinstance(toolchain_modules, list):
        raise _fail("module_provenance_toolchain_modules_array_required")
    toolchain_names = [
        record.get("name") if isinstance(record, dict) else None
        for record in toolchain_modules
    ]
    if any(
        not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*", name, re.ASCII)
        for name in toolchain_names
    ):
        raise _fail("module_provenance_toolchain_module_name_invalid")
    if toolchain_names != sorted(set(toolchain_names)) or not {
        *TOOLCHAIN_IMPORT_ROOTS,
        "Lean",
    } <= set(toolchain_names):
        raise _fail("module_provenance_toolchain_module_set_invalid")
    toolchain_by_name: dict[str, dict[str, Any]] = {}
    for record in toolchain_modules:
        module = record["name"]
        _exact_keys(
            record, {"name", "imports", "olean_files"},
            f"module_provenance.toolchain_modules.{module}",
        )
        imports = record["imports"]
        if not isinstance(imports, list) or any(not _valid_module_name(name) for name in imports):
            raise _fail(f"module_provenance_toolchain_imports_invalid={module}")
        if len(set(imports)) != len(imports):
            raise _fail(f"module_provenance_toolchain_imports_duplicate={module}")
        toolchain_by_name[module] = record
    project_imports = {
        record["name"]: tuple(record["olean_imports"])
        for record in modules
    }
    combined_imports: dict[str, Sequence[str]] = {
        **project_imports,
        **{name: tuple(record["imports"]) for name, record in toolchain_by_name.items()},
    }
    reachable: set[str] = set()

    def visit_module(module: str) -> None:
        if module in reachable:
            return
        imports = combined_imports.get(module)
        if imports is None:
            raise _fail(f"module_provenance_toolchain_import_missing={module}")
        reachable.add(module)
        for imported in imports:
            visit_module(imported)

    for root in IMPORT_GRAPH_ROOTS:
        visit_module(root)
    if reachable != set(project_imports) | set(toolchain_names):
        raise _fail("module_provenance_toolchain_module_closure_mismatch")
    checker_closure = _import_graph_closure(combined_imports, EXPECTED_CHECKER_MODULE)
    if set(checker["loaded_project_modules"]) != checker_closure & set(project_imports):
        raise _fail("module_provenance_checker_project_closure_mismatch")
    if set(loaded_toolchain_modules) != checker_closure & set(toolchain_names):
        raise _fail("module_provenance_checker_toolchain_closure_mismatch")
    for module in toolchain_names:
        stem = module.replace(".", "/")
        files = _module_olean_artifacts(
            toolchain_by_name[module]["olean_files"], module=module,
            relative_stem=f"lib/lean/{stem}", root=toolchain_root,
            label="module_provenance.toolchain", verify_files=verify_files,
        )
        for relative_path, digest, size, path in files:
            verified_artifacts.append((relative_path, digest, size))
            if module in loaded_toolchain_module_set:
                checker_paths.append(path)

    if derived_import_graph is not None:
        expected_imports = {
            module: tuple(imports) for module, imports in combined_imports.items()
        }
        actual_imports = {
            module: tuple(imports) for module, imports in derived_import_graph.items()
        }
        if actual_imports != expected_imports:
            raise _fail("module_provenance_actual_import_graph_mismatch")
        if derived_import_paths is None:
            raise _fail("module_provenance_actual_import_graph_paths_missing")
        if set(derived_import_paths) != set(expected_imports):
            raise _fail("module_provenance_actual_import_graph_path_set_mismatch")
        if derived_import_graph_sha256 != inspector_run["graph_sha256"]:
            raise _fail("module_provenance_actual_import_graph_hash_mismatch")
        for module, actual_path in derived_import_paths.items():
            if module in PROJECT_MODULE_IMPORTS:
                expected_path = product_root / Path(
                    _module_output_relative_path(module, "olean")
                )
            else:
                expected_path = toolchain_root / Path(
                    f"lib/lean/{module.replace('.', '/')}.olean"
                )
            try:
                resolved_expected = expected_path.resolve(strict=True)
                resolved_actual = Path(actual_path).resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise _fail(f"module_provenance_actual_import_graph_path_invalid={module};error={exc}") from exc
            if resolved_actual != resolved_expected or _path_is_link_or_reparse(expected_path):
                raise _fail(f"module_provenance_actual_import_graph_path_mismatch={module}")

    inventory_hash = _module_provenance_output_inventory_hash(provenance)
    if build_result["output_inventory_sha256"] != inventory_hash:
        raise _fail("module_provenance_output_inventory_mismatch")
    if checker_run["input_inventory_sha256"] != inventory_hash:
        raise _fail("module_provenance_checker_input_inventory_mismatch")
    manifest_hash = _module_provenance_manifest_hash(provenance)
    if checker_run["input_manifest_sha256"] != manifest_hash:
        raise _fail("module_provenance_checker_input_manifest_mismatch")

    return (
        hashlib.sha256(json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
        tuple(verified_artifacts),
        tuple(checker_paths),
        manifest_hash,
        inventory_hash,
    )


def _module_provenance_output_inventory_hash(provenance: Mapping[str, Any]) -> str:
    inventory: list[tuple[str, str, int]] = []
    for module_record in provenance["modules"]:
        for field in (
            "olean_files", "generated_c", "native_object",
            "reproduced_olean_files", "reproduced_generated_c", "reproduced_native_object",
        ):
            records = module_record[field]
            if isinstance(records, list):
                for artifact in records:
                    inventory.append(
                        (artifact["relative_path"], artifact["sha256"], artifact["size"])
                    )
            else:
                inventory.append(
                    (records["relative_path"], records["sha256"], records["size"])
                )
    link = provenance["link"]
    for artifact in (
        link["response_file"], link["link_trace"], link["reproduced_response_file"],
        link["reproduced_link_trace"],
        provenance["build_result"]["reproduced_binary"],
        provenance["inspector"]["script"],
    ):
        inventory.append((artifact["relative_path"], artifact["sha256"], artifact["size"]))
    for artifact in (link["linker_driver"], link["linker"]):
        inventory.append(
            (f"toolchain/{artifact['relative_path']}", artifact["sha256"], artifact["size"])
        )
    for field in ("resolved_inputs", "reproduced_resolved_inputs"):
        for artifact in link[field]:
            inventory.append(
                (
                    f"{artifact['root']}/{artifact['relative_path']}",
                    artifact["sha256"],
                    artifact["size"],
                )
            )
    for module_record in provenance["toolchain_modules"]:
        for artifact in module_record["olean_files"]:
            inventory.append(
                (artifact["relative_path"], artifact["sha256"], artifact["size"])
            )
    raw = json.dumps(inventory, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _module_provenance_manifest_hash(provenance: Mapping[str, Any]) -> str:
    """Hash static inputs without self-referential checker or inspector runs."""

    manifest = dict(provenance)
    checker = dict(provenance["checker"])
    checker.pop("run", None)
    manifest["checker"] = checker
    inspector = dict(provenance["inspector"])
    inspector.pop("run", None)
    manifest["inspector"] = inspector
    payload = {
        "domain": f"{MODULE_PROVENANCE_SCHEMA_ID}/manifest",
        "provenance": manifest,
    }
    raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _load_module_provenance(
    receipt: Mapping[str, Any],
    receipt_hash: str,
    *,
    verify_files: bool = False,
    derived_import_graph: Mapping[str, Sequence[str]] | None = None,
    derived_import_paths: Mapping[str, str] | None = None,
    derived_import_graph_sha256: str | None = None,
) -> tuple[str, tuple[tuple[str, str, int], ...], tuple[Path, ...], str, str]:
    if _path_is_link_or_reparse(MODULE_PROVENANCE_RECEIPT) or not MODULE_PROVENANCE_RECEIPT.is_file():
        raise _fail(f"module_provenance_missing_or_link={MODULE_PROVENANCE_RECEIPT}")
    try:
        raw = MODULE_PROVENANCE_RECEIPT.read_bytes()
    except OSError as exc:
        raise _fail(f"module_provenance_read_failed={exc}") from exc
    if len(raw) > MODULE_PROVENANCE_MAX_BYTES:
        raise _fail(f"module_provenance_too_large={len(raw)}")
    digest = hashlib.sha256(raw).hexdigest()
    if EXPECTED_MODULE_PROVENANCE_SHA256 is None:
        raise _fail("module_provenance_hash_unpinned")
    if digest != EXPECTED_MODULE_PROVENANCE_SHA256:
        raise _fail(f"module_provenance_hash_mismatch={digest}")
    try:
        provenance = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_json_object, parse_constant=_reject_json_constant
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise _fail(f"module_provenance_invalid_json={exc}") from exc
    _, artifacts, checker_paths, manifest_hash, inventory_hash = _validate_module_provenance_receipt(
        provenance,
        receipt,
        receipt_hash,
        verify_files=verify_files,
        derived_import_graph=derived_import_graph,
        derived_import_paths=derived_import_paths,
        derived_import_graph_sha256=derived_import_graph_sha256,
    )
    return digest, artifacts, checker_paths, manifest_hash, inventory_hash


def _hash_file(
    path: Path,
    label: str,
    *,
    expected_size: int | None = None,
    max_bytes: int = MAX_HASH_BYTES,
) -> tuple[str, int]:
    try:
        if _path_is_link_or_reparse(path) or not path.is_file():
            raise _fail(f"{label}_missing_or_link={path}")
        before = path.stat()
        if expected_size is not None and before.st_size != expected_size:
            raise _fail(f"{label}_size_mismatch={before.st_size};expected={expected_size}")
        if before.st_size > max_bytes:
            raise _fail(f"{label}_too_large={before.st_size}")
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise _fail(f"{label}_too_large={total}")
                digest.update(chunk)
        after = path.stat()
    except FormalArithmeticError:
        raise
    except OSError as exc:
        raise _fail(f"{label}_hash_failed={exc}") from exc
    before_id = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_id = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_id != after_id or total != after.st_size:
        raise _fail(f"{label}_changed_during_hash")
    return digest.hexdigest(), total


@contextmanager
def _hold_readonly_file_identity(
    path: Path,
    trusted_root: Path,
    *,
    label: str = "leanchecker",
    max_bytes: int = MAX_HASH_BYTES,
) -> Iterator[int]:
    """Hold Windows handles that prevent replacement of a pinned file."""

    if os.name != "nt":
        raise _fail(f"{label}_identity_lock_requires_windows")

    import ctypes
    from ctypes import wintypes

    class _FileTime(ctypes.Structure):
        _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("attributes", wintypes.DWORD),
            ("creation_time", _FileTime),
            ("last_access_time", _FileTime),
            ("last_write_time", _FileTime),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_file_information = kernel32.GetFileInformationByHandle
    get_file_information.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation))
    get_file_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    file_share_read = 0x00000001
    file_share_write = 0x00000002
    file_read_attributes = 0x00000080
    open_existing = 3
    file_flag_open_reparse_point = 0x00200000
    file_flag_backup_semantics = 0x02000000
    file_attribute_directory = 0x00000010
    file_attribute_reparse_point = 0x00000400
    invalid_handle = ctypes.c_void_p(-1).value
    handles: list[Any] = []

    def open_checked(candidate: Path, *, directory: bool) -> _ByHandleFileInformation:
        flags = file_flag_open_reparse_point
        share = file_share_read | file_share_write
        access = file_read_attributes
        if directory:
            flags |= file_flag_backup_semantics
        else:
            share = file_share_read
            access = 0x80000000  # GENERIC_READ; deny write and delete sharing.
        handle = create_file(
            str(candidate), access, share, None, open_existing, flags, None
        )
        if handle == invalid_handle:
            raise _fail(
                f"{label}_identity_lock_open_failed={candidate};"
                f"winerror={ctypes.get_last_error()}"
            )
        handles.append(handle)
        information = _ByHandleFileInformation()
        if not get_file_information(handle, ctypes.byref(information)):
            raise _fail(
                f"{label}_identity_lock_stat_failed={candidate};"
                f"winerror={ctypes.get_last_error()}"
            )
        if information.attributes & file_attribute_reparse_point:
            raise _fail(f"{label}_identity_path_is_reparse_point={candidate}")
        is_directory = bool(information.attributes & file_attribute_directory)
        if is_directory != directory:
            kind = "directory" if directory else "file"
            raise _fail(f"{label}_identity_path_not_{kind}={candidate}")
        return information

    try:
        root = trusted_root.absolute()
        absolute_path = path.absolute()
        try:
            relative = absolute_path.relative_to(root)
        except ValueError as exc:
            raise _fail(f"{label}_identity_path_outside_trusted_root={absolute_path}") from exc
        if not relative.parts or relative.parts[-1] in (".", ".."):
            raise _fail(f"{label}_identity_path_invalid={absolute_path}")

        directories = [root]
        current = root
        for part in relative.parts[:-1]:
            current = current / part
            directories.append(current)
        for directory in directories:
            open_checked(directory, directory=True)
        file_information = open_checked(absolute_path, directory=False)
        size = (file_information.file_size_high << 32) | file_information.file_size_low
        if size > max_bytes:
            raise _fail(f"{label}_identity_file_too_large={size}")
        yield size
    finally:
        close_errors: list[int] = []
        for handle in reversed(handles):
            if not close_handle(handle):
                close_errors.append(ctypes.get_last_error())
        if close_errors:
            raise _fail(f"{label}_identity_lock_release_failed=winerrors:{close_errors}")


@contextmanager
def _hold_readonly_module_inputs(paths: Sequence[Path]) -> Iterator[None]:
    """Lock the receipts and exact `.olean` inputs while leanchecker runs."""

    with ExitStack() as stack:
        stack.enter_context(
            _hold_readonly_file_identity(
                ARTIFACT_RECEIPT, Path.home(), label="artifact_receipt"
            )
        )
        stack.enter_context(
            _hold_readonly_file_identity(
                MODULE_PROVENANCE_RECEIPT, Path.home(), label="module_provenance"
            )
        )
        seen: set[Path] = set()
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            stack.enter_context(
                _hold_readonly_file_identity(path, Path.home(), label="olean_input")
            )
        yield


@contextmanager
def _hold_readonly_link_inputs(
    records: Sequence[Mapping[str, Any]],
    *,
    response_path: Path,
    linker_driver_path: Path,
    linker_path: Path,
    product_root: Path,
    toolchain_root: Path,
) -> Iterator[None]:
    with ExitStack() as stack:
        fixed_inputs = (
            (response_path, product_root, "link_response"),
            (linker_driver_path, toolchain_root, "linker_driver"),
            (linker_path, toolchain_root, "linker"),
        )
        held: set[Path] = set()
        for path, root, label in fixed_inputs:
            if path in held:
                continue
            held.add(path)
            stack.enter_context(
                _hold_readonly_file_identity(
                    path, root, label=label, max_bytes=MAX_LINK_INPUT_BYTES
                )
            )
        for record in records:
            root = product_root if record["root"] == "product" else toolchain_root
            path = root / Path(record["relative_path"])
            if path in held:
                continue
            held.add(path)
            stack.enter_context(
                _hold_readonly_file_identity(
                    path, root, label="link_input", max_bytes=MAX_LINK_INPUT_BYTES
                )
            )
        yield


def _resolve_product_path(relative_path: str) -> Path:
    try:
        candidate = (PRODUCT_ROOT / Path(relative_path)).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _fail(f"receipt_path_resolve_failed={relative_path};error={exc}") from exc
    if not candidate.is_file():
        raise _fail(f"receipt_path_not_file={relative_path}")
    return candidate


def _capture_v2_receipt_inputs() -> dict[str, Any]:
    source_hashes = {
        relative_path: _hash_file(
            _resolve_product_path(relative_path), f"source.{relative_path}"
        )[0]
        for relative_path in RECEIPT_SOURCE_PATHS
    }
    tool_paths = {
        "lean": PINNED_LEAN,
        "lake": PINNED_LAKE,
        "leanchecker": PINNED_LEANCHECKER,
        "pwsh": PINNED_PWSH,
    }
    tools: dict[str, dict[str, Any]] = {}
    for tool_name, path in tool_paths.items():
        digest, size = _hash_file(path, f"tool.{tool_name}")
        tools[tool_name] = {"sha256": digest, "size": size}
    guard_path = _resolve_product_path(EXPECTED_GUARD_RELATIVE_PATH)
    try:
        expected_guard = EXISTING_GUARD.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _fail(f"guard_path_resolve_failed={EXISTING_GUARD};error={exc}") from exc
    if guard_path != expected_guard:
        raise _fail(f"guard_path_mismatch={guard_path};expected={EXISTING_GUARD}")
    guard_hash, _ = _hash_file(guard_path, "guard")
    if guard_hash != EXPECTED_GUARD_SHA256:
        raise _fail(f"guard_hash_mismatch={guard_hash};expected={EXPECTED_GUARD_SHA256}")
    return {"source_sha256": source_hashes, "tools": tools, "guard_sha256": guard_hash}


def _v2_receipt_payload(
    inputs: Mapping[str, Any], binary_sha256: str, binary_size: int
) -> dict[str, Any]:
    return {
        "receipt_version": 2,
        "build_id": BUILD_ID,
        "schema_id": SCHEMA_ID,
        "toolchain": PINNED_TOOLCHAIN,
        "binary": {
            "relative_path": EXPECTED_BINARY_RELATIVE_PATH,
            "sha256": binary_sha256,
            "size": binary_size,
        },
        "source_sha256": inputs["source_sha256"],
        "theorem_manifest": {
            "encoding": THEOREM_MANIFEST_ENCODING,
            "count": EXPECTED_THEOREM_MANIFEST_COUNT,
            "names": list(EXPECTED_THEOREM_MANIFEST),
        },
        "guard": {
            "relative_path": EXPECTED_GUARD_RELATIVE_PATH,
            "sha256": inputs["guard_sha256"],
            "mutex_name": EXPECTED_GUARD_MUTEX,
            "physical_reserve_bytes": EXPECTED_PHYSICAL_RESERVE_BYTES,
            "effective_free_floor_bytes": EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES,
            "tolerance_percent": EXPECTED_PHYSICAL_RESERVE_TOLERANCE_PERCENT,
            "process_tree_cap_bytes": EXPECTED_PROCESS_TREE_CAP_BYTES,
        },
        "tools": inputs["tools"],
        "build_lock": {
            "binary_relative_path": EXPECTED_BINARY_RELATIVE_PATH,
            "source_root": "formal/lean",
            "source_file_count": len(RECEIPT_SOURCE_PATHS),
            "manifest_entry_count": EXPECTED_THEOREM_MANIFEST_COUNT,
            "build_directory": EXPECTED_BUILD_DIRECTORY,
            "guard_mode": "Command",
            "guard_mutex": EXPECTED_GUARD_MUTEX,
            "max_output_bytes": MAX_OUTPUT_BYTES,
        },
    }


def _write_v2_artifact_receipt(receipt: Mapping[str, Any]) -> str:
    if ARTIFACT_RECEIPT.is_symlink():
        raise _fail(f"artifact_receipt_link={ARTIFACT_RECEIPT}")
    raw = (json.dumps(receipt, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise _fail(f"artifact_receipt_too_large={len(raw)}")
    temporary = ARTIFACT_RECEIPT.with_name(
        f"{ARTIFACT_RECEIPT.name}.tmp-{os.getpid()}-{time.time_ns()}"
    )
    try:
        with open(temporary, "xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, ARTIFACT_RECEIPT)
    except OSError as exc:
        raise _fail(f"artifact_receipt_write_failed={exc}") from exc
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
    try:
        written = ARTIFACT_RECEIPT.read_bytes()
    except OSError as exc:
        raise _fail(f"artifact_receipt_verify_read_failed={exc}") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if written != raw:
        raise _fail("artifact_receipt_verify_mismatch")
    return digest


def _artifact_identity(
    *,
    require_module_provenance: bool = False,
    verify_module_inputs: bool = False,
    derived_import_graph: Mapping[str, Sequence[str]] | None = None,
    derived_import_paths: Mapping[str, str] | None = None,
    derived_import_graph_sha256: str | None = None,
) -> tuple[Any, ...]:
    """Check v2 runtime identity; load module provenance only on explicit request."""

    if verify_module_inputs and not require_module_provenance:
        raise _fail("module_provenance_verification_not_requested")
    if _path_is_link_or_reparse(FORMAL_ROOT) or not FORMAL_ROOT.is_dir():
        raise _fail(f"formal_root_missing_or_link={FORMAL_ROOT}")
    receipt, receipt_hash = _load_artifact_receipt()
    binary = receipt["binary"]
    expected_binary = PRODUCT_ROOT / Path(EXPECTED_BINARY_RELATIVE_PATH)
    try:
        actual_binary = FORMAL_BINARY.resolve(strict=True) if FORMAL_BINARY.exists() else FORMAL_BINARY
    except (OSError, RuntimeError) as exc:
        raise _fail(f"formal_binary_resolve_failed={FORMAL_BINARY};error={exc}") from exc
    if actual_binary != expected_binary:
        raise _fail(f"formal_binary_path_mismatch={actual_binary};expected={expected_binary}")
    binary_hash, binary_size = _hash_file(FORMAL_BINARY, "formal_binary", expected_size=binary["size"])
    if binary_hash != binary["sha256"]:
        raise _fail(f"formal_binary_hash_mismatch={binary_hash};expected={binary['sha256']}")
    source_hashes: list[tuple[str, str]] = []
    for relative_path in RECEIPT_SOURCE_PATHS:
        path = _resolve_product_path(relative_path)
        actual_hash, _ = _hash_file(path, f"source.{relative_path}")
        expected_hash = receipt["source_sha256"][relative_path]
        if actual_hash != expected_hash:
            raise _fail(f"source_hash_mismatch={relative_path};actual={actual_hash};expected={expected_hash}")
        source_hashes.append((relative_path, actual_hash))
    tool_paths = {
        "lean": PINNED_LEAN,
        "lake": PINNED_LAKE,
        "leanchecker": PINNED_LEANCHECKER,
        "pwsh": PINNED_PWSH,
    }
    tool_hashes: list[tuple[str, str]] = []
    for tool_name, path in tool_paths.items():
        actual_hash, actual_size = _hash_file(path, f"tool.{tool_name}", expected_size=receipt["tools"][tool_name]["size"])
        expected_hash = receipt["tools"][tool_name]["sha256"]
        if actual_hash != expected_hash:
            raise _fail(f"tool_hash_mismatch={tool_name};actual={actual_hash};expected={expected_hash}")
        tool_hashes.append((tool_name, actual_hash))
    guard_path = _resolve_product_path(EXPECTED_GUARD_RELATIVE_PATH)
    try:
        expected_guard = EXISTING_GUARD.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _fail(f"guard_path_resolve_failed={EXISTING_GUARD};error={exc}") from exc
    if guard_path != expected_guard:
        raise _fail(f"guard_path_mismatch={guard_path};expected={EXISTING_GUARD}")
    guard_hash, _ = _hash_file(guard_path, "guard")
    if guard_hash != receipt["guard"]["sha256"]:
        raise _fail(f"guard_hash_mismatch={guard_hash};expected={receipt['guard']['sha256']}")
    try:
        toolchain_text = (FORMAL_ROOT / "lean-toolchain").read_text(encoding="utf-8")
    except OSError as exc:
        raise _fail(f"toolchain_read_failed={exc}") from exc
    if toolchain_text != PINNED_TOOLCHAIN + "\n" and toolchain_text.strip() != PINNED_TOOLCHAIN:
        raise _fail(f"toolchain_mismatch={toolchain_text!r}")
    base_identity = (
        receipt_hash, BUILD_ID, SCHEMA_ID, PINNED_TOOLCHAIN, binary_hash, binary_size,
        tuple(EXPECTED_THEOREM_MANIFEST), tuple(source_hashes), tuple(tool_hashes), guard_hash,
    )
    if not require_module_provenance:
        return base_identity
    module_provenance = _load_module_provenance(
        receipt,
        receipt_hash,
        verify_files=verify_module_inputs,
        derived_import_graph=derived_import_graph,
        derived_import_paths=derived_import_paths,
        derived_import_graph_sha256=derived_import_graph_sha256,
    )
    return (*base_identity, module_provenance)


class _BoundedCapture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.overflow = False
        self.error: BaseException | None = None

    def read_from(self, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(PIPE_CHUNK_BYTES)
                if not chunk:
                    return
                if len(self.data) <= self.limit:
                    remaining = self.limit + 1 - len(self.data)
                    self.data.extend(chunk[:remaining])
                    if len(self.data) > self.limit:
                        self.overflow = True
        except BaseException as exc:  # pragma: no cover - only pipe failures
            self.error = exc


def _request_owned_process_stop(process: subprocess.Popen[bytes]) -> None:
    """Request a cooperative stop without bypassing the guard's finally block."""

    if os.name == "nt":
        process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        os.killpg(process.pid, signal.SIGTERM)


def _combine_failures(*failures: BaseException | None) -> FormalArithmeticError | None:
    messages: list[str] = []
    for failure in failures:
        if failure is None:
            continue
        message = str(failure)
        if message:
            messages.append(message)
    if not messages:
        return None
    return _fail(";".join(messages))


def _terminate_owned_process_tree(process: subprocess.Popen[bytes]) -> FormalArithmeticError | None:
    """Terminate only the process group created for this guarded controller.

    A root that has already exited is not proof that its descendants exited.  A
    caller must retain the returned failure and independently validate the
    owned-tree receipt before treating cancellation as complete.
    """

    try:
        if process.poll() is not None:
            return _fail("owned_process_tree_cleanup_unverified=root_exited")
    except BaseException as exc:
        return _fail(f"owned_process_tree_cleanup_failed=root_poll={exc!r}")
    if os.name == "nt":
        try:
            if WINDOWS_TASKKILL.is_symlink() or not WINDOWS_TASKKILL.is_file():
                return _fail(f"owned_process_tree_cleanup_tool_missing={WINDOWS_TASKKILL}")
        except OSError as exc:
            return _fail(f"owned_process_tree_cleanup_failed=tool_stat={exc!r}")
        try:
            result = subprocess.run(
                [str(WINDOWS_TASKKILL), "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=OWNED_PROCESS_TERMINATION_TIMEOUT_SECONDS,
            )
        except BaseException as exc:
            return _fail(f"owned_process_tree_cleanup_failed={exc!r}")
        if result.returncode != 0:
            return _fail(f"owned_process_tree_cleanup_failed=taskkill_exit_{result.returncode}")
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError as exc:
            return _fail(f"owned_process_tree_cleanup_unverified=process_group_missing:{exc!r}")
        except OSError as exc:
            return _fail(f"owned_process_tree_cleanup_failed={exc!r}")
    try:
        process.wait(timeout=OWNED_PROCESS_TERMINATION_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return _fail("owned_process_tree_cleanup_failed=process_still_running")
    except BaseException as exc:
        return _fail(f"owned_process_tree_cleanup_failed=wait={exc!r}")
    return None


def _stop_process_for_limit(process: subprocess.Popen[bytes], owned_process_tree: bool) -> FormalArithmeticError | None:
    if not owned_process_tree:
        try:
            process.kill()
        except BaseException as exc:
            return _fail(f"formal_process_stop_failed={exc!r}")
        return None
    try:
        _request_owned_process_stop(process)
    except BaseException as exc:
        try:
            cleanup_failure = _terminate_owned_process_tree(process)
        except BaseException as cleanup_exc:
            cleanup_failure = _fail(f"owned_process_tree_cleanup_failed={cleanup_exc!r}")
        return _combine_failures(
            _fail(f"owned_process_graceful_stop_failed={exc!r}"), cleanup_failure
        )
    return None


def _guarded_cleanup_contract(stdout_bytes: bytes, stderr_bytes: bytes) -> None:
    evidence = stdout_bytes + stderr_bytes
    if (
        b"CLEANUP=PASS label=Command owned_process_tree=empty" not in evidence
        or f"MUTEX=RELEASED name={EXPECTED_GUARD_MUTEX}".encode("ascii") not in evidence
    ):
        raise _fail("owned_process_tree_cleanup_unverified=guard_receipt_missing")


def _run_bounded(
    command: Sequence[str], *, cwd: Path, timeout_seconds: float, output_limit: int,
    owned_process_tree: bool = False,
    owned_tree_cleanup_checker: Callable[[bytes, bytes], None] | None = None,
) -> tuple[int, bytes, bytes]:
    if owned_process_tree and owned_tree_cleanup_checker is None:
        raise _fail("owned_process_tree_cleanup_contract_missing")
    popen_options: dict[str, Any] = {}
    if owned_process_tree:
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            if not creationflags:
                raise _fail("owned_process_group_unavailable")
            popen_options["creationflags"] = creationflags
        else:
            popen_options["start_new_session"] = True
    try:
        process = subprocess.Popen(
            list(command), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            **popen_options,
        )
    except OSError as exc:
        raise _fail(f"formal_process_start_failed={exc}") from exc
    stdout_capture = _BoundedCapture(output_limit)
    stderr_capture = _BoundedCapture(output_limit)
    stdout_thread = threading.Thread(target=stdout_capture.read_from, args=(process.stdout,), daemon=True)
    stderr_thread = threading.Thread(target=stderr_capture.read_from, args=(process.stderr,), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    overflow_stream: str | None = None
    stop_requested = False
    failures: list[FormalArithmeticError] = []

    def record_failure(failure: BaseException | None) -> None:
        if failure is not None:
            failures.append(failure if isinstance(failure, FormalArithmeticError) else _fail(str(failure)))

    def request_stop() -> None:
        try:
            record_failure(_stop_process_for_limit(process, owned_process_tree))
        except BaseException as exc:
            record_failure(_fail(f"formal_process_stop_failed={exc!r}"))

    try:
        while process.poll() is None:
            if stdout_capture.overflow:
                overflow_stream = "stdout"
                stop_requested = True
                request_stop()
                break
            if stderr_capture.overflow:
                overflow_stream = "stderr"
                stop_requested = True
                request_stop()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                stop_requested = True
                request_stop()
                break
            time.sleep(0.01)
    except BaseException as exc:
        record_failure(_fail(f"formal_process_monitor_failed={exc!r}"))
        stop_requested = True
        request_stop()

    return_code = -1
    try:
        return_code = process.wait(
            timeout=OWNED_PROCESS_STOP_GRACE_SECONDS if owned_process_tree and stop_requested else 5
        )
    except subprocess.TimeoutExpired:
        if owned_process_tree and stop_requested:
            try:
                record_failure(_terminate_owned_process_tree(process))
            except BaseException as cleanup_exc:
                record_failure(_fail(f"owned_process_tree_cleanup_failed={cleanup_exc!r}"))
            try:
                return_code = process.wait(timeout=OWNED_PROCESS_TERMINATION_TIMEOUT_SECONDS)
            except BaseException as wait_error:
                record_failure(_fail(f"owned_process_tree_cleanup_failed=wait_after_escalation={wait_error!r}"))
        else:
            try:
                process.kill()
            except OSError as kill_error:
                record_failure(_fail(f"formal_process_stop_failed={kill_error!r}"))
            try:
                return_code = process.wait(timeout=5)
            except BaseException as wait_error:
                record_failure(_fail(f"formal_process_did_not_stop_after_kill={wait_error!r}"))
    except BaseException as exc:
        record_failure(_fail(f"formal_process_wait_failed={exc!r}"))
        if owned_process_tree and stop_requested:
            try:
                record_failure(_terminate_owned_process_tree(process))
            except BaseException as cleanup_exc:
                record_failure(_fail(f"owned_process_tree_cleanup_failed={cleanup_exc!r}"))
            try:
                return_code = process.wait(timeout=OWNED_PROCESS_TERMINATION_TIMEOUT_SECONDS)
            except BaseException as wait_error:
                record_failure(_fail(f"owned_process_tree_cleanup_failed=wait_after_escalation={wait_error!r}"))

    def join_reader(thread: threading.Thread, label: str) -> None:
        try:
            thread.join(timeout=5)
        except BaseException as exc:
            record_failure(_fail(f"{label}_join_failed={exc!r}"))

    def reader_is_alive(thread: threading.Thread, label: str) -> bool:
        try:
            return thread.is_alive()
        except BaseException as exc:
            record_failure(_fail(f"{label}_state_failed={exc!r}"))
            return True

    def close_stream(stream: Any, label: str) -> None:
        if stream is None:
            return
        try:
            stream.close()
        except BaseException as exc:
            record_failure(_fail(f"{label}_close_failed={exc!r}"))

    join_reader(stdout_thread, "stdout_reader")
    join_reader(stderr_thread, "stderr_reader")
    if reader_is_alive(stdout_thread, "stdout_reader") or reader_is_alive(stderr_thread, "stderr_reader"):
        close_stream(process.stdout, "stdout")
        close_stream(process.stderr, "stderr")
        join_reader(stdout_thread, "stdout_reader_retry")
        join_reader(stderr_thread, "stderr_reader_retry")
    close_stream(process.stdout, "stdout")
    close_stream(process.stderr, "stderr")
    if reader_is_alive(stdout_thread, "stdout_reader") or reader_is_alive(stderr_thread, "stderr_reader"):
        record_failure(_fail("formal_output_reader_did_not_stop"))

    if stdout_capture.overflow or len(stdout_capture.data) > output_limit:
        overflow_stream = overflow_stream or "stdout"
    if stderr_capture.overflow or len(stderr_capture.data) > output_limit:
        overflow_stream = overflow_stream or "stderr"
    if overflow_stream is not None:
        stop_requested = True
    if owned_process_tree and stop_requested:
        if owned_tree_cleanup_checker is None:
            record_failure(_fail("owned_process_tree_cleanup_contract_missing"))
        else:
            try:
                owned_tree_cleanup_checker(bytes(stdout_capture.data), bytes(stderr_capture.data))
            except FormalArithmeticError as exc:
                record_failure(exc)
            except BaseException as exc:
                record_failure(_fail(f"owned_process_tree_cleanup_unverified={exc}"))
    if timed_out:
        failures.append(_fail(f"formal_invocation_timeout={timeout_seconds}"))
    if overflow_stream is not None:
        failures.append(_fail(f"formal_output_too_large={overflow_stream};limit={output_limit}"))
    if stdout_capture.error is not None:
        failures.append(_fail(f"stdout_capture_failed={stdout_capture.error}"))
    if stderr_capture.error is not None:
        failures.append(_fail(f"stderr_capture_failed={stderr_capture.error}"))
    if failures:
        combined = _combine_failures(*failures)
        if combined is None:
            raise _fail("formal_process_failure_unavailable")
        raise combined
    return return_code, bytes(stdout_capture.data), bytes(stderr_capture.data)


def _decode_output(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _fail(f"{label}_not_utf8") from exc


def _invoke(
    arguments: Sequence[str], mode: str, *, require_pass: bool = True,
    identity: tuple[Any, ...] | None = None,
) -> dict[str, Any]:
    if identity is None:
        identity = _artifact_identity()
    with _hold_readonly_file_identity(
        FORMAL_BINARY, PRODUCT_ROOT, label="formal_binary"
    ) as held_binary_size:
        locked_identity = _artifact_identity()
        if held_binary_size != locked_identity[5] or locked_identity != identity:
            raise _fail("formal_artifact_changed_before_invocation")
        return_code, stdout_bytes, stderr_bytes = _run_bounded(
            [str(FORMAL_BINARY), *arguments], cwd=FORMAL_ROOT,
            timeout_seconds=30, output_limit=MAX_OUTPUT_BYTES
        )
        after_identity = _artifact_identity()
        if after_identity != locked_identity:
            raise _fail("formal_artifact_replaced_during_invocation")
    stdout = _decode_output(stdout_bytes, "stdout")
    stderr = _decode_output(stderr_bytes, "stderr")
    result = _validate_result(stdout, stderr, mode)
    if return_code != 0:
        raise _fail(f"formal_exit={return_code};stdout={stdout!r}")
    return _normalise_result(result, mode, require_pass=require_pass, binary_sha256=identity[4])


_CACHE_IDENTITY: tuple[Any, ...] | None = None
_CAP_CACHE: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
_RUNTIME_CACHE: OrderedDict[tuple[tuple[Any, ...], tuple[int | bool, ...]], dict[str, Any]] = OrderedDict()
_ROW_CACHE: OrderedDict[tuple[tuple[Any, ...], int], dict[str, Any]] = OrderedDict()


def _clear_caches() -> None:
    global _CACHE_IDENTITY
    _CACHE_IDENTITY = None
    _CAP_CACHE.clear()
    _RUNTIME_CACHE.clear()
    _ROW_CACHE.clear()


def _prepare_cache(identity: tuple[Any, ...]) -> None:
    global _CACHE_IDENTITY
    if _CACHE_IDENTITY != identity:
        _clear_caches()
        _CACHE_IDENTITY = identity


def _cache_get(cache: OrderedDict[Any, dict[str, Any]], key: Any) -> dict[str, Any] | None:
    cached = cache.get(key)
    if cached is None:
        return None
    cache.move_to_end(key)
    return deepcopy(cached)


def _cache_put(
    cache: OrderedDict[Any, dict[str, Any]], key: Any, value: dict[str, Any], maxsize: int
) -> None:
    cache[key] = deepcopy(value)
    cache.move_to_end(key)
    while len(cache) > maxsize:
        cache.popitem(last=False)


def _cached_result(
    cache: OrderedDict[Any, dict[str, Any]], key: Any, maxsize: int,
    invoke: Callable[..., dict[str, Any]], *args: Any, **kwargs: Any,
) -> dict[str, Any]:
    cached = _cache_get(cache, key)
    if cached is not None:
        return cached
    result = invoke(*args, **kwargs)
    _cache_put(cache, key, result, maxsize)
    return result


def run_formal_cap() -> dict[str, Any]:
    """Run the complete cap arithmetic batch once in the current process."""

    identity = _artifact_identity()
    _prepare_cache(identity)
    return _cached_result(_CAP_CACHE, identity, CAP_CACHE_MAXSIZE, _invoke, ["cap"], "cap", identity=identity)


def _runtime_key(values: Mapping[str, Any]) -> tuple[int | bool, ...]:
    if not isinstance(values, Mapping):
        raise _fail("runtime_values_mapping_required")
    key: list[int | bool] = []
    for field in COUNTER_FIELDS:
        if field not in values:
            raise _fail(f"runtime_missing_field={field}")
        value = values[field]
        if type(value) is not int or value < 0:
            raise _fail(f"runtime_counter_not_natural={field}")
        key.append(value)
    for field in BOOLEAN_FIELDS:
        if field not in values:
            raise _fail(f"runtime_missing_field={field}")
        value = values[field]
        if type(value) is not bool:
            raise _fail(f"runtime_flag_not_boolean={field}")
        key.append(value)
    return tuple(key)


def _run_formal_runtime_key(identity: tuple[Any, ...], key: tuple[int | bool, ...]) -> dict[str, Any]:
    arguments = ["runtime"] + [str(value).lower() if isinstance(value, bool) else str(value) for value in key]
    return _invoke(arguments, "runtime", identity=identity)


def run_formal_runtime(values: Mapping[str, Any]) -> dict[str, Any]:
    """Run one exact runtime-counter arithmetic batch, never a Python fallback."""

    identity = _artifact_identity()
    _prepare_cache(identity)
    key = _runtime_key(values)
    cache_key = (identity, key)
    return _cached_result(_RUNTIME_CACHE, cache_key, RUNTIME_CACHE_MAXSIZE, _run_formal_runtime_key, identity, key)


def _run_formal_row_key(identity: tuple[Any, ...], j: int) -> dict[str, Any]:
    return _invoke(["row", str(j)], "row", identity=identity)


def run_formal_row(j: int) -> dict[str, Any]:
    """Run one exact certificate row evaluation in Lean."""

    if not isinstance(j, int) or isinstance(j, bool) or j < 0:
        raise _fail("formal_row_integer_required")
    identity = _artifact_identity()
    _prepare_cache(identity)
    cache_key = (identity, j)
    return _cached_result(_ROW_CACHE, cache_key, ROW_CACHE_MAXSIZE, _run_formal_row_key, identity, j)


def run_formal_arguments(arguments: Sequence[str]) -> dict[str, Any]:
    """Invoke the executable directly for adapter tests, including rejection cases."""

    if not arguments:
        raise _fail("formal_arguments_empty")
    mode = (
        "cap" if list(arguments) == ["cap"]
        else "runtime" if arguments[0] == "runtime"
        else "row" if arguments[0] == "row"
        else "unknown"
    )
    identity = _artifact_identity()
    return _invoke(list(arguments), mode, require_pass=False, identity=identity)


def _guarded_power_shell(
    inner: str, suffix: str, *, timeout_seconds: float, output_limit: int
) -> tuple[int, bytes, bytes]:
    for path, label in (
        (EXISTING_GUARD, "guard"), (PINNED_PWSH, "pwsh"), (PINNED_LEAN, "lean"), (PINNED_LAKE, "lake")
    ):
        if not path.is_file():
            raise _fail(f"{label}_missing={path}")
    guard_hash, _ = _hash_file(EXISTING_GUARD, "guard")
    if guard_hash != EXPECTED_GUARD_SHA256:
        raise _fail(f"guard_hash_mismatch={guard_hash};expected={EXPECTED_GUARD_SHA256}")
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    outer = (
        f"& {quote(EXISTING_GUARD)} -Mode Command -RunSuffix {quote(suffix)} "
        f"-CommandPath {quote(PINNED_PWSH)} "
        f"-CommandArguments @('-NoProfile','-Command',{quote(inner)})"
    )
    return_code, stdout_bytes, stderr_bytes = _run_bounded(
        [str(PINNED_PWSH), "-NoProfile", "-Command", outer],
        cwd=FORMAL_ROOT, timeout_seconds=timeout_seconds, output_limit=output_limit,
        owned_process_tree=True,
        owned_tree_cleanup_checker=_guarded_cleanup_contract,
    )
    return return_code, stdout_bytes, stderr_bytes


def _provenance_guarded_power_shell(
    inner: str, suffix: str, *, timeout_seconds: float, output_limit: int
) -> tuple[int, bytes, bytes]:
    for path, label in (
        (PROVENANCE_GUARD, "provenance_guard"),
        (PINNED_PWSH, "pwsh"),
        (PINNED_LEAN, "lean"),
        (PINNED_LAKE, "lake"),
    ):
        if not path.is_file():
            raise _fail(f"{label}_missing={path}")
    with _hold_readonly_file_identity(
        PROVENANCE_GUARD, Path.home(), label="provenance_guard"
    ):
        guard_hash, _ = _hash_file(PROVENANCE_GUARD, "provenance_guard")
        if guard_hash != PROVENANCE_GUARD_SHA256:
            raise _fail(
                f"provenance_guard_hash_mismatch={guard_hash};expected={PROVENANCE_GUARD_SHA256}"
            )
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        outer = (
            f"& {quote(PROVENANCE_GUARD)} -Mode Command -RunSuffix {quote(suffix)} "
            f"-MinimumStartFreeBytes {PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES} "
            f"-CommandPath {quote(PINNED_PWSH)} "
            f"-CommandArguments @('-NoProfile','-Command',{quote(inner)})"
        )
        return _run_bounded(
            [str(PINNED_PWSH), "-NoProfile", "-Command", outer],
            cwd=FORMAL_ROOT,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            owned_process_tree=True,
            owned_tree_cleanup_checker=_guarded_cleanup_contract,
        )


def _guarded_evidence(
    return_code: int,
    stdout_bytes: bytes,
    stderr_bytes: bytes,
    *,
    label: str,
    policy_version: str = "v3",
) -> str:
    stdout = _decode_output(stdout_bytes, "guarded_build_stdout")
    stderr = _decode_output(stderr_bytes, "guarded_build_stderr")
    evidence = stdout + stderr
    if return_code != 0:
        raise _fail(f"guarded_{label}_exit={return_code};evidence={evidence}")
    if policy_version == "v3":
        preflight = re.search(
            r"(?m)^PHYSICAL_PREFLIGHT free_bytes=(\d+) reserve_bytes=(\d+) "
            r"reserve_floor_bytes=(\d+) tolerance_percent=(\d+)\r?$",
            evidence,
        )
    elif policy_version == "v4":
        policy = re.search(
            r"(?m)^RESOURCE_POLICY version=v4 owner_waiver_effective=2026-09-23 "
            r"process_tree_memory_cap=WAIVED_UNTIL_REVOKED physical_reserve_bytes=(\d+) "
            r"physical_free_floor_bytes=(\d+) target_start_floor_bytes=(\d+) "
            r"effective_start_floor_bytes=(\d+) tolerance_percent=(\d+) "
            r"process_tree_sampling=ENABLED cleanup=ENABLED mutex=([^ ]+) activation=NONE\r?$",
            evidence,
        )
        if policy is None:
            raise _fail(f"guarded_{label}_v4_policy_identity_missing={evidence}")
        reserve, floor, target_floor, effective_floor, tolerance = map(int, policy.groups()[:5])
        if (
            reserve != EXPECTED_PHYSICAL_RESERVE_BYTES
            or floor != EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES
            or target_floor != PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES
            or effective_floor != PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES
            or tolerance != EXPECTED_PHYSICAL_RESERVE_TOLERANCE_PERCENT
            or policy.group(6) != EXPECTED_GUARD_MUTEX
        ):
            raise _fail(f"guarded_{label}_v4_policy_identity_mismatch={evidence}")
        preflight = re.search(
            r"(?m)^PHYSICAL_PREFLIGHT free_bytes=(\d+) reserve_bytes=(\d+) "
            r"reserve_floor_bytes=(\d+) target_start_floor_bytes=(\d+) "
            r"effective_start_floor_bytes=(\d+) tolerance_percent=(\d+)\r?$",
            evidence,
        )
    else:
        raise _fail(f"guarded_{label}_policy_version_invalid={policy_version!r}")
    summary = re.search(
        r"(?m)^LIVE_PHYSICAL_SUMMARY label=Command samples=(\d+) min_free_bytes=(\d+) "
        r"reserve_bytes=(\d+) peak_working_set_bytes=(\d+) peak_private_bytes=(\d+) "
        r"reserve_floor_bytes=(\d+) tolerance_percent=(\d+)\r?$",
        evidence,
    )
    if preflight is None or summary is None:
        raise _fail(f"guarded_{label}_resource_evidence_missing_or_malformed={evidence}")
    preflight_values = list(map(int, preflight.groups()))
    preflight_free, preflight_reserve, preflight_floor = preflight_values[:3]
    if policy_version == "v3":
        preflight_tolerance = preflight_values[3]
        target_floor = effective_floor = EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES
    else:
        target_floor, effective_floor, preflight_tolerance = preflight_values[3:]
    samples, min_free, reserve, _working_set, peak_private, floor, tolerance = map(int, summary.groups())
    if (
        preflight_free < EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES
        or preflight_reserve != EXPECTED_PHYSICAL_RESERVE_BYTES
        or preflight_floor != EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES
        or target_floor != PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES
        or effective_floor != PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES
        or preflight_tolerance != EXPECTED_PHYSICAL_RESERVE_TOLERANCE_PERCENT
    ):
        raise _fail(f"guarded_{label}_preflight_identity_or_floor_mismatch={evidence}")
    if (
        samples <= 0
        or min_free < EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES
        or reserve != EXPECTED_PHYSICAL_RESERVE_BYTES
        or (policy_version == "v3" and peak_private > EXPECTED_PROCESS_TREE_CAP_BYTES)
        or floor != EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES
        or tolerance != EXPECTED_PHYSICAL_RESERVE_TOLERANCE_PERCENT
    ):
        raise _fail(f"guarded_{label}_live_resource_identity_or_cap_mismatch={evidence}")
    if (
        "CHILD_EXIT_CHECK exit7=7 exit0=0" not in evidence
        or "CHILD_EXIT_STATUS label=Command exit=0" not in evidence
        or "CLEANUP=PASS label=Command owned_process_tree=empty" not in evidence
        or f"MUTEX=RELEASED name={EXPECTED_GUARD_MUTEX}" not in evidence
    ):
        raise _fail(f"guarded_{label}_exit_or_cleanup_evidence_incomplete={evidence}")
    return evidence


def _parse_link_input_trace(
    raw_json: str,
    *,
    build_directory: str,
    product_root: Path,
    toolchain_root: Path,
) -> list[dict[str, Any]]:
    try:
        paths = json.loads(
            raw_json,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _fail(f"module_provenance_link_input_trace_invalid={exc}") from exc
    if not isinstance(paths, list) or not paths or any(
        not isinstance(path, str) or not path for path in paths
    ):
        raise _fail("module_provenance_link_input_trace_array_invalid")
    product_root = product_root.resolve(strict=True)
    toolchain_root = toolchain_root.resolve(strict=True)
    records: list[dict[str, Any]] = []
    for index, path_text in enumerate(paths):
        path = Path(path_text)
        if not path.is_absolute():
            raise _fail(f"module_provenance_link_input_trace_path_not_absolute={index}")
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise _fail(f"module_provenance_link_input_trace_path_invalid={index};error={exc}") from exc
        if resolved != path or _path_is_link_or_reparse(path) or not path.is_file():
            raise _fail(f"module_provenance_link_input_trace_path_changed_or_linked={index}")
        try:
            relative = path.relative_to(product_root)
            root_kind = "product"
            root = product_root
        except ValueError:
            try:
                relative = path.relative_to(toolchain_root)
                root_kind = "toolchain"
                root = toolchain_root
            except ValueError as exc:
                raise _fail(
                    f"module_provenance_link_input_outside_pinned_roots={path}"
                ) from exc
        relative_path = relative.as_posix()
        if root_kind == "product":
            if index >= len(LINK_MODULE_ORDER):
                raise _fail(f"module_provenance_link_input_unexpected_product_path={path}")
            module = LINK_MODULE_ORDER[index]
            expected_path = _module_output_relative_path(
                module, "native_object", build_directory=build_directory
            )
            if relative_path != expected_path:
                raise _fail(f"module_provenance_link_input_project_order_mismatch={index}")
        elif index < len(LINK_MODULE_ORDER):
            raise _fail(f"module_provenance_link_input_project_prefix_incomplete={index}")
        digest, size = _hash_file(
            root / Path(relative_path),
            f"link_input[{index}]",
            max_bytes=MAX_LINK_INPUT_BYTES,
        )
        records.append(
            {
                "root": root_kind,
                "relative_path": relative_path,
                "sha256": digest,
                "size": size,
            }
        )
    if len(records) <= len(LINK_MODULE_ORDER):
        raise _fail("module_provenance_link_input_toolchain_closure_missing")
    return records


def _run_link_input_trace(
    *,
    response_path: Path,
    build_directory: str,
    output_path: Path,
    working_directory: Path,
    working_directory_record: str,
    suffix: str,
    product_root: Path,
    toolchain_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    linker_driver = PINNED_LEAN.parent / "clang.exe"
    linker = PINNED_LEAN.parent / "ld.lld.exe"
    toolchain_bin = PINNED_LEAN.parent
    if not linker_driver.is_file() or not linker.is_file() or not response_path.is_file():
        raise _fail("module_provenance_link_input_trace_tool_or_response_missing")
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    response_relative_path = response_path.resolve(strict=True).relative_to(
        product_root.resolve(strict=True)
    ).as_posix()
    inner = (
        "$ErrorActionPreference = 'Stop'; "
        f"Set-Location -LiteralPath {quote(working_directory)}; "
        f"$env:PATH = {quote(toolchain_bin)} + [IO.Path]::PathSeparator + $env:PATH; "
        f"$traceLines = @(& {quote(linker_driver)} '-o' {quote(output_path)} "
        f"{quote('@' + str(response_path))} '-Wl,-t' 2>&1 | "
        "ForEach-Object { $_.ToString() }); "
        "$traceExit = $LASTEXITCODE; "
        "Write-Output ('LINK_INPUT_TRACE_EXIT=' + $traceExit); "
        "if ($traceExit -eq 0) { "
        "$traceJson = ConvertTo-Json -InputObject $traceLines -AsArray -Compress -Depth 4; "
        "Write-Output ('LINK_INPUT_TRACE_JSON=' + $traceJson) }; "
        "exit $traceExit"
    )
    return_code, stdout_bytes, stderr_bytes = _provenance_guarded_power_shell(
        inner, suffix, timeout_seconds=180, output_limit=MAX_BUILD_OUTPUT_BYTES
    )
    evidence = _guarded_evidence(
        return_code,
        stdout_bytes,
        stderr_bytes,
        label="link_input_trace",
        policy_version="v4",
    )
    stdout = _decode_output(stdout_bytes, "link_input_trace_stdout")
    exit_records = [
        line[len("LINK_INPUT_TRACE_EXIT="):]
        for line in stdout.splitlines()
        if line.startswith("LINK_INPUT_TRACE_EXIT=")
    ]
    trace_records = [
        line[len("LINK_INPUT_TRACE_JSON="):]
        for line in stdout.splitlines()
        if line.startswith("LINK_INPUT_TRACE_JSON=")
    ]
    if exit_records != ["0"] or len(trace_records) != 1 or not trace_records[0]:
        raise _fail(
            f"module_provenance_link_input_trace_output_invalid="
            f"exit_records={exit_records!r};trace_records={len(trace_records)}"
        )
    records = _parse_link_input_trace(
        trace_records[0],
        build_directory=build_directory,
        product_root=product_root,
        toolchain_root=toolchain_root,
    )
    driver_hash, driver_size = _hash_file(linker_driver, "linker_driver")
    linker_hash, linker_size = _hash_file(linker, "linker")
    run = {
        "run_suffix": suffix,
        "driver_path": str(linker_driver),
        "driver_sha256": driver_hash,
        "driver_size": driver_size,
        "linker_path": str(linker),
        "linker_sha256": linker_hash,
        "linker_size": linker_size,
        "arguments": [
            "-o", "<temporary-output>", f"@{response_relative_path}", "-Wl,-t"
        ],
        "working_directory": working_directory_record,
        "child_exit": 0,
        "outer_guard_exit": return_code,
        "guard_cleanup": "PASS",
        "mutex_released": True,
        "guard_relative_path": PROVENANCE_GUARD_RELATIVE_PATH,
        "guard_sha256": PROVENANCE_GUARD_SHA256,
        "guard_policy_version": "v4",
        "guard_stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
        "guard_stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "input_trace_sha256": _link_input_trace_hash(records),
        "minimum_start_free_bytes": PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
    }
    return records, run, evidence


def _capture_link_input_provenance(
    *,
    response_path: Path,
    build_directory: str,
    working_directory: Path,
    working_directory_record: str,
    suffix: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    product_root = PRODUCT_ROOT.resolve(strict=True)
    toolchain_root = PINNED_LEAN.parent.parent.resolve(strict=True)
    linker_driver = PINNED_LEAN.parent / "clang.exe"
    linker = PINNED_LEAN.parent / "ld.lld.exe"
    with tempfile.TemporaryDirectory(prefix="blind-ledger-link-trace-") as temp_directory:
        temp_root = Path(temp_directory)
        with _hold_readonly_link_inputs(
            (),
            response_path=response_path,
            linker_driver_path=linker_driver,
            linker_path=linker,
            product_root=product_root,
            toolchain_root=toolchain_root,
        ):
            _verify_link_response(
                response_path,
                build_directory=build_directory,
                toolchain_root=toolchain_root,
            )
            driver_identity = _hash_file(linker_driver, "linker_driver")
            linker_identity = _hash_file(linker, "linker")
            first_records, _, first_evidence = _run_link_input_trace(
                response_path=response_path,
                build_directory=build_directory,
                output_path=temp_root / "first.exe",
                working_directory=working_directory,
                working_directory_record=working_directory_record,
                suffix=f"{suffix}-discover",
                product_root=product_root,
                toolchain_root=toolchain_root,
            )
            with _hold_readonly_link_inputs(
                first_records,
                response_path=response_path,
                linker_driver_path=linker_driver,
                linker_path=linker,
                product_root=product_root,
                toolchain_root=toolchain_root,
            ):
                second_records, run, second_evidence = _run_link_input_trace(
                    response_path=response_path,
                    build_directory=build_directory,
                    output_path=temp_root / "locked.exe",
                    working_directory=working_directory,
                    working_directory_record=working_directory_record,
                    suffix=f"{suffix}-locked",
                    product_root=product_root,
                    toolchain_root=toolchain_root,
                )
                if second_records != first_records:
                    raise _fail("module_provenance_link_input_trace_changed_under_lock")
                if (
                    (run["driver_sha256"], run["driver_size"]) != driver_identity
                    or (run["linker_sha256"], run["linker_size"]) != linker_identity
                ):
                    raise _fail("module_provenance_link_tool_changed_under_lock")
    return second_records, run, f"{first_evidence}\n{second_evidence}"


def _run_olean_import_inspector(
    suffix: str,
) -> tuple[dict[str, tuple[str, ...]], dict[str, str], str, dict[str, Any], str]:
    """Read the actual pinned OLean import graph under the shared guard."""

    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    inner = (
        "$ErrorActionPreference = 'Stop'; "
        f"Set-Location -LiteralPath {quote(FORMAL_ROOT)}; "
        f"$env:LEAN_PATH = {quote(FORMAL_ROOT / '.lake' / 'build-v2' / 'lib' / 'lean')}; "
        f"$graphLines = @(& {quote(PINNED_LEAN)} '--run' "
        f"'../../tools/direct_mask_contract/olean_imports.lean'); "
        "$leanExit = $LASTEXITCODE; "
        "if ($leanExit -ne 0) { Write-Output \"OLEAN_IMPORT_INSPECTOR_EXIT=$leanExit\"; exit $leanExit }; "
        "$graphText = $graphLines -join [Environment]::NewLine; "
        "Write-Output ('OLEAN_IMPORT_GRAPH_JSON=' + $graphText); "
        "exit 0"
    )
    return_code, stdout_bytes, stderr_bytes = _provenance_guarded_power_shell(
        inner, suffix, timeout_seconds=180, output_limit=MAX_BUILD_OUTPUT_BYTES
    )
    evidence = _guarded_evidence(
        return_code,
        stdout_bytes,
        stderr_bytes,
        label="olean_import_inspector",
        policy_version="v4",
    )
    stdout = _decode_output(stdout_bytes, "olean_import_inspector_stdout")
    records = [
        line[len("OLEAN_IMPORT_GRAPH_JSON="):]
        for line in stdout.splitlines()
        if line.startswith("OLEAN_IMPORT_GRAPH_JSON=")
    ]
    if len(records) != 1 or not records[0]:
        raise _fail(f"module_provenance_import_graph_output_invalid={len(records)}")
    raw_json = records[0]
    graph, paths = _parse_olean_import_graph(raw_json)
    graph_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
    lean_hash, lean_size = _hash_file(PINNED_LEAN, "tool.lean")
    inspector_run = {
        "run_suffix": suffix,
        "executable_path": str(PINNED_LEAN),
        "executable_sha256": lean_hash,
        "executable_size": lean_size,
        "arguments": ["--run", "../../tools/direct_mask_contract/olean_imports.lean"],
        "working_directory": "formal/lean",
        "lean_path": "formal/lean/.lake/build-v2/lib/lean",
        "child_exit": 0,
        "outer_guard_exit": return_code,
        "guard_cleanup": "PASS",
        "mutex_released": True,
        "guard_relative_path": PROVENANCE_GUARD_RELATIVE_PATH,
        "guard_sha256": PROVENANCE_GUARD_SHA256,
        "guard_policy_version": "v4",
        "guard_stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
        "guard_stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "graph_sha256": graph_hash,
        "minimum_start_free_bytes": PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
    }
    return graph, paths, graph_hash, inspector_run, evidence


def compile_formal_module_for_test(relative_source: str) -> str:
    """Compile one fixed formal source module under the shared resource guard."""

    if relative_source not in GUARDED_FORMAL_MODULES:
        raise _fail(f"formal_module_not_allowed={relative_source!r}")
    source = FORMAL_ROOT / relative_source
    output = FORMAL_ROOT / ".lake" / "build-v2" / "lib" / "lean" / relative_source.replace(".lean", ".olean")
    inner = (
        f"$ErrorActionPreference = 'Stop'; "
        f"Set-Location -LiteralPath '{FORMAL_ROOT}'; "
        f"$env:LEAN_PATH = '{FORMAL_ROOT / '.lake' / 'build-v2' / 'lib' / 'lean'}'; "
        f"& '{PINNED_LEAN}' '--trust=0' '{source}' '-o' '{output}'; "
        f"exit $LASTEXITCODE"
    )
    suffix = f"lean-security-module-{relative_source.replace('/', '-')}-{time.time_ns()}"
    return_code, stdout_bytes, stderr_bytes = _guarded_power_shell(
        inner, suffix, timeout_seconds=180, output_limit=MAX_BUILD_OUTPUT_BYTES
    )
    return _guarded_evidence(return_code, stdout_bytes, stderr_bytes, label="formal_module")


def run_independent_formal_checker_for_test() -> str:
    """Inspect locked OLean imports, then run the pinned checker under the guard."""

    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    inner = (
        f"$ErrorActionPreference = 'Stop'; "
        f"Set-Location -LiteralPath {quote(FORMAL_ROOT)}; "
        f"$env:LEAN_PATH = {quote(FORMAL_ROOT / '.lake' / 'build-v2' / 'lib' / 'lean')}; "
        f"& {quote(PINNED_LEANCHECKER)} 'BlindLedger.Theorems'; "
        f"exit $LASTEXITCODE"
    )
    suffix = f"lean-security-independent-checker-{time.time_ns()}"
    inspector_suffix = f"lean-security-import-graph-{time.time_ns()}"
    inspector_script = PRODUCT_ROOT / Path(IMPORT_GRAPH_SCRIPT_RELATIVE_PATH)
    with _hold_readonly_file_identity(PINNED_LEANCHECKER, Path.home()) as checker_size:
        with _hold_readonly_file_identity(PINNED_LEAN, Path.home(), label="lean") as lean_size:
            with _hold_readonly_file_identity(
                inspector_script, Path.home(), label="olean_import_inspector"
            ) as inspector_script_size:
                identity = _artifact_identity(require_module_provenance=True)
                checker_hash = dict(identity[8]).get("leanchecker")
                lean_hash = dict(identity[8]).get("lean")
                if checker_hash is None or lean_hash is None:
                    raise _fail("formal_checker_tool_identity_missing_from_artifact_receipt")
                if lean_size != _hash_file(PINNED_LEAN, "tool.lean", expected_size=lean_size)[1]:
                    raise _fail("lean_identity_size_changed_before_import_inspection")
                with _hold_readonly_module_inputs(identity[-1][2]):
                    locked_identity = _artifact_identity(
                        require_module_provenance=True, verify_module_inputs=True
                    )
                    if locked_identity != identity:
                        raise _fail(
                            "formal_module_identity_changed_before_import_inspection;"
                            f"checker_sha256={checker_hash};checker_size={checker_size}"
                        )
                    graph, graph_paths, graph_hash, inspector_run, inspector_evidence = (
                        _run_olean_import_inspector(inspector_suffix)
                    )
                    graph_identity = _artifact_identity(
                        require_module_provenance=True,
                        verify_module_inputs=True,
                        derived_import_graph=graph,
                        derived_import_paths=graph_paths,
                        derived_import_graph_sha256=graph_hash,
                    )
                    if graph_identity != locked_identity:
                        raise _fail(
                            "formal_module_identity_changed_after_import_inspection;"
                            f"graph_sha256={graph_hash};inspector_guard={inspector_evidence}"
                        )
                    return_code, stdout_bytes, stderr_bytes = _provenance_guarded_power_shell(
                        inner, suffix, timeout_seconds=180, output_limit=MAX_OUTPUT_BYTES
                    )
                    evidence = _guarded_evidence(
                        return_code,
                        stdout_bytes,
                        stderr_bytes,
                        label="independent_checker",
                        policy_version="v4",
                    )
                    after_identity = _artifact_identity(
                        require_module_provenance=True,
                        verify_module_inputs=True,
                        derived_import_graph=graph,
                        derived_import_paths=graph_paths,
                        derived_import_graph_sha256=graph_hash,
                    )
                    if after_identity != graph_identity:
                        raise _fail(
                            "formal_artifact_identity_changed_during_independent_checker;"
                            f"checker_sha256={checker_hash};checker_size={checker_size};"
                            f"guard_evidence={evidence}"
                        )
                    checker_run = {
                        "run_suffix": suffix,
                        "executable_path": str(PINNED_LEANCHECKER),
                        "executable_sha256": checker_hash,
                        "executable_size": checker_size,
                        "arguments": [EXPECTED_CHECKER_MODULE],
                        "working_directory": "formal/lean",
                        "lean_path": "formal/lean/.lake/build-v2/lib/lean",
                        "child_exit": 0,
                        "outer_guard_exit": return_code,
                        "guard_cleanup": "PASS",
                        "mutex_released": True,
                        "guard_relative_path": PROVENANCE_GUARD_RELATIVE_PATH,
                        "guard_sha256": PROVENANCE_GUARD_SHA256,
                        "guard_policy_version": "v4",
                        "guard_stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
                        "guard_stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
                        "input_manifest_sha256": graph_identity[-1][3],
                        "input_inventory_sha256": graph_identity[-1][4],
                        "import_graph_sha256": graph_hash,
                        "minimum_start_free_bytes": PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
                    }
                    checker_run_json = json.dumps(
                        checker_run, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                    )
                    inspector_run_json = json.dumps(
                        inspector_run, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                    )
                    return (
                        "PINNED_LEANCHECKER_IDENTITY "
                        f"run_suffix={suffix} target_module={EXPECTED_CHECKER_MODULE} "
                        "child_exit=0 "
                        f"outer_guard_exit={return_code} guard_cleanup=PASS mutex_released=true "
                        f"executable_path_json={json.dumps(str(PINNED_LEANCHECKER), ensure_ascii=True)} "
                        f"executable_sha256={checker_hash} executable_size={checker_size} "
                        f"arguments_json={json.dumps([EXPECTED_CHECKER_MODULE], ensure_ascii=True)} "
                        "working_directory=formal/lean "
                        "lean_path=formal/lean/.lake/build-v2/lib/lean "
                        f"guard_stdout_sha256={hashlib.sha256(stdout_bytes).hexdigest()} "
                        f"guard_stderr_sha256={hashlib.sha256(stderr_bytes).hexdigest()} "
                        f"input_manifest_sha256={graph_identity[-1][3]} "
                        f"input_inventory_sha256={graph_identity[-1][4]} "
                        f"import_graph_sha256={graph_hash} "
                        f"receipt_sha256={identity[0]} "
                        f"pre_run_module_provenance_sha256={identity[-1][0]} "
                        f"locked_olean_inputs={len(identity[-1][2])}\n"
                        f"IMPORT_GRAPH_RUN_JSON={inspector_run_json}\n"
                        f"CHECKER_RUN_JSON={checker_run_json}\n"
                        f"{inspector_evidence}\n{evidence}"
                    )


def build_formal_arithmetic_for_test() -> str:
    """Build v2 in place and write its receipt after trust-0; not a provenance rebuild."""

    inputs_before = _capture_v2_receipt_inputs()
    suffix = f"lean-security-arithmetic-{time.time_ns()}"
    inner = (
        f"$ErrorActionPreference = 'Stop'; "
        f"Set-Location -LiteralPath '{FORMAL_ROOT}'; "
        f"$binary = '{FORMAL_BINARY}'; "
        f"$backup = $binary + '.previous-{suffix}'; "
        f"$hadPrevious = Test-Path -LiteralPath $binary; "
        f"if ($hadPrevious) {{ Copy-Item -LiteralPath $binary -Destination $backup -Force -ErrorAction Stop }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.Arithmetic'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsSupport'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsTerms'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsH0'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsH1'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsH1Outer'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsFS1'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsFS2'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsFS3'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBoundsZero'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.RowBounds'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.WidthBoundsDefinitions'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.WidthBoundsCaps'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.WidthBounds'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.Theorems'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build '+BlindLedger.SecurityExecutable'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
        f"& '{PINNED_LAKE}' build blind_security_arithmetic_v2; "
        f"$status = $LASTEXITCODE; "
        f"if ($status -ne 0) {{ if ($hadPrevious) {{ Copy-Item -LiteralPath $backup -Destination $binary -Force -ErrorAction Stop }} elseif (Test-Path -LiteralPath $binary) {{ Remove-Item -LiteralPath $binary -Force -ErrorAction Stop }}; exit $status }}; "
        f"$env:LEAN_PATH = '{FORMAL_ROOT / '.lake' / 'build-v2' / 'lib' / 'lean'}'; "
        f"& '{PINNED_LEAN}' '--trust=0' 'BlindLedger/AxiomCheck.lean'; "
        f"$status = $LASTEXITCODE; "
        f"if ($status -ne 0) {{ if ($hadPrevious) {{ Copy-Item -LiteralPath $backup -Destination $binary -Force -ErrorAction Stop }} elseif (Test-Path -LiteralPath $binary) {{ Remove-Item -LiteralPath $binary -Force -ErrorAction Stop }}; exit $status }}; "
        f"if ($hadPrevious) {{ Remove-Item -LiteralPath $backup -Force -ErrorAction Stop }}; "
        f"exit 0"
    )
    return_code, stdout_bytes, stderr_bytes = _guarded_power_shell(
        inner, suffix, timeout_seconds=300, output_limit=MAX_BUILD_OUTPUT_BYTES
    )
    evidence = _guarded_evidence(return_code, stdout_bytes, stderr_bytes, label="formal_build")
    inputs_after = _capture_v2_receipt_inputs()
    if inputs_after != inputs_before:
        raise _fail("formal_build_inputs_changed_during_build")
    binary_hash, binary_size = _hash_file(FORMAL_BINARY, "formal_binary")
    receipt = _v2_receipt_payload(inputs_after, binary_hash, binary_size)
    receipt_hash = _write_v2_artifact_receipt(receipt)
    _clear_caches()
    return f"{evidence}\nARTIFACT_RECEIPT_CREATED path={ARTIFACT_RECEIPT.name} sha256={receipt_hash}"
