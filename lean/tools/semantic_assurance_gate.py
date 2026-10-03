"""Build and check the live financial correction transition proofs.

The candidate is a clean, read-only checkout of the rightrail-main trunk; its
one Lake workspace is `candidate.lean_root` (`lean/`).  This gate records the
commit/tree it verified in its receipt (and, with `--expected-head`, refuses any
other commit), extracts that commit's Lake workspace into a fresh build root,
builds `build.targets` (the native diagnostic and the target that compiles the
theorem module), checks the pinned theorem statements of the financial
correction transition (`candidate.namespace`) and their proof bodies with the
pinned Lean toolchain, checks the axiom closure of every declaration, checks the
independent Lean checker, and fingerprints the freshly built native diagnostic
artifact (`blind_financial --correction-transition-kat`) before and after
execution.  The native diagnostic output is conformance evidence only; it is
never used as proof evidence.  An unapproved axiom does not stop the run: every
check still runs and the gate then fails, naming each declaration and each
unapproved axiom it depends on.

Manifest v2 (2026-09-24, Constitution XI.2) retargeted this gate from the
retired Kernel-series clearance kernel, whose theorem source no longer exists,
to the Lean that actually runs.  It inherits none of the old gate's assurance.
Manifest v3 (2026-09-24) replaced the fixed commit pin (which could never equal
the commit that carries the manifest) with a recorded commit, builds the theorem
module that v2's `blind_financial` build never produced, and allows Lean's three
standard axioms.  Engineering decision (2026-09-24, lead engineer, founder
deferred): allow Lean's three standard axioms; they underlie Lean's own logic;
sorry/custom/native axioms remain forbidden.  `STANDARD_LEAN_AXIOMS` bounds the
manifest, so `sorryAx`, `Lean.ofReduceBool`, `Lean.trustCompiler`,
`native_decide` auxiliary axioms and project axioms can never be allowed.

This gate does not establish refinement to Rust, database durability,
cryptographic soundness, source truth, deployment, payment movement, or
activation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "lean" / "tools" / "semantic_assurance_manifest.json"
MAX_MANIFEST_BYTES = 256 * 1024
COMMAND_TIMEOUT_SECONDS = 180.0
CHECK_TIMEOUT_SECONDS = 90.0
NATIVE_TIMEOUT_SECONDS = 15.0

REQUIRED_MANIFEST_SHA256 = "60a513084f050f3ea319670b3cc48a3e12e1f3dcb529764c0fa990d0b443287c"

# The only axioms a manifest may allow: the ones Lean's own logic rests on.
STANDARD_LEAN_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})

THEOREM_DECLARATION_RE = re.compile(
    r"(?ms)^theorem\s+(?P<name>[A-Za-z0-9_']+)\s+(?P<header>.*?)\s*:=\s*by\b"
)
AXIOM_LINE_RE = re.compile(
    r"^'(?P<name>[^']+)' (?:(?:does not depend on any axioms)|(?:depends on axioms: \[(?P<axioms>.*)\]))$"
)
# A pinned executable's import closure holds no proof-side module (theorems, KATs, vectors, axiom checks), so a proof
# edit never changes its bytes. The roots are those executables' `root` entries in lakefile.toml.
PINNED_EXES = ("blind_financial_worker",)
PROOF_MODULE_RE = re.compile(r"(?:^|\.)(?:Theorems|KAT|Vectors|CodecLaws\w*|\w*Check)(?:\.|$)")
PROOF_COMMAND_RE = re.compile(r"(?m)^\s*(?:#print\s+axioms|#guard_msgs)\b")
LEAN_TOKEN_RE = re.compile(r"/-|-/|--[^\n]*|(?:(?!/-|-/|--)\S)+")
HEX_256_RE = re.compile(r"[0-9a-f]{64}\Z")
HEX_160_RE = re.compile(r"[0-9a-f]{40}\Z")
LEAN_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")

class AssuranceError(RuntimeError):
    """A fail-closed semantic assurance setup or verification error."""


class AxiomClosureFailure(AssuranceError):
    """Every check ran, but declarations depend on unapproved axioms."""

    def __init__(self, message: str, receipt: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.receipt = receipt


@dataclass(frozen=True)
class DeclarationExpectation:
    property_id: str
    name: str
    source_statement: str


@dataclass(frozen=True)
class Manifest:
    candidate: Mapping[str, Any]
    toolchain: Mapping[str, Any]
    build: Mapping[str, Any]
    properties: tuple[Mapping[str, Any], ...]
    declarations: tuple[DeclarationExpectation, ...]
    allowed_axioms: frozenset[str]
    forbidden_tokens: tuple[str, ...]
    native: Mapping[str, Any]


@dataclass(frozen=True)
class FileIdentity:
    path: str
    bytes: int
    sha256: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssuranceError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise AssuranceError(f"non-finite manifest number: {value}")


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise AssuranceError(
            f"{label} keys differ: expected={sorted(expected)!r} got={sorted(value)!r}"
        )


def _string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise AssuranceError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise AssuranceError(f"{label} must be a positive integer")
    return value


def _relative_path(value: Any, label: str) -> str:
    value = _string(value, label)
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or "" in parsed.parts:
        raise AssuranceError(f"{label} is not a safe relative POSIX path: {value!r}")
    if "\\" in value:
        raise AssuranceError(f"{label} must use POSIX separators: {value!r}")
    return value


def _sha256_hex(value: Any, label: str) -> str:
    value = _string(value, label).lower()
    if HEX_256_RE.fullmatch(value) is None:
        raise AssuranceError(f"{label} is not a SHA-256 digest")
    return value


def _git_hex(value: Any, label: str) -> str:
    value = _string(value, label).lower()
    if HEX_160_RE.fullmatch(value) is None:
        raise AssuranceError(f"{label} is not a Git object id")
    return value


def _load_manifest() -> Manifest:
    if MANIFEST_PATH.is_symlink() or not MANIFEST_PATH.is_file():
        raise AssuranceError(f"manifest is not a regular file: {MANIFEST_PATH}")
    raw = MANIFEST_PATH.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise AssuranceError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    if manifest_sha256 != REQUIRED_MANIFEST_SHA256:
        raise AssuranceError(
            "manifest identity changed: "
            f"expected={REQUIRED_MANIFEST_SHA256} got={manifest_sha256}"
        )
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssuranceError(f"manifest is not strict UTF-8 JSON: {exc}") from exc
    if type(value) is not dict:
        raise AssuranceError("manifest root must be an object")
    _exact_keys(
        value,
        {
            "schema",
            "manifest_version",
            "candidate",
            "toolchain",
            "build",
            "properties",
            "allowed_axioms",
            "forbidden_source_tokens",
            "native_protocol",
        },
        "manifest",
    )
    if value["schema"] != "blind_ledger_semantic_assurance_manifest_v3":
        raise AssuranceError(f"unsupported manifest schema: {value['schema']!r}")
    if value["manifest_version"] != 3:
        raise AssuranceError(f"unsupported manifest version: {value['manifest_version']!r}")

    candidate = value["candidate"]
    if type(candidate) is not dict:
        raise AssuranceError("candidate record must be an object")
    _exact_keys(
        candidate,
        {
            "lean_root",
            "namespace",
            "module",
            "theorem_source",
            "declaration_sources",
            "source_files",
        },
        "candidate",
    )
    _relative_path(candidate["lean_root"], "candidate.lean_root")
    namespace = _string(candidate["namespace"], "candidate.namespace")
    if LEAN_NAME_RE.fullmatch(namespace) is None:
        raise AssuranceError(f"candidate.namespace is not a Lean name: {namespace!r}")
    _string(candidate["module"], "candidate.module")
    theorem_source = _relative_path(candidate["theorem_source"], "candidate.theorem_source")
    source_files_value = candidate["source_files"]
    if type(source_files_value) is not list or not source_files_value:
        raise AssuranceError("candidate.source_files must be a non-empty list")
    source_files = tuple(_relative_path(item, "candidate.source_files[]") for item in source_files_value)
    if source_files != tuple(sorted(source_files)) or len(set(source_files)) != len(source_files):
        raise AssuranceError("candidate.source_files must be sorted and unique")
    if theorem_source not in source_files:
        raise AssuranceError("candidate.theorem_source is not in candidate.source_files")
    declaration_sources_value = candidate["declaration_sources"]
    if type(declaration_sources_value) is not dict:
        raise AssuranceError("candidate.declaration_sources must be an object")

    toolchain = value["toolchain"]
    if type(toolchain) is not dict:
        raise AssuranceError("toolchain record must be an object")
    _exact_keys(
        toolchain,
        {"descriptor", "platform", "lean_version", "lake_version", "executables"},
        "toolchain",
    )
    _string(toolchain["descriptor"], "toolchain.descriptor")
    _string(toolchain["platform"], "toolchain.platform")
    _string(toolchain["lean_version"], "toolchain.lean_version")
    _string(toolchain["lake_version"], "toolchain.lake_version")
    executables = toolchain["executables"]
    if type(executables) is not dict or set(executables) != {"lake", "lean", "leanchecker"}:
        raise AssuranceError("toolchain.executable set is not exactly lake/lean/leanchecker")
    for name, record in executables.items():
        if type(record) is not dict:
            raise AssuranceError(f"toolchain executable record is not an object: {name}")
        _exact_keys(record, {"bytes", "sha256"}, f"toolchain.executables.{name}")
        _positive_int(record["bytes"], f"toolchain.executables.{name}.bytes")
        _sha256_hex(record["sha256"], f"toolchain.executables.{name}.sha256")

    build = value["build"]
    if type(build) is not dict:
        raise AssuranceError("build record must be an object")
    _exact_keys(build, {"targets", "root_module", "artifact"}, "build")
    targets = build["targets"]
    if (
        type(targets) is not list
        or not targets
        or any(type(item) is not str or not item or item.startswith("-") for item in targets)
        or len(set(targets)) != len(targets)
    ):
        raise AssuranceError("build.targets must be a non-empty list of unique target names")
    _string(build["root_module"], "build.root_module")
    artifact = build["artifact"]
    if type(artifact) is not dict:
        raise AssuranceError("build.artifact must be an object")
    _exact_keys(artifact, {"relative_path", "minimum_bytes", "identity"}, "build.artifact")
    _relative_path(artifact["relative_path"], "build.artifact.relative_path")
    _positive_int(artifact["minimum_bytes"], "build.artifact.minimum_bytes")
    if artifact["identity"] != "sha256-and-byte-length-of-fresh-build-output":
        raise AssuranceError("build.artifact.identity is not the reviewed identity rule")

    properties_value = value["properties"]
    if type(properties_value) is not list or not properties_value:
        raise AssuranceError("manifest properties must be a non-empty list")
    declarations: list[DeclarationExpectation] = []
    property_ids: list[str] = []
    declaration_names: set[str] = set()
    for property_index, item in enumerate(properties_value):
        if type(item) is not dict:
            raise AssuranceError(f"properties[{property_index}] must be an object")
        _exact_keys(item, {"id", "statement", "declarations"}, f"properties[{property_index}]")
        property_id = _string(item["id"], f"properties[{property_index}].id")
        property_ids.append(property_id)
        statement = _string(item["statement"], f"properties[{property_index}].statement")
        declaration_value = item["declarations"]
        if type(declaration_value) is not list or not declaration_value:
            raise AssuranceError(f"properties[{property_index}].declarations must be non-empty")
        for declaration_index, declaration in enumerate(declaration_value):
            if type(declaration) is not dict:
                raise AssuranceError(
                    f"properties[{property_index}].declarations[{declaration_index}] must be an object"
                )
            _exact_keys(
                declaration,
                {"name", "source_statement"},
                f"properties[{property_index}].declarations[{declaration_index}]",
            )
            declarations.append(
                DeclarationExpectation(
                    property_id=property_id,
                    name=_string(
                        declaration["name"],
                        f"properties[{property_index}].declarations[{declaration_index}].name",
                    ),
                    source_statement=_string(
                        declaration["source_statement"],
                        f"properties[{property_index}].declarations[{declaration_index}].source_statement",
                    ),
                )
            )
        if len(declaration_value) == 1 and statement != declaration_value[0]["source_statement"]:
            raise AssuranceError(f"property statement/declaration mismatch: {property_id}")

        for declaration in declaration_value:
            name = str(declaration["name"])
            if name in declaration_names:
                raise AssuranceError(f"duplicate theorem declaration in manifest: {name}")
            declaration_names.add(name)
    if len(set(property_ids)) != len(property_ids):
        raise AssuranceError("manifest property ids must be unique")
    if set(declaration_sources_value) != declaration_names:
        raise AssuranceError(
            "candidate.declaration_sources keys differ from manifest declarations: "
            f"expected={sorted(declaration_names)!r} got={sorted(declaration_sources_value)!r}"
        )
    for declaration_name in declaration_names:
        declaration_source = _relative_path(
            declaration_sources_value[declaration_name],
            f"candidate.declaration_sources.{declaration_name}",
        )
        if declaration_source not in source_files:
            raise AssuranceError(
                f"candidate.declaration_sources.{declaration_name} is not in "
                "candidate.source_files"
            )

    allowed_axioms_value = value["allowed_axioms"]
    if (
        type(allowed_axioms_value) is not list
        or not allowed_axioms_value
        or any(type(item) is not str or not item for item in allowed_axioms_value)
        or len(set(allowed_axioms_value)) != len(allowed_axioms_value)
    ):
        raise AssuranceError("allowed_axioms must be a non-empty list of unique strings")
    allowed_axioms = frozenset(allowed_axioms_value)
    if not allowed_axioms <= STANDARD_LEAN_AXIOMS:
        raise AssuranceError(
            "allowed_axioms may only name Lean's standard axioms "
            f"{sorted(STANDARD_LEAN_AXIOMS)!r}; got {sorted(allowed_axioms - STANDARD_LEAN_AXIOMS)!r}"
        )

    forbidden_value = value["forbidden_source_tokens"]
    if (
        type(forbidden_value) is not list
        or not forbidden_value
        or any(type(item) is not str or not item for item in forbidden_value)
        or len(set(forbidden_value)) != len(forbidden_value)
    ):
        raise AssuranceError(
            "forbidden_source_tokens must be a non-empty list of unique strings"
        )

    native = value["native_protocol"]
    if type(native) is not dict:
        raise AssuranceError("native_protocol must be an object")
    _exact_keys(
        native,
        {"arguments", "header", "count_key", "gate_tag", "gate_names", "final_line"},
        "native_protocol",
    )
    for key in ("arguments", "header", "gate_names"):
        items = native[key]
        if type(items) is not list or not items or any(
            type(item) is not str or not item for item in items
        ):
            raise AssuranceError(f"native_protocol.{key} must be a non-empty list of strings")
    if any(" " in item for item in native["gate_names"]):
        raise AssuranceError("native_protocol.gate_names must not contain spaces")
    if len(set(native["gate_names"])) != len(native["gate_names"]):
        raise AssuranceError("native_protocol.gate_names must be unique")
    for key in ("count_key", "gate_tag", "final_line"):
        if " " in _string(native[key], f"native_protocol.{key}"):
            raise AssuranceError(f"native_protocol.{key} must not contain spaces")

    return Manifest(
        candidate=candidate,
        toolchain=toolchain,
        build=build,
        properties=tuple(properties_value),
        declarations=tuple(declarations),
        allowed_axioms=allowed_axioms,
        forbidden_tokens=tuple(forbidden_value),
        native=native,
    )


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: Mapping[str, str] | None = None,
    input_bytes: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd),
            env=dict(env) if env is not None else None,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise AssuranceError(f"could not execute {' '.join(command)}: {exc}") from exc
    try:
        stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        cleanup = b""
        if os.name == "nt":
            try:
                killed = subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10.0,
                    check=False,
                )
                cleanup = killed.stdout + killed.stderr
            except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                cleanup = repr(cleanup_error).encode("utf-8", "replace")
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError as cleanup_error:
                cleanup = repr(cleanup_error).encode("utf-8", "replace")
        stdout, stderr = process.communicate()
        raise AssuranceError(
            f"command timed out after {timeout:.1f}s: {' '.join(command)}; "
            f"stdout={stdout!r} stderr={stderr!r} cleanup={cleanup!r}"
        ) from exc
    return subprocess.CompletedProcess(list(command), process.returncode, stdout, stderr)


def _decode(data: bytes, label: str, *, encoding: str = "utf-8") -> str:
    try:
        return data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise AssuranceError(f"{label} output is not {encoding}: {data!r}") from exc


def _git(root: Path, *args: str) -> str:
    return _decode(_git_bytes(root, *args), "git").strip()


def _git_bytes(root: Path, *args: str) -> bytes:
    result = _run(["git", *args], cwd=root, timeout=CHECK_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise AssuranceError(
            f"git {' '.join(args)} failed exit={result.returncode}; "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    if result.stderr:
        raise AssuranceError(f"git {' '.join(args)} wrote stderr: {result.stderr!r}")
    return result.stdout


def _require_success(label: str, result: subprocess.CompletedProcess[bytes]) -> None:
    if result.returncode != 0:
        raise AssuranceError(
            f"{label} failed exit={result.returncode}\n"
            f"stdout={result.stdout!r}\n"
            f"stderr={result.stderr!r}"
        )
    if b"warning" in result.stderr.lower():
        print(f"{label.upper()}_WARNINGS_BEGIN")
        print(_decode(result.stderr, f"{label} stderr"), end="" if result.stderr.endswith(b"\n") else "\n")
        print(f"{label.upper()}_WARNINGS_END")


def _regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise AssuranceError(f"{label} is not a regular file: {path}")


def _worktree_identity(root: Path) -> tuple[str, int, str]:
    status = _git(root, "status", "--porcelain", "--untracked-files=all")
    normalized = status.replace("\r\n", "\n").encode("utf-8")
    count = len(status.splitlines()) if status else 0
    return status, count, hashlib.sha256(normalized).hexdigest()


def _source_identity(
    root: Path, lean_root: str, source_files: Sequence[str]
) -> tuple[str, tuple[FileIdentity, ...]]:
    """Identity of `source_files`, which are relative to `root/lean_root`."""
    digest = hashlib.sha256()
    identities: list[FileIdentity] = []
    for relative in source_files:
        path = root / Path(*lean_root.split("/")) / Path(*relative.split("/"))
        _regular_file(path, f"source file {relative}")
        git_path = f"HEAD:{lean_root}/{relative}"
        expected_blob = _git(root, "rev-parse", git_path).lower()
        # Git's canonical blob is the input to the fresh archive/build.  The
        # working tree may have a reviewed CRLF conversion on Windows, so the
        # identity is taken from `git show`, while the required clean status
        # still rejects any tracked edit or untracked source replacement.
        content = _git_bytes(root, "show", git_path)
        blob = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
        if blob != expected_blob:
            raise AssuranceError(
                f"source file differs from pinned Git blob: {relative} expected={expected_blob} got={blob}"
            )
        file_hash = hashlib.sha256(content).hexdigest()
        identities.append(FileIdentity(relative, len(content), file_hash))
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest(), tuple(identities)


def _parse_source_declarations(
    source: str, expectations: Sequence[DeclarationExpectation]
) -> tuple[dict[str, str], ...]:
    found: dict[str, str] = {}
    for match in THEOREM_DECLARATION_RE.finditer(source):
        name = match.group("name")
        header = match.group("header").strip()
        if header.startswith(":"):
            header = header[1:].strip()
        header = re.sub(r"\s+", " ", header)
        if name in found:
            raise AssuranceError(f"duplicate theorem declaration in source: {name}")
        found[name] = header
    expected_names = tuple(item.name for item in expectations)
    missing = [name for name in expected_names if name not in found]
    if missing:
        raise AssuranceError(f"required theorem declaration missing: {missing!r}")
    observed = tuple(found[name] for name in expected_names)
    for expectation, observed_header in zip(expectations, observed, strict=True):
        if observed_header != expectation.source_statement:
            raise AssuranceError(
                f"theorem statement changed: {expectation.name}; "
                f"expected={expectation.source_statement!r} got={observed_header!r}"
            )
    statement_records = tuple(
        {"name": name, "source_statement": found[name]} for name in expected_names
    )
    # Extra declarations are allowed for implementation lemmas, but they can
    # never replace a required declaration.  The exact candidate tree/source
    # identity still binds the complete reviewed source closure.
    return statement_records


def _forbidden_token_pattern(tokens: Sequence[str]) -> re.Pattern[str] | None:
    if not tokens:
        return None
    alternatives = "|".join(
        re.escape(token) for token in sorted(tokens, key=lambda token: (-len(token), token))
    )
    return re.compile(
        rf"(?i)(?<![A-Za-z0-9_])(?:{alternatives})(?![A-Za-z0-9_])"
    )


def _check_forbidden_sources(
    root: Path, source_files: Sequence[str], forbidden_tokens: Sequence[str]
) -> dict[str, int]:
    pattern = _forbidden_token_pattern(forbidden_tokens)
    files_scanned = 0
    for relative in source_files:
        path = root / Path(*relative.split("/"))
        source = path.read_text(encoding="utf-8")
        files_scanned += 1
        if pattern is not None:
            for match in pattern.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                raise AssuranceError(
                    f"forbidden source token {match.group(0)!r} in {relative}:{line}"
                )
    return {"files_scanned": files_scanned, "forbidden_token_matches": 0}


def _extract_git_tree(root: Path, revision: str, destination: Path) -> None:
    result = _run(
        ["git", "archive", "--format=tar", revision],
        cwd=root,
        timeout=CHECK_TIMEOUT_SECONDS,
    )
    _require_success("git archive", result)
    destination.mkdir(parents=True, exist_ok=False)
    try:
        with tarfile.open(fileobj=BytesIO(result.stdout), mode="r:") as archive:
            members = archive.getmembers()
            for member in members:
                relative = PurePosixPath(member.name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise AssuranceError(f"Git archive contains unsafe path: {member.name!r}")
                if member.issym() or member.islnk():
                    raise AssuranceError(f"Git archive contains a link: {member.name!r}")
                if not (member.isdir() or member.isfile()):
                    raise AssuranceError(f"Git archive contains unsupported entry: {member.name!r}")
                target = (destination / Path(*relative.parts)).resolve()
                if destination.resolve() not in target.parents and target != destination.resolve():
                    raise AssuranceError(f"Git archive path escapes destination: {member.name!r}")
            archive.extractall(destination)
    except (OSError, tarfile.TarError) as exc:
        raise AssuranceError(f"could not extract pinned Git archive: {exc}") from exc


def _lean_imports(source: str) -> list[str]:
    """Modules named in a Lean file's header: `prelude`, then `[public] [meta] import [public] [meta] [all] M`, any layout."""
    words: list[str] = []
    depth = 0
    for token in LEAN_TOKEN_RE.findall(source):
        if token == "/-":
            depth += 1
        elif token == "-/":
            depth = max(depth - 1, 0)
        elif depth == 0 and not token.startswith("--"):
            words.append(token)
    imports: list[str] = []
    at = 1 if words[:1] == ["prelude"] else 0
    while True:
        while at < len(words) and words[at] in ("public", "meta"):
            at += 1
        if at + 1 >= len(words) or words[at] != "import":
            return imports
        at += 1
        while at + 1 < len(words) and words[at] in ("public", "meta", "all"):
            at += 1
        imports.append(words[at])
        at += 1


def _pinned_exe_modules(lean_dir: Path, exes: Sequence[str] = PINNED_EXES) -> set[str]:
    lake = tomllib.loads((lean_dir / "lakefile.toml").read_text(encoding="utf-8"))
    roots = {str(exe["name"]): str(exe["root"]) for exe in lake.get("lean_exe", [])}
    if any(name not in roots for name in exes):
        raise AssuranceError("pinned executable is not a lean_exe in lakefile.toml")
    seen: set[str] = set()
    pending = [roots[name] for name in exes]
    while pending:
        module = pending.pop()
        if module in seen:
            continue
        seen.add(module)
        if PROOF_MODULE_RE.search(module):
            raise AssuranceError(f"pinned executable imports proof module {module}")
        *folders, name = module.split(".")
        path = lean_dir.joinpath(*folders) / f"{name}.lean"
        if not path.is_file():
            continue  # Init, Std or Lean: not a source file of this workspace
        source = path.read_text(encoding="utf-8")
        if PROOF_COMMAND_RE.search(source):
            raise AssuranceError(f"pinned executable imports {module}, which pins axioms")
        pending.extend(_lean_imports(source))
    return seen


def _check_pinned_exe_closure(lean_dir: Path, exes: Sequence[str] = PINNED_EXES) -> int:
    return len(_pinned_exe_modules(lean_dir, exes))


def pinned_source_manifest(lean_dir: Path, exes: Sequence[str] = PINNED_EXES) -> str:
    """SHA-256 over `sha256  lean/path` lines (LF bytes, string-sorted) for the sources the exes are built from: each exe's import closure and the build files."""
    names = {"lakefile.toml", "lean-toolchain", "lake-manifest.json"}
    sources = {module.replace(".", "/") + ".lean" for module in _pinned_exe_modules(lean_dir, exes)}
    names |= {name for name in sources if (lean_dir / name).is_file()}  # Init, Std and Lean are not files of this tree
    digest = hashlib.sha256()
    for name in sorted(names):
        lf = (lean_dir / name).read_bytes().replace(b"\r\n", b"\n")
        digest.update(f"{hashlib.sha256(lf).hexdigest()}  lean/{name}\n".encode())
    return digest.hexdigest()


def _toolchain_paths(manifest: Manifest) -> tuple[dict[str, Path], dict[str, Any]]:
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise AssuranceError(
            f"reviewed toolchain requires Windows x86_64; observed={platform.system()} {platform.machine()}"
        )
    descriptor = str(manifest.toolchain["descriptor"])
    version = descriptor.split(":", 1)[1]
    base = Path.home() / ".elan" / "toolchains" / f"leanprover--lean4---{version}" / "bin"
    paths: dict[str, Path] = {}
    identities: dict[str, Any] = {}
    for name, expected in manifest.toolchain["executables"].items():
        path = base / f"{name}.exe"
        _regular_file(path, f"pinned {name} executable")
        content = path.read_bytes()
        observed = {"path": str(path.resolve()), "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        if observed["bytes"] != expected["bytes"] or observed["sha256"] != expected["sha256"]:
            raise AssuranceError(
                f"pinned {name} executable identity changed: expected={expected!r} got={observed!r}"
            )
        paths[name] = path.resolve()
        identities[name] = observed

    lake_version = _run([str(paths["lake"]), "--version"], cwd=ROOT, timeout=CHECK_TIMEOUT_SECONDS)
    _require_success("lake version", lake_version)
    observed_lake_version = _decode(lake_version.stdout, "lake version").strip()
    if lake_version.stderr or observed_lake_version != manifest.toolchain["lake_version"]:
        raise AssuranceError(
            f"lake version changed: expected={manifest.toolchain['lake_version']!r} "
            f"got={observed_lake_version!r} stderr={lake_version.stderr!r}"
        )
    lean_version = _run([str(paths["lean"]), "--version"], cwd=ROOT, timeout=CHECK_TIMEOUT_SECONDS)
    _require_success("lean version", lean_version)
    observed_lean_version = _decode(lean_version.stdout, "lean version").strip()
    if lean_version.stderr or observed_lean_version != manifest.toolchain["lean_version"]:
        raise AssuranceError(
            f"Lean version changed: expected={manifest.toolchain['lean_version']!r} "
            f"got={observed_lean_version!r} stderr={lean_version.stderr!r}"
        )
    identities["descriptor"] = descriptor
    identities["lean_version"] = observed_lean_version
    identities["lake_version"] = observed_lake_version
    identities["bin_dir"] = str(base.resolve())
    return paths, identities


def _clean_environment(tool_paths: Mapping[str, Path]) -> dict[str, str]:
    environment = dict(os.environ)
    for key in tuple(environment):
        if key.upper() in {
            "LEAN_PATH",
            "LAKE_PATH",
            "LAKE_HOME",
            "ELAN_HOME",
            "LEAN_SRC_PATH",
            "LEAN_LIB",
        }:
            environment.pop(key, None)
    bin_dir = str(next(iter(tool_paths.values())).parent)
    environment["PATH"] = bin_dir + os.pathsep + environment.get("PATH", "")
    return environment


def _parse_fields(line: str, prefix: str) -> dict[str, str]:
    parts = line.split(" ")
    if not parts or parts[0] != prefix:
        raise AssuranceError(f"expected {prefix} line, got {line!r}")
    fields: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            raise AssuranceError(f"malformed {prefix} field in {line!r}")
        key, value = part.split("=", 1)
        if not key or key in fields:
            raise AssuranceError(f"duplicate or empty {prefix} field in {line!r}")
        fields[key] = value
    return fields


def _check_native_output(raw: bytes, native: Mapping[str, Any]) -> dict[str, int]:
    text = _decode(raw, "native diagnostic", encoding="ascii")
    if not raw.endswith(b"\n"):
        raise AssuranceError("native diagnostic output has no final line ending")
    lines = text.splitlines()
    header = tuple(native["header"])
    gate_names = tuple(native["gate_names"])
    expected_line_count = len(header) + 1 + len(gate_names) + 1
    if len(lines) != expected_line_count:
        raise AssuranceError(
            f"native output line count mismatch: expected={expected_line_count} got={len(lines)}"
        )
    if tuple(lines[: len(header)]) != header:
        raise AssuranceError(f"native protocol header mismatch: {lines[:len(header)]!r}")
    index = len(header)
    expected_count_line = f"{native['count_key']}={len(gate_names)}"
    if lines[index] != expected_count_line:
        raise AssuranceError(f"native KAT count changed: {lines[index]!r}")
    index += 1
    seen_gates: list[str] = []
    for _ in gate_names:
        fields = _parse_fields(lines[index], str(native["gate_tag"]))
        index += 1
        if set(fields) != {"name", "result"} or fields.get("result") != "PASS":
            raise AssuranceError(f"native KAT gate failed: {lines[index - 1]!r}")
        name = fields.get("name")
        if name not in gate_names or name in seen_gates:
            raise AssuranceError(f"unexpected or duplicate native KAT gate: {name!r}")
        seen_gates.append(name)
    if tuple(seen_gates) != gate_names:
        raise AssuranceError(f"native KAT gate order changed: {seen_gates!r}")
    if lines[index] != native["final_line"]:
        raise AssuranceError(f"native final result changed: {lines[index]!r}")
    return {"kat_gate_count": len(seen_gates)}


def _file_identity(path: Path, label: str) -> FileIdentity:
    _regular_file(path, label)
    content = path.read_bytes()
    return FileIdentity(str(path), len(content), hashlib.sha256(content).hexdigest())


def _require_identity_unchanged(
    label: str, before: FileIdentity, after: FileIdentity
) -> None:
    if before != after:
        raise AssuranceError(f"{label} changed during execution: before={before} after={after}")


def _require_source_identity_unchanged(
    before: tuple[str, tuple[FileIdentity, ...]],
    after: tuple[str, tuple[FileIdentity, ...]],
) -> None:
    if before != after:
        raise AssuranceError(
            "candidate source identity changed during verification: "
            f"before={before} after={after}"
        )


def _require_toolchain_identity_unchanged(
    tool_paths: Mapping[str, Path], before: Mapping[str, Mapping[str, Any]]
) -> None:
    for name, path in tool_paths.items():
        identity = _file_identity(path, f"pinned {name} executable after execution")
        after = {
            "path": str(path.resolve()),
            "bytes": identity.bytes,
            "sha256": identity.sha256,
        }
        if before.get(name) != after:
            raise AssuranceError(
                f"pinned {name} executable changed during execution: "
                f"before={before.get(name)!r} after={after!r}"
            )


def _parse_axiom_output(
    raw: bytes, declarations: Sequence[str], allowed: frozenset[str], namespace: str
) -> tuple[dict[str, Any], ...]:
    text = _decode(raw, "axiom closure")
    # Lean wraps a long axiom list onto indented continuation lines; each
    # declaration's record starts at column 0 with its quoted name.
    lines: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if not lines:
                raise AssuranceError(f"axiom closure output starts with a continuation: {text!r}")
            lines[-1] = f"{lines[-1]} {line.strip()}"
        else:
            lines.append(line)
    if len(lines) != len(declarations):
        raise AssuranceError(
            f"axiom closure line count mismatch: expected={len(declarations)} got={len(lines)} raw={text!r}"
        )
    records: list[dict[str, Any]] = []
    for expected_name, line in zip(declarations, lines, strict=True):
        match = AXIOM_LINE_RE.fullmatch(line)
        if match is None or match.group("name") != f"{namespace}.{expected_name}":
            raise AssuranceError(f"axiom closure declaration order changed: {line!r}")
        axioms = tuple(
            sorted(item.strip() for item in (match.group("axioms") or "").split(",") if item.strip())
        )
        unapproved = sorted(set(axioms) - allowed)
        records.append(
            {"name": expected_name, "axioms": list(axioms), "unapproved": unapproved, "raw": line}
        )
    return tuple(records)


def _axiom_violation_message(
    records: Sequence[Mapping[str, Any]], allowed: frozenset[str]
) -> str | None:
    """None when every declaration is approved; otherwise one exact entry per failure."""
    failures = [record for record in records if record["unapproved"]]
    if not failures:
        return None
    details = "; ".join(
        f"{record['name']} uses unapproved {record['unapproved']!r}" for record in failures
    )
    return (
        f"unapproved axiom dependency: {len(failures)} of {len(records)} declarations; "
        f"allowed={sorted(allowed)!r}; {details}"
    )


def _check_declaration_output(raw: bytes, declarations: Sequence[str], namespace: str) -> str:
    text = _decode(raw, "declaration check")
    cursor = 0
    for name in declarations:
        marker = f"{namespace}.{name}"
        position = text.find(marker, cursor)
        if position < 0:
            raise AssuranceError(f"declaration check did not expose {marker}")
        cursor = position + len(marker)
    return text


def _verify_candidate(
    candidate_root: Path, manifest: Manifest, expected_head: str | None = None
) -> dict[str, Any]:
    candidate_root = candidate_root.resolve()
    if not candidate_root.is_dir() or not (candidate_root / ".git").exists():
        raise AssuranceError(f"candidate root is not a Git checkout: {candidate_root}")
    before_status, before_status_count, before_status_sha256 = _worktree_identity(candidate_root)
    if before_status:
        raise AssuranceError(f"candidate checkout is dirty:\n{before_status}")
    head = _git_hex(_git(candidate_root, "rev-parse", "HEAD"), "candidate HEAD")
    tree = _git_hex(_git(candidate_root, "rev-parse", "HEAD^{tree}"), "candidate tree")
    if expected_head is not None and head != _git_hex(expected_head, "expected head"):
        raise AssuranceError(
            f"candidate Git identity mismatch: expected head={expected_head.lower()} got={head}"
        )
    lean_root = str(manifest.candidate["lean_root"])
    namespace = str(manifest.candidate["namespace"])
    lean_dir = candidate_root / Path(*lean_root.split("/"))
    source_files = tuple(manifest.candidate["source_files"])
    source_hash_before, file_identities = _source_identity(
        candidate_root, lean_root, source_files
    )
    theorem_source = str(manifest.candidate["theorem_source"])
    declaration_sources = manifest.candidate["declaration_sources"]
    grouped_expectations: dict[str, list[DeclarationExpectation]] = {}
    for expectation in manifest.declarations:
        source_path = str(declaration_sources[expectation.name])
        grouped_expectations.setdefault(source_path, []).append(expectation)
    parsed_by_name: dict[str, dict[str, str]] = {}
    statement_records: list[dict[str, str]] = []
    for source_path, expectations in grouped_expectations.items():
        source_file = lean_dir / Path(*source_path.split("/"))
        source_text = source_file.read_text(encoding="utf-8")
        parsed_records = _parse_source_declarations(source_text, expectations)
        for record in parsed_records:
            name = record["name"]
            if name in parsed_by_name:
                raise AssuranceError(f"duplicate source mapping for theorem declaration: {name}")
            parsed_by_name[name] = record
    for expectation in manifest.declarations:
        try:
            record = parsed_by_name[expectation.name]
        except KeyError as exc:
            raise AssuranceError(
                f"required theorem declaration was not parsed: {expectation.name}"
            ) from exc
        statement_records.append(
            {
                "name": record["name"],
                "source_path": str(declaration_sources[expectation.name]),
                "source_statement": record["source_statement"],
            }
        )
    source_scan = _check_forbidden_sources(
        lean_dir, source_files, manifest.forbidden_tokens
    )
    _check_pinned_exe_closure(lean_dir)
    tool_paths, tool_identities = _toolchain_paths(manifest)
    build_command = [
        str(tool_paths["lake"]),
        "build",
        *(str(item) for item in manifest.build["targets"]),
    ]
    declarations = tuple(item.name for item in manifest.declarations)

    with tempfile.TemporaryDirectory(prefix="blind-ledger-semantic-assurance-") as temporary:
        temporary_root = Path(temporary)
        build_root = temporary_root / "build"
        # Extract only the pinned commit's Lake workspace (`<head>:<lean_root>`),
        # so the build root is the workspace root.
        _extract_git_tree(candidate_root, f"{head}:{lean_root}", build_root)
        environment = _clean_environment(tool_paths)
        build = _run(
            build_command,
            cwd=build_root,
            timeout=COMMAND_TIMEOUT_SECONDS,
            env=environment,
        )
        _require_success("candidate build", build)
        lib_path = (build_root / ".lake" / "build" / "lib" / "lean").resolve()
        if not lib_path.is_dir():
            raise AssuranceError(f"fresh Lean build library path is missing: {lib_path}")
        artifact_relative = str(manifest.build["artifact"]["relative_path"])
        artifact = build_root / Path(*artifact_relative.split("/"))
        artifact_identity_before = _file_identity(artifact, "fresh native artifact")
        if artifact_identity_before.bytes < manifest.build["artifact"]["minimum_bytes"]:
            raise AssuranceError(f"fresh native artifact is below its minimum size: {artifact}")

        check_environment = dict(environment)
        check_environment["LEAN_PATH"] = str(lib_path)
        proof_body_checks: dict[str, dict[str, Any]] = {}
        for source_path in grouped_expectations:
            proof_olean = temporary_root / (
                source_path.replace("/", "_").replace("\\", "_") + ".bodycheck.olean"
            )
            body_check_command = [
                str(tool_paths["lean"]),
                "--trust=0",
                source_path,
                "-o",
                str(proof_olean),
            ]
            body_check = _run(
                body_check_command,
                cwd=build_root,
                timeout=CHECK_TIMEOUT_SECONDS,
                env=check_environment,
            )
            _require_success(f"proof body check {source_path}", body_check)
            proof_identity = _file_identity(
                proof_olean, f"fresh theorem body-check artifact for {source_path}"
            )
            proof_body_checks[source_path] = {
                "command": body_check_command,
                "exit": body_check.returncode,
                "stdout": _decode(body_check.stdout, f"proof body check {source_path}"),
                "stderr": _decode(body_check.stderr, f"proof body check {source_path} stderr"),
                "bodycheck_artifact": {
                    "path": proof_identity.path,
                    "bytes": proof_identity.bytes,
                    "sha256": proof_identity.sha256,
                },
            }

        declaration_query = "import " + str(manifest.candidate["module"]) + "\n" + "\n".join(
            f"#check {namespace}.{name}" for name in declarations
        ) + "\n"
        declaration_check = _run(
            [str(tool_paths["lean"]), "--trust=0", "--stdin"],
            cwd=build_root,
            timeout=CHECK_TIMEOUT_SECONDS,
            env=check_environment,
            input_bytes=declaration_query.encode("ascii"),
        )
        _require_success("declaration check", declaration_check)
        declaration_output = _check_declaration_output(
            declaration_check.stdout, declarations, namespace
        )

        axiom_query = "import " + str(manifest.candidate["module"]) + "\n" + "\n".join(
            f"#print axioms {namespace}.{name}" for name in declarations
        ) + "\n"
        axiom_check = _run(
            [str(tool_paths["lean"]), "--trust=0", "--stdin"],
            cwd=build_root,
            timeout=CHECK_TIMEOUT_SECONDS,
            env=check_environment,
            input_bytes=axiom_query.encode("ascii"),
        )
        _require_success("axiom closure check", axiom_check)
        axiom_records = _parse_axiom_output(
            axiom_check.stdout, declarations, manifest.allowed_axioms, namespace
        )
        axiom_failure = _axiom_violation_message(axiom_records, manifest.allowed_axioms)

        independent_check = _run(
            [str(tool_paths["leanchecker"]), str(manifest.candidate["module"])],
            cwd=build_root,
            timeout=CHECK_TIMEOUT_SECONDS,
            env=check_environment,
        )
        _require_success("independent Lean checker", independent_check)

        native = _run(
            [str(artifact.resolve()), *manifest.native["arguments"]],
            cwd=build_root,
            timeout=NATIVE_TIMEOUT_SECONDS,
            env=check_environment,
        )
        _require_success("native semantic diagnostic", native)
        if native.stderr:
            raise AssuranceError(f"native semantic diagnostic wrote stderr: {native.stderr!r}")
        native_counts = _check_native_output(native.stdout, manifest.native)
        artifact_identity_after = _file_identity(artifact, "native artifact after execution")
        _require_identity_unchanged(
            "native artifact", artifact_identity_before, artifact_identity_after
        )
        _require_toolchain_identity_unchanged(tool_paths, tool_identities)

        source_hash_after, file_identities_after = _source_identity(
            candidate_root, lean_root, source_files
        )
        _require_source_identity_unchanged(
            (source_hash_before, file_identities),
            (source_hash_after, file_identities_after),
        )
        head_after = _git(candidate_root, "rev-parse", "HEAD").lower()
        tree_after = _git(candidate_root, "rev-parse", "HEAD^{tree}").lower()
        if head_after != head or tree_after != tree:
            raise AssuranceError(
                "candidate Git identity changed during verification: "
                f"before={head}/{tree} after={head_after}/{tree_after}"
            )
        after_status, after_status_count, after_status_sha256 = _worktree_identity(candidate_root)
        if before_status != after_status:
            raise AssuranceError(
                f"candidate Git status changed during verification: before={before_status!r} after={after_status!r}"
            )

        print("DECLARATION_CHECK_OUTPUT_BEGIN")
        print(declaration_output, end="" if declaration_output.endswith("\n") else "\n")
        print("DECLARATION_CHECK_OUTPUT_END")
        axiom_output = _decode(axiom_check.stdout, "axiom closure")
        print("AXIOM_CLOSURE_OUTPUT_BEGIN")
        print(axiom_output, end="" if axiom_output.endswith("\n") else "\n")
        print("AXIOM_CLOSURE_OUTPUT_END")
        print("NATIVE_OUTPUT_BEGIN")
        print(_decode(native.stdout, "native semantic diagnostic", encoding="ascii"), end="")
        print("NATIVE_OUTPUT_END")

        receipt = {
            "schema": "blind_ledger_semantic_assurance_receipt_v3",
            "status": "PASS" if axiom_failure is None else "FAIL",
            "failures": [] if axiom_failure is None else [axiom_failure],
            "claim": "FINANCIAL_CORRECTION_TRANSITION_PROOFS_NONACTIVATING",
            "manifest": {
                "path": str(MANIFEST_PATH),
                "sha256": hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
                "property_count": len(manifest.properties),
                "declaration_count": len(manifest.declarations),
                "allowed_axioms": sorted(manifest.allowed_axioms),
            },
            "candidate": {
                "root": str(candidate_root),
                "head": head,
                "tree": tree,
                "source_sha256": source_hash_after,
                "source_files": [identity.__dict__ for identity in file_identities_after],
                "worktree_status_count": after_status_count,
                "worktree_status_sha256": after_status_sha256,
                "status_unchanged": before_status == after_status,
            },
            "toolchain": {**tool_identities, "identity_unchanged": True},
            "build": {
                "targets": list(manifest.build["targets"]),
                "root_module": manifest.build["root_module"],
                "command": build_command,
                "exit": build.returncode,
                "artifact": {
                    "path": str(artifact.resolve()),
                    "bytes": artifact_identity_before.bytes,
                    "sha256": artifact_identity_before.sha256,
                    "identity_unchanged": artifact_identity_before == artifact_identity_after,
                },
                "proof_body_checks": proof_body_checks,
                "declaration_check": {
                    "exit": declaration_check.returncode,
                    "declaration_count": len(declarations),
                    "output": declaration_output,
                },
                "axiom_closure": {
                    "exit": axiom_check.returncode,
                    "status": "PASS" if axiom_failure is None else "FAIL",
                    "unapproved": [
                        {"name": record["name"], "unapproved": record["unapproved"]}
                        for record in axiom_records
                        if record["unapproved"]
                    ],
                    "records": list(axiom_records),
                    "output": axiom_output,
                },
                "independent_checker": {
                    "command": [str(tool_paths["leanchecker"]), str(manifest.candidate["module"])],
                    "exit": independent_check.returncode,
                    "stdout": _decode(independent_check.stdout, "independent Lean checker"),
                    "stderr": _decode(independent_check.stderr, "independent Lean checker stderr"),
                },
            },
            "source_declarations": list(statement_records),
            "native": {
                "counts": native_counts,
                "source_scan": source_scan,
                "stdout": _decode(native.stdout, "native semantic diagnostic", encoding="ascii"),
            },
            "qualification": {
                "modeled": "PASS",
                "proved": "PASS" if axiom_failure is None else "FAIL",
                "compiled": "PASS",
                "runtime_linked": "NOT_ESTABLISHED",
                "deployment_qualified": "NOT_ESTABLISHED",
                "production_usable": False,
                "activation": False,
                "proofSuiteId": None,
            },
        }
        if axiom_failure is not None:
            raise AxiomClosureFailure(axiom_failure, receipt)
        return receipt


def verify(candidate_root: Path, expected_head: str | None = None) -> dict[str, Any]:
    manifest = _load_manifest()
    return _verify_candidate(candidate_root, manifest, expected_head)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate-root",
        type=Path,
        required=True,
        help="a clean checkout of rightrail-main; the receipt records its commit and tree",
    )
    parser.add_argument(
        "--expected-head",
        default=None,
        help="optional full commit id; any other candidate HEAD is refused",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="strict")
    args = _parser().parse_args(argv)
    try:
        receipt = verify(args.candidate_root, args.expected_head)
    except AxiomClosureFailure as exc:
        for record in exc.receipt["build"]["axiom_closure"]["unapproved"]:
            print(
                f"AXIOM_CLOSURE_FAIL name={record['name']} "
                f"unapproved={','.join(record['unapproved'])}"
            )
        print(
            "SEMANTIC_ASSURANCE_RECEIPT="
            + json.dumps(exc.receipt, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        )
        print(f"SEMANTIC_ASSURANCE_GATE=FAIL {exc}", file=sys.stderr)
        return 1
    except AssuranceError as exc:
        print(f"SEMANTIC_ASSURANCE_GATE=FAIL {exc}", file=sys.stderr)
        return 1
    print("PROOF_BODY_CHECK=PASS actual_lean_trust=0 fresh_source_process=true")
    print("INDEPENDENT_LEAN_CHECKER=PASS fresh_pinned_process=true")
    source_scan = receipt["native"]["source_scan"]
    print(
        "SOURCE_CLOSURE_SCAN=PASS "
        f"files_scanned={source_scan['files_scanned']} "
        f"forbidden_token_matches={source_scan['forbidden_token_matches']}"
    )
    print(
        "SEMANTIC_ASSURANCE_GATE=PASS "
        f"head={receipt['candidate']['head']} tree={receipt['candidate']['tree']} "
        f"property_count={receipt['manifest']['property_count']} "
        f"declaration_count={receipt['manifest']['declaration_count']} "
        f"artifact_bytes={receipt['build']['artifact']['bytes']} "
        f"artifact_sha256={receipt['build']['artifact']['sha256']}"
    )
    print("SEMANTIC_ASSURANCE_RECEIPT=" + json.dumps(receipt, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
