"""Bounded, read-only differential check against the pinned Lean fixture executable."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

from .api import preflight_bytes
from .checker import check_result
from .codec import parse_bundle_bytes, parse_request_bytes
from .contracts import (
    CheckRequest,
    FactName,
    Outcome,
    ReferenceState,
    RuleBundle,
    RuleId,
    RuleSemantic,
    RunMode,
    Scope,
    ServiceCategory,
    SourceStatus,
)

_TOOLCHAIN_PIN = "leanprover/lean4:v4.33.1"
_LEAN_SHA256 = "AF49BACFABAA1FEA71332CA0FEAE0FA1A60912219D5902291ADC79F905BFFB8D"
_LAKE_SHA256 = "565C3976275D79E104421014B6229F4FCF4A8C8EDFE164A43B344C91AF6F496C"
_SEMANTICS_SHA256 = "DDFD8F2CE54B711191666B6B4ED2689497A82B38F84338C45EADBEA043950132"
_INPUT_PROTOCOL_SHA256 = "573016427EE74B06092A9F885AACCAFDB025D834AF932F61F7EA3A1212630807"
_TOKENS_SHA256 = "0D38081BEE905701130AF4BAB56A9F4A0C500D9D216BFD390C21F08B9F089B87"
_RULES_SHA256 = "C6B6EF4B616EBA6D736DCA2760CBE14172038F679AF2C00E9E4BF1A25D8E68CB"
_FACTS_SHA256 = "EB4F357926CFAEC7E5E669742482DE6F985EC306A7A46F1D4315013C298E9258"
_BUNDLE_SHA256 = "77610DACF50B47DBE059EFE670A21462E0BE8D88980E96173835A3C0FE7397C3"
_MAIN_SHA256 = "EE7AFDED9CB823044180E86226E810A494C9121000894A24F76C8139E5C6B829"
_LAKEFILE_SHA256 = "920671B6929BA574FAD5C427C0B2A3A70FC4277E67A0B5E4173A1E17288D588F"
_MANIFEST_SHA256 = "5142AC3E09A9CF106AA2319778E84A3AD8E48DCFDF3337DE7B5CC8CE6A603217"
_LOCAL_PIN_SHA256 = "A0ADA3782CD088719516BBFDF37B9E7032230E211BF424B85D952EE650C51091"
_LEAN_ARTIFACT_SHA256 = "PENDING"

_INPUT_HEADER = "RRPA-LEAN-COMPARE/v1"
_OUTPUT_HEADER = "RRPA-LEAN-RESULT/v1"
_MAX_INPUT_BYTES = 2048
_MAX_OUTPUT_BYTES = 4096
_MAX_STDERR_BYTES = 2048
_MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
_TIMEOUT_SECONDS = 2.0
_PROCESS_LOCK = threading.Lock()
_MAX_DAY = 3_652_059
_MAX_UTC_SECOND = 315_537_897_599

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE_ROOT = _REPO_ROOT / "lean" / "ProviderApp"
_BUILD_BIN = _PACKAGE_ROOT / ".lake" / "provider-lean-split-r7" / "bin"
_EXECUTABLE = _BUILD_BIN / "providerAppLean.exe"
_RULE_ORDER = tuple(rule.value for rule in RuleId)
_FACT_ORDER = tuple(fact.value for fact in FactName)
_OUTCOMES = frozenset(item.value for item in Outcome)
_BUNDLE_ISSUES = frozenset(
    {
        "REAL_USE_REQUIRES_APPROVED_ISSUER_BUNDLE",
        "BUNDLE_ID_UNSUPPORTED",
        "BUNDLE_SEMANTIC_VERSION_UNSUPPORTED",
        "BUNDLE_PROVENANCE_UNSUPPORTED",
        "BUNDLE_ISSUER_UNSUPPORTED",
        "BUNDLE_SCOPE_MISMATCH",
        "BUNDLE_EFFECTIVE_INTERVAL_INVALID",
        "BUNDLE_LIFETIME_INVALID",
        "BUNDLE_WITHDRAWAL_INVALID",
        "BUNDLE_NOT_YET_PUBLISHED",
        "BUNDLE_EXPIRED",
        "BUNDLE_WITHDRAWN",
        "BUNDLE_CONTENT_DIGEST_MISMATCH",
        "BUNDLE_RULESET_UNSUPPORTED",
    }
)
_REASON_CODES = frozenset(
    {
        "BUNDLE_BLOCKED",
        "REQUIRED_FACT_MISSING",
        "SERVICE_DATE_OUTSIDE_RULE_INTERVAL",
        "SERVICE_CATEGORY_REQUIRES_REVIEW",
        "SUPPORT_REFERENCE_MISSING",
        "CHARGE_OUTSIDE_SYNTHETIC_RANGE",
        "SOURCE_EFFECTIVE_TIME_MISSING",
        "SOURCE_RECEIVED_TIME_MISSING",
        "SOURCE_STATUS_REQUIRES_REVIEW",
        "SOURCE_RECEIVED_BEFORE_EFFECTIVE_DATE",
        "SOURCE_RECEIVED_AFTER_EVALUATION_TIME",
        "SOURCE_STALE_FOR_SYNTHETIC_WINDOW",
        "RULE_SEMANTIC_UNSUPPORTED",
    }
)
_CITATION = re.compile(
    r"^RR-SYNTHETIC-PREFLIGHT/v[1-9][0-9]*#SYN-PRE-00[1-5]/v[1-9][0-9]*$"
)
_SOURCE_STATUS_CODES = {
    SourceStatus.COMPLETE_FIXTURE: "COMPLETE_FIXTURE",
    SourceStatus.PARTIAL: "PARTIAL",
    SourceStatus.STALE: "STALE",
    SourceStatus.CONFLICT: "CONFLICT",
    SourceStatus.REPLAYED: "REPLAYED",
    SourceStatus.UNKNOWN: "UNKNOWN",
}
_RULE_ID_CODES = {
    RuleId.SERVICE_DATE: "001",
    RuleId.SERVICE_CATEGORY: "002",
    RuleId.SUPPORT_REFERENCE: "003",
    RuleId.CHARGE_RANGE: "004",
    RuleId.SOURCE_CURRENCY: "005",
}
_RULE_SEMANTIC_CODES = {
    RuleSemantic.SERVICE_DATE_IN_EFFECTIVE_WINDOW: "DATE",
    RuleSemantic.SERVICE_CATEGORY_EQUALS: "CATEGORY",
    RuleSemantic.SUPPORT_REFERENCE_PRESENT: "REFERENCE",
    RuleSemantic.CHARGE_CENTS_BETWEEN: "CHARGE",
    RuleSemantic.SOURCE_COMPLETE_AND_FRESH: "SOURCE",
}
_EXPECTED_SOURCE_HASHES = {
    "lean/ProviderApp/Semantics.lean": _SEMANTICS_SHA256,
    "lean/ProviderApp/Semantics/Model.lean": "99098C22327038F99E04AE9A16B8B27749C3095678472204E2CBE0FD19F2EA01",
    "lean/ProviderApp/Semantics/Codes.lean": "E48E0D7EF16962CBE84841B29CC1DEAB3F111F78AF619F45362FB45292722709",
    "lean/ProviderApp/Semantics/Rules.lean": "8F4828A4F950F7C6CEB0C567B99AD3BE02FD43F3750615B17FC97AA51F8F8BB4",
    "lean/ProviderApp/Semantics/RuleEvaluation.lean": "C0364A4BF766A538EC9474E8E682CEAB216802100D300D4E51538710B903533A",
    "lean/ProviderApp/Semantics/Result.lean": "BC64DEB2D19CF1073AD358F123D8B1D1DEE92622066B10E713A4A360E1994212",
    "lean/ProviderApp/Semantics/Properties.lean": "5876940158CAFEE511447B8635997C6369192470E545B6BF617083DE946883D6",
    "lean/ProviderApp/InputProtocol.lean": _INPUT_PROTOCOL_SHA256,
    "lean/ProviderApp/InputProtocol/Tokens.lean": _TOKENS_SHA256,
    "lean/ProviderApp/InputProtocol/Rules.lean": _RULES_SHA256,
    "lean/ProviderApp/InputProtocol/Facts.lean": _FACTS_SHA256,
    "lean/ProviderApp/InputProtocol/Bundle.lean": _BUNDLE_SHA256,
    "lean/ProviderApp/Main.lean": _MAIN_SHA256,
    "lean/ProviderApp/lakefile.lean": _LAKEFILE_SHA256,
    "lean/ProviderApp/lake-manifest.json": _MANIFEST_SHA256,
    "lean/ProviderApp/lean-toolchain": _LOCAL_PIN_SHA256,
}


class LeanCompareError(RuntimeError):
    """A stable comparison failure code; never includes input or process output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class LeanRuleProjection:
    rule_id: str
    citation: str
    outcome: str
    missing_facts: tuple[str, ...]
    reason_codes: tuple[str, ...]
    facts_used: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LeanProjection:
    outcome: str
    bundle_issues: tuple[str, ...]
    rules: tuple[LeanRuleProjection, ...]
    missing_facts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ProcessOutput:
    stdout: bytes
    stderr: bytes
    returncode: int


def _sha256_file(path: Path, maximum_bytes: int) -> str:
    try:
        size = path.stat().st_size
        if not path.is_file() or size > maximum_bytes:
            raise LeanCompareError("LEAN_IDENTITY_UNAVAILABLE")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(65_536), b""):
                digest.update(block)
        return digest.hexdigest().upper()
    except LeanCompareError:
        raise
    except OSError:
        raise LeanCompareError("LEAN_IDENTITY_UNAVAILABLE") from None


def _verify_identity() -> Path:
    expected_pins = (_TOOLCHAIN_PIN,)
    for pin_path in (_REPO_ROOT / "lean-toolchain", _PACKAGE_ROOT / "lean-toolchain"):
        try:
            if tuple(pin_path.read_text(encoding="ascii").splitlines()) != expected_pins:
                raise LeanCompareError("LEAN_TOOLCHAIN_PIN_MISMATCH")
        except LeanCompareError:
            raise
        except OSError:
            raise LeanCompareError("LEAN_IDENTITY_UNAVAILABLE") from None

    for relative, expected_hash in _EXPECTED_SOURCE_HASHES.items():
        if expected_hash == "PENDING":
            raise LeanCompareError("LEAN_ARTIFACT_NOT_PINNED")
        if _sha256_file(_REPO_ROOT / relative, 2 * 1024 * 1024) != expected_hash:
            raise LeanCompareError("LEAN_SOURCE_IDENTITY_MISMATCH")

    elan_root = Path(os.environ.get("ELAN_HOME", str(Path.home() / ".elan")))
    toolchain_bin = (
        elan_root
        / "toolchains"
        / "leanprover--lean4---v4.33.1"
        / "bin"
    )
    if _sha256_file(toolchain_bin / "lean.exe", 32 * 1024 * 1024) != _LEAN_SHA256:
        raise LeanCompareError("LEAN_TOOLCHAIN_IDENTITY_MISMATCH")
    if _sha256_file(toolchain_bin / "lake.exe", 32 * 1024 * 1024) != _LAKE_SHA256:
        raise LeanCompareError("LEAN_TOOLCHAIN_IDENTITY_MISMATCH")

    if _LEAN_ARTIFACT_SHA256 == "PENDING":
        raise LeanCompareError("LEAN_ARTIFACT_NOT_PINNED")
    try:
        expected_build_dir = _BUILD_BIN.resolve(strict=True)
        executable = _EXECUTABLE.resolve(strict=True)
        executable.relative_to(expected_build_dir)
    except (OSError, ValueError):
        raise LeanCompareError("LEAN_ARTIFACT_UNAVAILABLE") from None
    if _sha256_file(executable, _MAX_ARTIFACT_BYTES) != _LEAN_ARTIFACT_SHA256:
        raise LeanCompareError("LEAN_ARTIFACT_IDENTITY_MISMATCH")
    return toolchain_bin


def _date_day(value: date) -> str:
    day = value.toordinal()
    if not 1 <= day <= _MAX_DAY:
        raise LeanCompareError("LEAN_INPUT_UNREPRESENTABLE")
    return str(day)


def _utc_seconds(value: datetime) -> str:
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0) or value.microsecond != 0:
        raise LeanCompareError("LEAN_INPUT_UNREPRESENTABLE")
    normalized = value.astimezone(timezone.utc)
    seconds = (
        (normalized.toordinal() - 1) * 86_400
        + normalized.hour * 3_600
        + normalized.minute * 60
        + normalized.second
    )
    if not 0 <= seconds <= _MAX_UTC_SECOND:
        raise LeanCompareError("LEAN_INPUT_UNREPRESENTABLE")
    return str(seconds)


def _optional(value: int | None) -> str:
    return "-" if value is None else str(value)


def _encode_input(request: CheckRequest, bundle: RuleBundle) -> str:
    facts = request.facts
    blocked_real_use = request.mode is RunMode.REAL_USE
    source = None if blocked_real_use else facts.source_binding
    fields = [
        _INPUT_HEADER,
        "S" if request.mode is RunMode.SYNTHETIC_TEST else "R",
        "A" if request.scope is Scope.SYNTHETIC_PROVIDER_A else "B",
        _utc_seconds(request.evaluated_at),
        _date_day(request.evaluated_at.date()),
        "-" if blocked_real_use or facts.service_date is None else _date_day(facts.service_date),
        "-" if blocked_real_use or facts.service_category is None else (
            "A" if facts.service_category is ServiceCategory.CATEGORY_A else "B"
        ),
        "-" if blocked_real_use or facts.support_reference is None else (
            "P" if facts.support_reference is ReferenceState.PRESENT else "A"
        ),
        "-" if blocked_real_use else _optional(facts.charge_cents),
        "-" if source is None else _SOURCE_STATUS_CODES[source.status],
        "-" if source is None or source.effective_at is None else _date_day(source.effective_at),
        "-" if source is None or source.received_at is None else _utc_seconds(source.received_at),
        str(bundle.version),
        "A" if bundle.scope is Scope.SYNTHETIC_PROVIDER_A else "B",
        _utc_seconds(bundle.published_at),
        _date_day(bundle.effective_from),
        _date_day(bundle.effective_until),
        _utc_seconds(bundle.expires_at),
        "-" if bundle.withdrawn_at is None else _utc_seconds(bundle.withdrawn_at),
        "1",
        str(len(bundle.rules)),
    ]
    for rule in bundle.rules:
        fields.extend(
            [
                _RULE_ID_CODES[rule.rule_id],
                str(rule.version),
                _RULE_SEMANTIC_CODES[rule.semantic],
                _date_day(rule.effective_from),
                _date_day(rule.effective_until),
                "-" if rule.expected_category is None else (
                    "A" if rule.expected_category is ServiceCategory.CATEGORY_A else "B"
                ),
                _optional(rule.minimum_cents),
                _optional(rule.maximum_cents),
                _optional(rule.max_source_age_days),
            ]
        )
    encoded = "|".join(fields)
    try:
        encoded_bytes = encoded.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise LeanCompareError("LEAN_INPUT_UNREPRESENTABLE") from None
    if len(encoded_bytes) > _MAX_INPUT_BYTES:
        raise LeanCompareError("LEAN_INPUT_UNREPRESENTABLE")
    return encoded


def _capture_pipe(
    stream: object,
    maximum_bytes: int,
    result: bytearray,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    try:
        pipe = stream
        while True:
            block = pipe.read(1024)  # type: ignore[attr-defined]
            if not block:
                return
            remaining = maximum_bytes - len(result)
            if len(block) > remaining:
                result.extend(block[:remaining])
                overflow.set()
                try:
                    process.kill()
                except OSError:
                    pass
                continue
            result.extend(block)
    except (OSError, ValueError):
        overflow.set()


def _terminate_bounded(process: subprocess.Popen[bytes]) -> None:
    for _ in range(2):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=0.25)
            return
        except subprocess.TimeoutExpired:
            continue
        except OSError:
            continue
    raise LeanCompareError("LEAN_RESOURCE_LIMIT")


def _wait_bounded(
    process: subprocess.Popen[bytes],
    deadline: float,
    overflow: threading.Event,
) -> None:
    while process.poll() is None:
        if overflow.is_set():
            try:
                process.kill()
            except OSError:
                pass
            raise LeanCompareError("LEAN_OUTPUT_LIMIT")
        if time.monotonic() >= deadline:
            try:
                process.kill()
            except OSError:
                pass
            raise LeanCompareError("LEAN_TIMEOUT")
        time.sleep(0.005)


def _run_process(payload: str) -> _ProcessOutput:
    if not _PROCESS_LOCK.acquire(timeout=_TIMEOUT_SECONDS):
        raise LeanCompareError("LEAN_RESOURCE_LIMIT")
    try:
        return _run_process_locked(payload)
    finally:
        _PROCESS_LOCK.release()


def _run_process_locked(payload: str) -> _ProcessOutput:
    toolchain_bin = _verify_identity()
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise LeanCompareError("LEAN_EXECUTION_UNAVAILABLE")
    runtime_environment = {
        "SystemRoot": system_root,
        "WINDIR": os.environ.get("WINDIR", system_root),
        "PATH": str(toolchain_bin),
    }
    try:
        executable = _EXECUTABLE.resolve(strict=True)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        process = subprocess.Popen(
            [str(executable), payload],
            cwd=_PACKAGE_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            creationflags=flags,
            env=runtime_environment,
        )
    except (OSError, ValueError):
        raise LeanCompareError("LEAN_EXECUTION_UNAVAILABLE") from None
    assert process.stdout is not None and process.stderr is not None

    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    readers = (
        threading.Thread(
            target=_capture_pipe,
            args=(process.stdout, _MAX_OUTPUT_BYTES, stdout, overflow, process),
            daemon=True,
        ),
        threading.Thread(
            target=_capture_pipe,
            args=(process.stderr, _MAX_STDERR_BYTES, stderr, overflow, process),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    try:
        _wait_bounded(process, time.monotonic() + _TIMEOUT_SECONDS, overflow)
        returncode = process.wait()
    except LeanCompareError:
        _terminate_bounded(process)
        raise
    finally:
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        for reader in readers:
            reader.join(timeout=0.25)
    if any(reader.is_alive() for reader in readers):
        raise LeanCompareError("LEAN_RESOURCE_LIMIT")
    if overflow.is_set():
        raise LeanCompareError("LEAN_OUTPUT_LIMIT")
    return _ProcessOutput(bytes(stdout), bytes(stderr), returncode)


def _take_count(fields: list[str], cursor: int, maximum: int) -> tuple[int, int]:
    if cursor >= len(fields):
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    token = fields[cursor]
    if not token.isascii() or not token.isdecimal():
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    value = int(token)
    if str(value) != token or value > maximum:
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    return value, cursor + 1


def _take_token(fields: list[str], cursor: int) -> tuple[str, int]:
    if cursor >= len(fields) or not fields[cursor]:
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    return fields[cursor], cursor + 1


def _take_codes(
    fields: list[str], cursor: int, maximum: int, allowed: frozenset[str]
) -> tuple[tuple[str, ...], int]:
    count, cursor = _take_count(fields, cursor, maximum)
    values: list[str] = []
    for _ in range(count):
        token, cursor = _take_token(fields, cursor)
        if token not in allowed:
            raise LeanCompareError("LEAN_PROTOCOL_INVALID")
        values.append(token)
    if len(set(values)) != len(values):
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    return tuple(values), cursor


def _parse_output(stdout: bytes) -> LeanProjection:
    if len(stdout) > _MAX_OUTPUT_BYTES or not stdout.endswith(b"\n"):
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    line = stdout[:-1]
    if line.endswith(b"\r"):
        line = line[:-1]
    if b"\r" in line or b"\n" in line:
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    try:
        text = line.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise LeanCompareError("LEAN_PROTOCOL_INVALID") from None
    fields = text.split("|")
    if not fields or fields[0] != _OUTPUT_HEADER or any(not token for token in fields):
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    cursor = 1
    outcome, cursor = _take_token(fields, cursor)
    if outcome not in _OUTCOMES:
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    issues, cursor = _take_codes(fields, cursor, 14, _BUNDLE_ISSUES)
    rule_count, cursor = _take_count(fields, cursor, 5)
    if rule_count != len(_RULE_ORDER):
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    rules: list[LeanRuleProjection] = []
    for expected_id in _RULE_ORDER:
        rule_id, cursor = _take_token(fields, cursor)
        citation, cursor = _take_token(fields, cursor)
        rule_outcome, cursor = _take_token(fields, cursor)
        if (
            rule_id != expected_id
            or not _CITATION.fullmatch(citation)
            or rule_outcome not in _OUTCOMES
        ):
            raise LeanCompareError("LEAN_PROTOCOL_INVALID")
        missing, cursor = _take_codes(fields, cursor, len(_FACT_ORDER), frozenset(_FACT_ORDER))
        reasons, cursor = _take_codes(fields, cursor, 3, _REASON_CODES)
        used, cursor = _take_codes(fields, cursor, 3, frozenset(_FACT_ORDER))
        rules.append(
            LeanRuleProjection(
                rule_id=rule_id,
                citation=citation,
                outcome=rule_outcome,
                missing_facts=missing,
                reason_codes=reasons,
                facts_used=used,
            )
        )
    missing_facts, cursor = _take_codes(
        fields, cursor, len(_FACT_ORDER), frozenset(_FACT_ORDER)
    )
    if cursor != len(fields):
        raise LeanCompareError("LEAN_PROTOCOL_INVALID")
    return LeanProjection(outcome, issues, tuple(rules), missing_facts)


def _python_projection(result_bytes: bytes) -> LeanProjection:
    try:
        result = json.loads(result_bytes.decode("ascii", errors="strict"))
        rules = tuple(
            LeanRuleProjection(
                rule_id=rule["ruleId"],
                citation=rule["citation"],
                outcome=rule["outcome"],
                missing_facts=tuple(rule["missingFacts"]),
                reason_codes=tuple(rule["reasonCodes"]),
                facts_used=tuple(rule["factsUsed"]),
            )
            for rule in result["rules"]
        )
        return LeanProjection(
            outcome=result["outcome"],
            bundle_issues=tuple(result["bundleIssues"]),
            rules=rules,
            missing_facts=tuple(result["missingFacts"]),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise LeanCompareError("PYTHON_RESULT_INVALID") from None


def _hybrid_result_bytes(
    result_bytes: bytes, projection: LeanProjection
) -> bytes:
    try:
        result = json.loads(result_bytes.decode("ascii", errors="strict"))
        result["outcome"] = projection.outcome
        result["bundleIssues"] = list(projection.bundle_issues)
        result["rules"] = [
            {
                "ruleId": rule.rule_id,
                "citation": rule.citation,
                "outcome": rule.outcome,
                "missingFacts": list(rule.missing_facts),
                "reasonCodes": list(rule.reason_codes),
                "factsUsed": list(rule.facts_used),
            }
            for rule in projection.rules
        ]
        result["missingFacts"] = list(projection.missing_facts)
        return json.dumps(
            result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise LeanCompareError("PYTHON_RESULT_INVALID") from None


def compare_bytes(request_bytes: bytes, bundle_bytes: bytes) -> LeanProjection:
    """Compare one valid normalized synthetic request and bundle with Lean.

    Raw JSON is parsed by the existing strict Python codec and never reaches
    the child process. The return value contains only the Lean model projection.
    """
    request = parse_request_bytes(request_bytes)
    bundle = parse_bundle_bytes(bundle_bytes)
    python_result = preflight_bytes(request_bytes, bundle_bytes)
    differences = check_result(request_bytes, bundle_bytes, python_result)
    if differences:
        raise LeanCompareError("PYTHON_CHECKER_DISAGREEMENT")
    payload = _encode_input(request, bundle)
    process = _run_process(payload)
    if process.returncode != 0 or process.stderr:
        raise LeanCompareError("LEAN_EXECUTION_FAILED")
    lean_result = _parse_output(process.stdout)
    python_result_projection = _python_projection(python_result)
    if check_result(
        request_bytes, bundle_bytes, _hybrid_result_bytes(python_result, lean_result)
    ):
        raise LeanCompareError("LEAN_CHECKER_DISAGREEMENT")
    if lean_result != python_result_projection:
        raise LeanCompareError("LEAN_DISAGREEMENT")
    return lean_result
