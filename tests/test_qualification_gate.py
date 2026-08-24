from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from tools import ops_authority
from tools import qualification_gate as gate


ROOT = Path(__file__).resolve().parents[1]


def _blockers(*, qualification_closed: bool = False, activation_closed: bool = False) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, (identifier, classification, blocker_gate) in enumerate(gate.BLOCKER_IDENTITY):
        closed = qualification_closed or (activation_closed and index >= 0)
        if not activation_closed and index >= 6:
            closed = False
        result.append(
            {
                "id": identifier,
                "classification": classification,
                "gate": blocker_gate,
                "status": "closed" if closed else "open",
                "evidenceSha3_512": "a" * 128 if closed else None,
            }
        )
    return result


def _pin(
    state: str = "UNSELECTED",
    *,
    production: bool = False,
    activation: bool = False,
) -> dict[str, object]:
    identities: dict[str, object] = {
        "proofSuiteId": None,
        "artifactSha3_512": None,
        "verifierExecutableSha3_512": None,
    }
    if state != "UNSELECTED":
        identities = {
            "proofSuiteId": "synthetic-suite-v2",
            "artifactSha3_512": "b" * 128,
            "verifierExecutableSha3_512": "c" * 128,
        }
    return {
        "schema_version": gate.PIN_SCHEMA,
        "selection_state": state,
        **identities,
        "production_usable": production,
        "activation": activation,
    }


def _encode(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def test_current_inspect_is_canonical_and_nonqualifying() -> None:
    result = gate.inspect_current()
    assert set(result) == {
        "qualification_state",
        "activation_state",
        "qualification_open",
        "activation_open",
        "selection_state",
        "proofSuiteId",
        "production_usable",
        "activation",
        "blockersSha3_512",
        "pinSha3_512",
        "opsAuthority",
    }
    assert result["qualification_state"] == "NOT_QUALIFIED"
    assert result["activation_state"] == "INACTIVE"
    assert result["selection_state"] == "UNSELECTED"
    assert result["proofSuiteId"] is None
    assert result["production_usable"] is False
    assert result["activation"] is False
    assert result["qualification_open"] == list(gate.QUALIFICATION_IDS)
    assert result["activation_open"] == list(gate.ACTIVATION_IDS)
    assert len(result["blockersSha3_512"]) == 128
    assert len(result["pinSha3_512"]) == 128


def test_ops_authority_exact_set_is_verified() -> None:
    assert ops_authority.verify_ops_authority() == ops_authority.OPS_AUTHORITY_STATUS
    assert tuple(name for name, _, _ in ops_authority.EXPECTED_OPS_FILES) == tuple(
        sorted(name for name, _, _ in ops_authority.EXPECTED_OPS_FILES)
    )
    assert len(ops_authority.EXPECTED_OPS_FILES) == 7


def test_duplicate_unknown_missing_nonfinite_and_cap_reject() -> None:
    raws = (
        b'{"schema_version":"blind_ledger_launch_blockers_v2","schema_version":"x","blockers":[]}',
        b'{"schema_version":"blind_ledger_launch_blockers_v2","blockers":[],"extra":1}',
        b'{"schema_version":"blind_ledger_launch_blockers_v2"}',
        b'{"schema_version":"blind_ledger_launch_blockers_v2","blockers":NaN}',
        b"x" * (gate.MAX_AUTHORITY_BYTES + 1),
    )
    for raw in raws:
        with pytest.raises(gate.QualificationGateError):
            gate.parse_blockers(raw)


def test_exact_type_rejection_never_treats_bool_as_integer_or_string() -> None:
    value = {"schema_version": gate.BLOCKER_SCHEMA, "blockers": _blockers()}
    value["blockers"][0]["status"] = True
    with pytest.raises(gate.QualificationGateError):
        gate.parse_blockers(_encode(value))
    pin = _pin()
    pin["production_usable"] = 0
    with pytest.raises(gate.QualificationGateError):
        gate.parse_pin(_encode(pin))


def test_open_evidence_and_closed_without_evidence_reject() -> None:
    value = {"schema_version": gate.BLOCKER_SCHEMA, "blockers": _blockers()}
    value["blockers"][0]["evidenceSha3_512"] = "a" * 128
    with pytest.raises(gate.QualificationGateError):
        gate.parse_blockers(_encode(value))
    value = {"schema_version": gate.BLOCKER_SCHEMA, "blockers": _blockers(qualification_closed=True)}
    value["blockers"][0]["evidenceSha3_512"] = None
    with pytest.raises(gate.QualificationGateError):
        gate.parse_blockers(_encode(value))


def test_open_blocker_cannot_flip_activation() -> None:
    with pytest.raises(gate.QualificationGateError):
        gate.evaluate(_blockers(), _pin("QUALIFIED", production=True, activation=True))


def test_closed_qualification_blockers_require_qualified_pin() -> None:
    with pytest.raises(gate.QualificationGateError):
        gate.evaluate(_blockers(qualification_closed=True), _pin())
    with pytest.raises(gate.QualificationGateError):
        gate.evaluate(_blockers(qualification_closed=True), _pin("CANDIDATE"))


def test_fully_closed_synthetic_fixture_evaluates_active() -> None:
    result = gate.evaluate(
        _blockers(activation_closed=True),
        _pin("QUALIFIED", production=True, activation=True),
    )
    assert result.qualification_state == "QUALIFIED"
    assert result.activation_state == "ACTIVE"
    assert result.qualification_open == ()
    assert result.activation_open == ()


def test_production_usable_is_distinct_from_activation() -> None:
    result = gate.evaluate(
        _blockers(qualification_closed=True),
        _pin("QUALIFIED", production=True),
    )
    assert result.qualification_state == "QUALIFIED"
    assert result.activation_state == "INACTIVE"
    assert result.activation_open == tuple(gate.ACTIVATION_IDS[6:])


def test_cli_outputs_are_fixed_and_current_require_commands_fail_closed() -> None:
    command = [sys.executable, "-m", "tools.qualification_gate"]
    inspect = subprocess.run(command + ["inspect"], cwd=ROOT, capture_output=True, text=True)
    assert inspect.returncode == 0
    assert inspect.stderr == ""
    assert set(json.loads(inspect.stdout)) == {
        "qualification_state",
        "activation_state",
        "qualification_open",
        "activation_open",
        "selection_state",
        "proofSuiteId",
        "production_usable",
        "activation",
        "blockersSha3_512",
        "pinSha3_512",
        "opsAuthority",
    }
    production = subprocess.run(command + ["require-production"], cwd=ROOT, capture_output=True, text=True)
    activation = subprocess.run(command + ["require-activation"], cwd=ROOT, capture_output=True, text=True)
    assert production.returncode == 1
    assert production.stdout == ""
    assert production.stderr == "qualification_gate=not_production_usable\n"
    assert activation.returncode == 1
    assert activation.stdout == ""
    assert activation.stderr == "qualification_gate=not_activated\n"


def test_cli_invalid_and_authority_failures_are_sanitized() -> None:
    output = io.StringIO()
    with redirect_stderr(output):
        assert gate.main(["--repo-root", "C:\\private\\host\\path"]) == 2
    assert output.getvalue() == "qualification_gate=invalid\n"
    assert "private" not in output.getvalue()
    output = io.StringIO()
    with patch.object(gate, "_read_authority", side_effect=ValueError("C:\\secret\\raw.json")):
        with redirect_stderr(output):
            assert gate.main(["inspect"]) == 2
    assert output.getvalue() == "qualification_gate=invalid\n"
    assert "secret" not in output.getvalue()


def test_ops_authority_cli_has_one_fixed_success_line() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "tools.ops_authority"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == "ops_authority=verified\n"
    assert result.stderr == ""
