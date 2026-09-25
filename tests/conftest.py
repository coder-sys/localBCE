"""Fail-closed enforcement for the semantic assurance gate's real-candidate
tests (tests/test_semantic_assurance_gate.py).

Those tests clone the actual external Lean/Git candidate and only run when
BLIND_LEDGER_SEMANTIC_CANDIDATE names it -- the semantic assurance gate sets
that variable before invoking pytest. An ordinary full-suite run has no such
candidate, so the tests skip themselves with a specific reason instead of
being red on every run (see the `_REQUIRES_REAL_CANDIDATE` marker there).

But plain pytest treats "0 selected", "all skipped" and "all deselected" as a
passing run. If the gate's candidate wiring ever broke, or a filter excluded
the real tests, that would let a broken gate report green. This hook makes it
a hard failure instead: when BLIND_LEDGER_SEMANTIC_CANDIDATE is configured,
every real-candidate test must actually run and pass, or the whole run fails
closed.
"""
from __future__ import annotations

import os

CANDIDATE_ENVIRONMENT_VARIABLE = "BLIND_LEDGER_SEMANTIC_CANDIDATE"
_REAL_TEST_FILENAME = "test_semantic_assurance_gate.py"
_REAL_TEST_PREFIX = "test_real_"


def _required_real_test_names() -> frozenset[str]:
    from tests.test_semantic_assurance_gate import (
        SemanticAssuranceGateNegativeTests as gate_tests,
    )

    return frozenset(
        name for name in vars(gate_tests) if name.startswith(_REAL_TEST_PREFIX)
    )


def _is_real_gate_test(nodeid: str) -> bool:
    path = nodeid.split("::", 1)[0]
    if not path.replace("\\", "/").endswith(_REAL_TEST_FILENAME):
        return False
    return any(part.startswith(_REAL_TEST_PREFIX) for part in nodeid.split("::"))


def pytest_sessionfinish(session, exitstatus) -> None:
    if not os.environ.get(CANDIDATE_ENVIRONMENT_VARIABLE):
        return  # ordinary run: the tests skip themselves; nothing to enforce
    terminalreporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if terminalreporter is None:
        return
    passed_real_names = {
        report.nodeid.rsplit("::", 1)[-1]
        for report in terminalreporter.stats.get("passed", [])
        if _is_real_gate_test(report.nodeid)
    }
    missing = _required_real_test_names() - passed_real_names
    if missing:
        terminalreporter.write_line(
            "SEMANTIC_ASSURANCE_GATE_ENFORCEMENT=FAIL "
            f"{CANDIDATE_ENVIRONMENT_VARIABLE} is configured, so every real-candidate "
            f"test must run and pass; not passed: {sorted(missing)!r}"
        )
        session.exitstatus = 1
