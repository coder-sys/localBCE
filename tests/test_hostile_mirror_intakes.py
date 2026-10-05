"""Hostile bytes at the Mirror intakes: FHIR adapter and independent checker, trust-graph parse, read model, view bundle, export verifier.

Fixed seeds, bounded cases.  Every case is a typed refusal or a FAILED page (I2), deterministic on a repeat (I3), under one
second and within the byte cap (I4), with a fixed code and no raw bytes (I6); an unknown field is refused (I5).  The
intakes are pure functions with no store, so there is no write for I1 to guard."""

import json
import random
import re
import time
import unittest

from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_evidence_export_v1 as export
from app.mirror import provider_evidence_export_v1_independent as export_independent
from app.mirror import provider_trust_graph as graph
from app.mirror import provider_trust_graph_read_model_v1 as read_model
from tests import test_mirror_provider_evidence_export_v1 as export_tests
from tests import test_mirror_provider_trust_graph_read_model_v1 as read_tests
from tests.test_nc_medicaid_fhir_source import _bundle, _envelope
from tools import provider_trust_graph_view as view

_CODE = re.compile(r"[a-z0-9:_.-]{1,96}")
_REF = "a" * 64
_BOUND_SECONDS = 1.0


def _fixed(base: bytes) -> list[bytes]:
    """The named hostile shapes: deep nesting, huge integer, BOM, NUL, duplicate key, oversize."""
    key = base[1:base.index(b":")]
    return [
        b'{"a":' + b"[" * 2000 + b"]" * 2000 + b"}", b'{"a":' + b"9" * 5000 + b"}", b"\xef\xbb\xbf" + base,
        base[:1] + b"\x00" + base[1:], base[:-1] + b"," + key + b":0}", base + b" " * 2_000_000,
    ]


def _mutants(base: bytes, seeds: int):
    """Seeded truncation, one flipped bit, or one inserted byte at a seeded offset."""
    for seed in range(seeds):
        rng = random.Random(seed)
        at = rng.randrange(len(base))
        if seed % 3 == 0:
            yield base[:at]
        elif seed % 3 == 1:
            yield base[:at] + bytes([base[at] ^ (1 << rng.randrange(8))]) + base[at + 1:]
        else:
            yield base[:at] + rng.choice((b"\x00", b"\xff", b'"', b"[", b"\\")) + base[at:]


class HostileMirrorIntakeTests(unittest.TestCase):
    def _outcome(self, call, allowed: tuple, raw: bytes, case: int) -> tuple:
        """("ok", result) or ("refused", code); any other exception or a slow call fails with the case number only."""
        started = time.perf_counter()
        try:
            outcome = ("ok", call(raw))
        except allowed as error:
            self.assertIsNotNone(_CODE.fullmatch(str(error)), f"case {case}: code shape")
            outcome = ("refused", str(error))
        except Exception as error:
            self.fail(f"case {case}: untyped {type(error).__name__}")
        self.assertLess(time.perf_counter() - started, _BOUND_SECONDS, f"case {case}: slow")
        return outcome

    def _sweep(self, call, allowed: tuple, base: bytes, seeds: int, *, strict_keys: bool = False) -> None:
        fixed = _fixed(base)
        for case, raw in enumerate(fixed + list(_mutants(base, seeds))):
            first = self._outcome(call, allowed, raw, case)
            self.assertEqual(first, self._outcome(call, allowed, raw, case), f"case {case}: repeat differs")
            if case < len(fixed):
                self.assertEqual("refused", first[0], f"case {case}: hostile shape accepted")
        if strict_keys:
            extra = fhir.canonical_json({**json.loads(base), "zz": 1})
            self.assertEqual("refused", self._outcome(call, allowed, extra, -1)[0], "unknown field accepted")

    def test_fhir_adapter_fails_the_page_not_the_capture(self) -> None:
        url = profile.NC_MEDICAID_PROFILE.page_url(0, None)

        def capture(body: bytes) -> bytes:
            response = fhir.FhirTransportResponse(url, 200, fhir.ALLOWED_MEDIA_TYPE, body)
            return fhir.build_fixture_envelope(fhir.SyntheticFhirTransport({(url, 0): response}))

        base = fhir.canonical_json(_bundle())
        fixed = _fixed(base)
        for case, body in enumerate(fixed + list(_mutants(base, 500))):
            raw = self._outcome(capture, (), body, case)[1]
            self.assertEqual(raw, capture(body), f"case {case}: repeat differs")
            value = json.loads(raw)
            self.assertIn(value["source_status"], fhir.SOURCE_STATUSES)
            self.assertIn(value["failure_code"], fhir.FAILURE_CODES | {None})
            if case < len(fixed):
                self.assertEqual(("FAILED", "schema"), (value["source_status"], value["failure_code"]), f"case {case}")

    def test_fhir_independent_checker(self) -> None:
        self._sweep(fhir_independent.verify_bytes, (fhir_independent.IndependentNcMedicaidFhirError,), _envelope(), 500, strict_keys=True)

    def test_trust_graph_parse_canonical(self) -> None:
        artifact = read_tests._admission().graph_artifact
        self._sweep(lambda raw: graph.parse_canonical(raw, artifact=True), (graph.ProviderTrustGraphError,), artifact, 500)

    def test_read_model_selection(self) -> None:
        artifact = read_tests._admission().graph_artifact
        self._sweep(read_tests._read, (read_model.ProviderTrustGraphReadModelV1Error,), artifact, 100)

    def test_view_bundle(self) -> None:
        artifact = read_tests._admission().graph_artifact
        call = lambda raw: view._build_bundle(read_tests._selection(raw), now=7_000)
        self._sweep(call, (read_model.ProviderTrustGraphReadModelV1Error, view._LocalViewError), artifact, 100)

    def test_export_verifier(self) -> None:
        raw = export.build_export(export_tests._request(_REF), export_tests._selection(), now=7_000)
        call = lambda body: export_independent.verify_export(body, expected_operation_ref=_REF, now=7_000)
        self._sweep(call, (export_independent.IndependentProviderEvidenceExportError,), raw, 100, strict_keys=True)


if __name__ == "__main__":
    unittest.main()
