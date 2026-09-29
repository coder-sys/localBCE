"""Focused checks for the loopback-only synthetic staff workspace."""

from __future__ import annotations

from contextlib import closing, contextmanager
import http.client
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from app import right_rail_financial_owner_independent as independent
from app import right_rail_financial_engine as financial_engine
from app.right_rail_financial_mirror import (
    FinancialMirror,
    FinancialMirrorContinuityError,
    FinancialMirrorDispatchError,
)
from app.right_rail_financial_owner import (
    FinancialBusyError,
    FinancialConflictError,
    FinancialContinuityError,
    FinancialDispatchError,
    FinancialInputError,
    FinancialOwner,
    FinancialRevisionError,
)
from app.right_rail_financial_followthrough import build_followthrough_pack
from tests.test_right_rail_financial_acceptance import _correction_transition_test_release

from app.right_rail_financial_staff_server import (
    CASH_CORRECTION_COMMAND,
    H_CASH_CENTS,
    H_ITEM_ID,
    H_OWED_CENTS,
    H_SHORTFALL_CENTS,
    ITEM_IDS,
    PROGRAM_TOTAL_CENTS,
    SUPPORT_EVENT_MS,
    StaffWorkflow,
    _COMMAND_ROUTES,
    _LoopbackServer,
    _handler_for,
    _request_allowed,
)


class RightRailFinancialStaffWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="rightrail-staff-workspace-test-")
        self.addCleanup(self.temp_dir.cleanup)

    def _workflow(
        self,
        *,
        with_correction_release: bool = False,
        workspace_dir: Path | None = None,
    ) -> StaffWorkflow:
        workspace = workspace_dir or Path(self.temp_dir.name)
        release = None
        if with_correction_release:
            release = _correction_transition_test_release(
                workspace=workspace / "correction-engine-workspace"
            )
        workflow = StaffWorkflow(
            workspace,
            correction_transition_release=release,
        )
        self.addCleanup(workflow.close)
        return workflow

    def test_server_cli_loads_only_an_explicit_exact_engine_artifact(self) -> None:
        from app import right_rail_financial_staff_server as staff_server

        artifact = b"synthetic pinned engine artifact"
        executable = Path(self.temp_dir.name) / "blind_financial_correction.exe"
        executable.write_bytes(artifact)
        engine_workspace = Path(self.temp_dir.name) / "engine-work"
        engine_workspace.mkdir()
        owner_workspace = Path(self.temp_dir.name) / "owner-work"
        owner_workspace.mkdir()
        artifact_digest = hashlib.sha256(artifact).digest()

        with (
            patch.object(financial_engine, "CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES", len(artifact)),
            patch.object(financial_engine, "CORRECTION_TRANSITION_ARTIFACT_SHA256", artifact_digest),
            patch.object(staff_server, "serve") as serve,
        ):
            self.assertEqual(
                staff_server.main([
                    "--port", "0",
                    "--workspace", str(owner_workspace),
                    "--correction-transition-executable", str(executable),
                    "--correction-transition-workspace", str(engine_workspace),
                ]),
                0,
            )

        release = serve.call_args.kwargs["correction_transition_release"]
        self.assertIs(type(release), financial_engine.FinancialCorrectionTransitionRelease)
        self.assertEqual(release.executable, executable)
        self.assertEqual(release.executable_sha256, artifact_digest)
        self.assertEqual(release.request_vector_sha256, financial_engine.CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256)
        self.assertEqual(release.result_vector_sha256, financial_engine.CORRECTION_TRANSITION_RESULT_VECTOR_SHA256)
        self.assertEqual(serve.call_args.kwargs["workspace_dir"], owner_workspace)

    def test_server_cli_rejects_partial_engine_configuration(self) -> None:
        from app import right_rail_financial_staff_server as staff_server

        with patch.object(staff_server, "serve") as serve:
            with self.assertRaises(SystemExit):
                staff_server.main(["--correction-transition-executable", "C:\\fixture\\engine.exe"])
        serve.assert_not_called()

    def _http_json(self, port: int, path: str, body: dict[str, object] | None = None, *, timeout: float = 5) -> dict[str, object]:
        host = f"127.0.0.1:{port}"
        headers = {"Host": host, "Origin": f"http://{host}", "Content-Type": "application/json"}
        with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)) as connection:
            connection.request("GET" if body is None else "POST", path,
                               body=None if body is None else json.dumps(body, separators=(",", ":")), headers=headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            return json.loads(response.read().decode("utf-8"))

    def _serve_workflow(self, workflow: StaffWorkflow, handler_type=None):
        server = _LoopbackServer(("127.0.0.1", 0), handler_type or _handler_for(workflow))
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        return server

    def _second_owner(self, owner: FinancialOwner) -> FinancialOwner:
        writer = FinancialOwner(path=owner.path, config=owner.config,
                                trusted_authority=owner.trusted_authority, clock=owner.clock,
                                mode=owner.mode, owner_id=owner.owner_id)
        self.addCleanup(writer.close)
        return writer

    @staticmethod
    def _lose_first_response(handler_type, route: str) -> list[bool]:
        original_respond, lost = handler_type._respond, []
        def respond(handler, status, payload, content_type="application/json"):
            if not lost and handler.command == "POST" and handler.path == route and status == 200:
                lost.append(True)  # drop the whole response only after the Owner committed
                handler.close_connection = True
                try:
                    handler.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                handler.connection.close()
            else:
                original_respond(handler, status, payload, content_type)
        handler_type._respond = respond
        return lost

    def test_service_kit_correction_lost_response_retry_and_shadow_restore(self) -> None:
        run_workspace = Path(os.environ.get("RR_FINANCIAL_SERVICE_KIT_TEST_WORKSPACE", self.temp_dir.name))
        workflow = self._workflow(with_correction_release=True, workspace_dir=run_workspace)
        owner = workflow.mirror.owner
        self.assertEqual(owner.mode, "TEST")
        handler_type = _handler_for(workflow)
        lost = self._lose_first_response(handler_type, "/api/decision/reject-offset")
        server = self._serve_workflow(workflow, handler_type)
        port = int(server.server_address[1])
        before_view = self._http_json(port, "/api/decision-package")
        before_package = owner.export_continuity()
        before_integrity = owner.verify_integrity()
        sequence_before = int(before_integrity["sequence"])
        counts_before = before_integrity["counts"]
        command = self._review_body(workflow, view=before_view)

        # The server drops the entire response after the Owner command commits.
        with self.assertRaises(http.client.RemoteDisconnected):
            self._http_json(port, "/api/decision/reject-offset", command)
        self.assertEqual(lost, [True])
        committed_package = owner.export_continuity()
        committed_integrity = owner.verify_integrity()
        self.assertEqual(int(committed_integrity["sequence"]), sequence_before + 1)
        for table in ("determinations", "actions", "events"):
            self.assertEqual(
                int(committed_integrity["counts"][table]),
                int(counts_before[table]) + 1,
            )

        retry = self._http_json(port, "/api/decision/reject-offset", command)
        self.assertEqual(retry["command"]["status"], "DUPLICATE")
        self.assertEqual(owner.export_continuity(), committed_package)
        self.assertEqual(int(owner.verify_integrity()["sequence"]), sequence_before + 1)

        staff_readback = self._http_json(port, "/api/decision-package")
        mirror_readback = workflow.mirror.decision_package(H_ITEM_ID, limit=100, offset=0)
        self.assertIs(workflow.mirror.owner, owner)
        for field in (
            "contract", "scope", "obligation", "evaluation_receipt", "control_pack",
            "case", "current_determination", "current_action", "cash", "reporting",
            "references", "conclusions",
        ):
            self.assertEqual(staff_readback["decision_package"][field], mirror_readback[field])
        self.assertNotEqual(before_view["decision_package"], staff_readback["decision_package"])
        self.assertEqual(owner.verify_integrity()["mode"], "TEST")

        shadow_path = run_workspace / "service-kit-shadow.sqlite"
        shadow = workflow.mirror.restore_continuity(committed_package, shadow_path)
        self.addCleanup(shadow.owner.close)
        self.assertEqual(shadow.verify_integrity()["mode"], "SHADOW")
        self.assertIs(shadow.summary()["dispatch_enabled"], False)
        self.assertIs(shadow.summary()["egress_enabled"], False)
        self.assertEqual(shadow.decision_package(H_ITEM_ID, limit=100, offset=0), mirror_readback)

        shadow_package_before_write = shadow.export_continuity()
        with self.assertRaises(FinancialDispatchError) as read_only:
            shadow.owner.record_support_evidence(
                item_id=H_ITEM_ID,
                evidence_id="evidence:shadow-write-must-fail",
                common_origin_id="origin:shadow-write-must-fail",
            )
        self.assertEqual(str(read_only.exception), "shadow_owner_read_only")
        with self.assertRaises(FinancialMirrorDispatchError) as dispatch:
            shadow.dispatch_outbox()
        self.assertEqual(str(dispatch.exception), "dispatch_disabled")
        self.assertEqual(shadow.export_continuity(), shadow_package_before_write)

        restored_bytes = shadow_path.read_bytes()
        with self.assertRaises(FinancialMirrorContinuityError) as replacement:
            workflow.mirror.restore_continuity(committed_package, shadow_path)
        self.assertEqual(str(replacement.exception), "continuity_destination")
        self.assertEqual(shadow_path.read_bytes(), restored_bytes)
        self.assertIs(workflow.mirror.owner, owner)
        self.assertEqual(owner.export_continuity(), committed_package)
        self.assertNotEqual(before_package, committed_package)
        print("SERVICE_KIT_SCENARIO " + json.dumps({
            "contract": "RR/FINANCIAL/SERVICE-KIT-SCENARIO/v1",
            "status": "PASS",
            "source_mode": "TEST",
            "owner_sequence_before": sequence_before,
            "owner_sequence_after_exact_retry": int(owner.verify_integrity()["sequence"]),
            "correction_commit_count": 1,
            "exact_retry": "DUPLICATE_NO_SECOND_WRITE",
            "staff_mirror_same_owner": True,
            "independent_integrity": "VERIFIED",
            "shadow_restore": "VERIFIED_READ_ONLY",
            "replacement_attempt": "REJECTED",
            "dispatch_enabled": False,
            "egress_enabled": False,
            "production_usable": False,
            "activation": False,
            "proof_suite_id": None,
        }, sort_keys=True, separators=(",", ":")))

    @staticmethod
    def _review_body(workflow: StaffWorkflow, *, view: dict[str, object] | None = None) -> dict[str, object]:
        view = workflow.decision_view() if view is None else view
        package = view["decision_package"]
        return {
            "revision": package["obligation"]["revision"],
            "evaluation_id": package["evaluation_receipt"]["evaluation_id"],
            "evaluation_result_digest": package["evaluation_receipt"]["result_digest"],
            "read_binding": StaffWorkflow._staff_command_binding(view),
        }

    @staticmethod
    def _revision_body(workflow: StaffWorkflow) -> dict[str, object]:
        return {"revision": workflow.decision_view()["decision_package"]["obligation"]["revision"]}

    @staticmethod
    def _cash_body(workflow: StaffWorkflow) -> dict[str, object]:
        return {
            **RightRailFinancialStaffWorkspaceTests._revision_body(workflow),
            "cash_command": dict(CASH_CORRECTION_COMMAND),
        }

    def test_population_and_unknown_source_are_visible(self) -> None:
        workflow = self._workflow()
        snapshot = workflow.workspace()
        package = workflow.decision_view()["decision_package"]

        self.assertEqual(len(snapshot["items"]), 20)
        self.assertEqual({item["item_id"] for item in snapshot["items"]}, set(ITEM_IDS))
        self.assertEqual(snapshot["summary"]["obligation_count"], 20)
        self.assertEqual(snapshot["summary"]["owed_cents"], PROGRAM_TOTAL_CENTS)
        self.assertEqual(snapshot["population"]["imported_count"], 20)
        self.assertEqual(snapshot["population"]["completeness"], "EXACT")
        self.assertEqual(snapshot["source_assessment"]["status"], "UNKNOWN")
        self.assertEqual(snapshot["source_assessment"]["h_support_status"], "MISSING")
        self.assertEqual(snapshot["freshness"]["status"], "UNKNOWN")
        self.assertEqual(snapshot["read_envelope"]["contract"], "RR/FINANCIAL/STAFF-READ-ENVELOPE/v1")
        self.assertEqual(snapshot["read_envelope"]["verification"]["sequence"], snapshot["summary"]["sequence"])
        self.assertEqual(snapshot["read_envelope"]["read_cost"]["owner_connection_acquisitions"], 1)
        self.assertEqual(snapshot["read_envelope"]["read_cost"]["independent_verifier_connection_acquisitions"], 0)
        self.assertEqual(snapshot["nonactivation"]["proof_suite_id"], None)
        self.assertFalse(snapshot["nonactivation"]["dispatch_enabled"])
        self.assertFalse(snapshot["nonactivation"]["egress_enabled"])

        h = package["obligation"]
        self.assertEqual(h["item_id"], H_ITEM_ID)
        self.assertEqual(h["owed_cents"], H_OWED_CENTS)
        self.assertEqual(h["received_cash_cents"], H_CASH_CENTS)
        self.assertEqual(h["shortfall_cents"], H_SHORTFALL_CENTS)
        self.assertEqual(h["lawful_adjustment_cents"], 0)
        self.assertIsNone(package["current_determination"])
        self.assertEqual(package["reporting"]["complete"], False)

    def test_ack_cash_reporting_and_test_restore_remain_separate(self) -> None:
        workflow = self._workflow(with_correction_release=True)
        decision = workflow.reject_offset_and_authorize_correction(self._review_body(workflow))
        self.assertEqual(decision["command"]["status"], "CORRECTION_AUTHORIZED")

        acknowledgment = workflow.acknowledge_correction_action(self._revision_body(workflow))
        self.assertEqual(acknowledgment["cash_before_cents"], H_CASH_CENTS)
        self.assertEqual(acknowledgment["cash_after_cents"], H_CASH_CENTS)
        self.assertEqual(acknowledgment["cash_effect_cents"], 0)
        ack_package = workflow.decision_view()["decision_package"]
        self.assertEqual(ack_package["current_action"]["status"], "ACKNOWLEDGED")
        self.assertGreaterEqual(ack_package["current_action"]["acknowledgment"]["updated_at_ms"], ack_package["current_action"]["created_at_ms"])
        self.assertEqual(ack_package["cash"]["shortfall_cents"], H_SHORTFALL_CENTS)
        self.assertEqual(ack_package["reporting"]["complete"], False)

        cash_result = workflow.record_cash_correction(self._cash_body(workflow))
        self.assertFalse(cash_result["money_movement"])
        cash_package = workflow.decision_view()["decision_package"]
        self.assertEqual(cash_package["cash"]["recorded_received_cash_cents"], H_OWED_CENTS)
        self.assertEqual(cash_package["cash"]["shortfall_cents"], 0)
        self.assertEqual(cash_package["reporting"]["complete"], False)
        with closing(sqlite3.connect(workflow.mirror.owner.path)) as check:
            self.assertEqual(check.execute(
                "SELECT json_extract(payload_json,'$.pays_action_id') FROM financial_events "
                "WHERE kind='PAYMENT_RECEIVED' AND json_extract(payload_json,'$.payment_id')='payment:h:p2'"
            ).fetchone(), ("action:obligation-item-h:correction-v1",))

        workflow.record_reporting_evidence(self._revision_body(workflow))
        report_package = workflow.decision_view()["decision_package"]
        self.assertTrue(report_package["reporting"]["complete"])
        self.assertEqual(report_package["cash"]["recorded_received_cash_cents"], H_OWED_CENTS)

        restored = workflow.restore_test(self._review_body(workflow))
        self.assertEqual(restored["continuity"]["mode"], "TEST")
        self.assertTrue(restored["continuity"]["decision_package_equal"])
        self.assertEqual(restored["workspace"]["integrity"]["mode"], "TEST")
        self.assertFalse(restored["workspace"]["nonactivation"]["dispatch_enabled"])
        self.assertFalse(restored["workspace"]["nonactivation"]["egress_enabled"])
        self.assertFalse(restored["workspace"]["nonactivation"]["production_usable"])
        self.assertFalse(restored["workspace"]["nonactivation"]["activation"])
        self.assertIsNone(restored["workspace"]["nonactivation"]["proof_suite_id"])
        self.assertEqual(restored["workspace"]["h"]["obligation"]["shortfall_cents"], 0)

    def test_h_store_followthrough_chain(self) -> None:
        workflow = self._workflow(with_correction_release=True)
        owner = workflow.mirror.owner
        rules = (Path(__file__).resolve().parents[1] / "app" / "fixtures" / "h_followthrough_rules_v1.json").read_bytes()
        scope = {key: getattr(owner.config, key) for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")}

        def items(at_ms: int) -> dict[str, dict]:
            pack = build_followthrough_pack(owner.path, owner.export_continuity(), trusted_authority=owner.trusted_authority, expected_scope=scope, rules_bytes=rules, generated_at_ms=at_ms)
            return {item["item_id"]: item for item in json.loads(pack)["items"]}

        def query(sql: str) -> tuple:
            with closing(sqlite3.connect(owner.path)) as check:
                return check.execute(sql).fetchone()

        workflow.reject_offset_and_authorize_correction(self._review_body(workflow))
        sequence, at_ms = query("SELECT event_sequence,committed_at_ms FROM financial_events WHERE aggregate_type='OBLIGATION' AND kind='OFFSET_REJECTED_CORRECTION_AUTHORIZED'")
        h = items(at_ms + 1)[H_ITEM_ID]
        self.assertEqual((h["found"]["party"], h["found"]["source_owner_id"], h["status"]), ("STATE", "source-owner:fixture-state-finance-v1", "OPEN"))
        self.assertEqual(h["owner"], {"owner_id": "state:provider-finance", "basis": "RULES_DEFAULT", "decision_id": None})
        (clock,) = h["clocks"]
        self.assertEqual(clock["anchor"], {"source": "EVENT:OFFSET_REJECTED_CORRECTION_AUTHORIZED", "at_ms": at_ms, "recorded_at_ms": at_ms, "evidence_id": None, "evidence_record_digest": None, "event_sequence": sequence})
        self.assertEqual((clock["clock_id"], clock["ends_ms"], clock["status"]), ("correction-payment", at_ms + 30 * 86_400_000, "RUNNING"))

        workflow.acknowledge_correction_action(self._revision_body(workflow))
        workflow.record_cash_correction(self._cash_body(workflow))
        (collected,) = query(f"SELECT MAX(event_at_ms) FROM payments WHERE obligation_id='{h['obligation_id']}' AND active=1")  # the collection date, not the evaluation's recording time
        done = items(query("SELECT MAX(committed_at_ms) FROM financial_events")[0] + 1)
        (clock,) = done[H_ITEM_ID]["clocks"]
        self.assertEqual((done[H_ITEM_ID]["status"], done[H_ITEM_ID]["federal_share"], clock["status"], clock["satisfied"]["at_ms"]), ("SATISFIED", None, "MET", collected))
        self.assertEqual({clock["status"] for item in done.values() if item["item_id"] != H_ITEM_ID for clock in item["clocks"]}, {"NOT_ANCHORED"})
        self.assertEqual(len(done), 20)

    def test_decision_leaves_correction_followup_current(self) -> None:
        workflow = self._workflow(with_correction_release=True)
        owner = workflow.mirror.owner
        workflow.reject_offset_and_authorize_correction(self._review_body(workflow))
        workflow.acknowledge_correction_action(self._revision_body(workflow))
        workflow.record_cash_correction(self._cash_body(workflow))
        status = lambda: workflow.correction_followup()["followup"]["followup_status"]
        before = workflow.decision_view()["decision_package"]
        self.assertEqual(status(), "CURRENT")
        decided = owner.record_followthrough_decision(
            item_id=H_ITEM_ID, decision_id="decision:h:assign", act="ASSIGN", owner_id="state:provider-finance",
            actor_id="synthetic-official", actor_role="CASE_OWNER", expected_revision=before["obligation"]["revision"],
        )
        after = workflow.decision_view()["decision_package"]
        self.assertEqual(decided["status"], "RECORDED")
        self.assertEqual(status(), "CURRENT")
        self.assertEqual((after["cash"], after["obligation"]["shortfall_cents"]), (before["cash"], before["obligation"]["shortfall_cents"]))

    def test_a_failed_test_restore_returns_a_valid_support_package_over_http(self) -> None:
        workflow = self._workflow()
        port = self._serve_workflow(workflow).server_address[1]
        host = f"127.0.0.1:{port}"
        failure = FinancialContinuityError("continuity_history_head")
        with patch.object(FinancialOwner, "restore_continuity", side_effect=failure):
            with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
                connection.request("POST", "/api/continuity/restore-test", body=json.dumps(self._review_body(workflow)),
                                   headers={"Host": host, "Origin": f"http://{host}", "Content-Type": "application/json"})
                response = connection.getresponse()
                body = json.loads(response.read().decode("utf-8"))
        self.assertEqual(response.status, 409)
        self.assertEqual(body["error"]["code"], "continuity_history_head")
        support = body["error"]["corporate_support"]
        self.assertEqual(support, FinancialMirror.continuity_restore_support(failure))
        self.assertEqual((support["contract"], support["status"], support["failure_stage"], support["error_class"]),
                         ("RR/FINANCIAL/CORPORATE-SUPPORT/v2", "FAILED", "RESTORE", "continuity_history_head"))
        self.assertEqual((support["rule_version"], support["adapter_versions"]["population"], support["work_ref_count"]), ("NONE", "NONE", 0))

    def test_ack_cash_effect_is_measured_before_and_after_the_command(self) -> None:
        workflow = self._workflow(with_correction_release=True)
        workflow.reject_offset_and_authorize_correction(self._review_body(workflow))
        reviewed = self._revision_body(workflow)
        with patch.object(
            workflow,
            "_h_received_cash_cents",
            side_effect=[H_CASH_CENTS, H_CASH_CENTS + 1],
        ) as cash_spy:
            acknowledgment = workflow.acknowledge_correction_action(reviewed)
        self.assertEqual(cash_spy.call_count, 2)
        self.assertEqual(acknowledgment["cash_before_cents"], H_CASH_CENTS)
        self.assertEqual(acknowledgment["cash_after_cents"], H_CASH_CENTS + 1)
        self.assertEqual(acknowledgment["cash_effect_cents"], 1)
        self.assertEqual(workflow._h_received_cash_cents(), H_CASH_CENTS)

    def test_same_workspace_reopens_verified_owner_and_durable_followup(self) -> None:
        workspace = Path(self.temp_dir.name)
        release = _correction_transition_test_release(
            workspace=workspace / "correction-engine-workspace"
        )
        workflow = StaffWorkflow(
            workspace,
            correction_transition_release=release,
        )
        self.addCleanup(workflow.close)
        owner_path = workflow.mirror.owner.path
        command = workflow.reject_offset_and_authorize_correction(self._review_body(workflow))
        self.assertEqual(command["command"]["status"], "CORRECTION_AUTHORIZED")
        sequence = int(workflow.mirror.owner.verify_integrity()["sequence"])
        self.assertEqual(workflow.correction_followup()["status"], "AVAILABLE")
        workflow.close()

        resumed = StaffWorkflow(
            workspace,
            correction_transition_release=release,
            resume_existing=True,
        )
        self.addCleanup(resumed.close)
        self.assertEqual(resumed.mirror.owner.path, owner_path)
        resumed_integrity = resumed.mirror.owner.verify_integrity()
        self.assertEqual(resumed_integrity["mode"], "TEST")
        self.assertEqual(resumed_integrity["owner_id"], resumed.mirror.owner.owner_id)
        self.assertEqual(int(resumed_integrity["sequence"]), sequence)
        self.assertEqual(resumed.correction_followup()["status"], "AVAILABLE")
        self.assertEqual(
            resumed.decision_view()["decision_package"]["current_action"]["status"],
            "READY",
        )

    def test_staff_server_process_restart_reopens_same_owner_without_reseed(self) -> None:
        workspace = Path(self.temp_dir.name) / "process-restart-owner"
        workspace.mkdir()
        engine_workspace = Path(self.temp_dir.name) / "process-restart-engine"
        release = _correction_transition_test_release(workspace=engine_workspace)
        repository_root = Path(__file__).resolve().parents[1]

        def reserve_port() -> int:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                return int(listener.getsockname()[1])

        def start_server(*, resume_existing: bool) -> tuple[subprocess.Popen[str], int]:
            port = reserve_port()
            command = [
                sys.executable,
                "-u",
                "-m",
                "app.right_rail_financial_staff_server",
                "--port",
                str(port),
                "--workspace",
                str(workspace),
                "--correction-transition-executable",
                str(release.executable),
                "--correction-transition-workspace",
                str(engine_workspace),
            ]
            if resume_existing:
                command.append("--resume-existing-workspace")
            process = subprocess.Popen(
                command,
                cwd=repository_root,
                env=os.environ.copy(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return process, port

        def stop_server(process: subprocess.Popen[str]) -> str:
            if process.poll() is None:
                process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
                self.fail(f"staff server did not stop: stdout={stdout!r} stderr={stderr!r}")
            self.assertEqual(stderr, "")
            return stdout

        def request_json(
            process: subprocess.Popen[str],
            port: int,
            path: str,
            *,
            method: str = "GET",
            body: dict[str, object] | None = None,
        ) -> dict[str, object]:
            deadline = time.monotonic() + 10
            last_error = "server_not_ready"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    self.fail(f"staff server exited before read: stdout={stdout!r} stderr={stderr!r}")
                try:
                    return self._http_json(port, path, body, timeout=1)
                except (OSError, http.client.HTTPException, AssertionError) as error:
                    last_error = str(error)
                    if method == "POST":
                        self.fail(f"staff command response unresolved: {last_error}")
                time.sleep(0.05)
            self.fail(f"staff server did not become ready: {last_error}")

        first_process, first_port = start_server(resume_existing=False)
        try:
            view = request_json(first_process, first_port, "/api/decision-package")
            package = view["decision_package"]
            request_json(first_process, first_port, "/api/decision/reject-offset", method="POST", body={
                "revision": package["obligation"]["revision"], "evaluation_id": package["evaluation_receipt"]["evaluation_id"],
                "evaluation_result_digest": package["evaluation_receipt"]["result_digest"], "read_binding": StaffWorkflow._staff_command_binding(view),
            })
            first = request_json(first_process, first_port, "/api/workspace")
            first_package = request_json(first_process, first_port, "/api/decision-package")["decision_package"]
            cash_result = request_json(
                first_process,
                first_port,
                "/api/correction/record-cash",
                method="POST",
                body={
                    "revision": first_package["obligation"]["revision"],
                    "cash_command": dict(CASH_CORRECTION_COMMAND),
                },
            )
            self.assertEqual(cash_result["command"]["status"], "RECORDED")
            self.assertFalse(cash_result["money_movement"])
            committed = cash_result["workspace"]
        finally:
            first_stdout = stop_server(first_process)
        self.assertIn("Synthetic RightRail staff workspace", first_stdout)
        first_envelope = first["read_envelope"]
        self.assertIsInstance(first_envelope, dict)
        first_identity = (
            first_envelope["owner_id"],
            first_envelope["continuity_epoch"],
            first_envelope["sequence"],
            first_envelope["history_head"],
        )
        committed_envelope = committed["read_envelope"]
        self.assertEqual(committed_envelope["owner_id"], first_identity[0])
        self.assertEqual(committed_envelope["continuity_epoch"], first_identity[1])
        self.assertEqual(committed_envelope["sequence"], first_envelope["sequence"] + 1)

        resumed_process, resumed_port = start_server(resume_existing=True)
        try:
            resumed = request_json(resumed_process, resumed_port, "/api/workspace")
        finally:
            resumed_stdout = stop_server(resumed_process)
        self.assertIn("Reopened the caller-owned synthetic TEST Owner workspace", resumed_stdout)
        resumed_envelope = resumed["read_envelope"]
        self.assertEqual(
            (
                resumed_envelope["owner_id"],
                resumed_envelope["continuity_epoch"],
                resumed_envelope["sequence"],
                resumed_envelope["history_head"],
            ),
            (
                committed_envelope["owner_id"],
                committed_envelope["continuity_epoch"],
                committed_envelope["sequence"],
                committed_envelope["history_head"],
            ),
        )
        self.assertEqual(resumed["summary"]["obligation_count"], len(ITEM_IDS))
        self.assertEqual(resumed["summary"]["owed_cents"], PROGRAM_TOTAL_CENTS)
        self.assertEqual(resumed["h"]["obligation"]["received_cash_cents"], H_OWED_CENTS)
        self.assertEqual(resumed["h"]["obligation"]["shortfall_cents"], 0)
        self.assertEqual(resumed["integrity"]["status"], "VERIFIED")

    def test_cash_exact_postcommit_retry_is_inert(self) -> None:
        workflow = self._workflow(with_correction_release=True)
        workflow.reject_offset_and_authorize_correction(self._review_body(workflow))
        owner = workflow.mirror.owner
        body = self._cash_body(workflow)
        original_revision = body["revision"]
        sequence_before = int(owner.verify_integrity()["sequence"])

        recorded = workflow.record_cash_correction(body)
        self.assertEqual(recorded["command"]["status"], "RECORDED")
        self.assertFalse(recorded["money_movement"])
        committed_bytes = owner.export_continuity()
        committed_sequence = int(owner.verify_integrity()["sequence"])
        self.assertEqual(committed_sequence, sequence_before + 1)

        duplicate = workflow.record_cash_correction(body)
        self.assertEqual(duplicate["command"]["status"], "DUPLICATE")
        self.assertEqual(int(owner.verify_integrity()["sequence"]), committed_sequence)
        self.assertEqual(owner.export_continuity(), committed_bytes)

    def test_http_cash_lost_response_retries_original_revision_once(self) -> None:
        workflow = self._workflow(with_correction_release=True)
        workflow.reject_offset_and_authorize_correction(self._review_body(workflow))
        owner = workflow.mirror.owner
        handler_type = _handler_for(workflow)
        lost = self._lose_first_response(handler_type, "/api/correction/record-cash")
        server = self._serve_workflow(workflow, handler_type)
        port = int(server.server_address[1])
        body = self._cash_body(workflow)
        original_revision = body["revision"]
        sequence_before = int(owner.verify_integrity()["sequence"])

        with self.assertRaises(http.client.RemoteDisconnected):
            self._http_json(port, "/api/correction/record-cash", body)
        self.assertEqual(lost, [True])
        committed_bytes = owner.export_continuity()
        committed_sequence = int(owner.verify_integrity()["sequence"])
        self.assertEqual(committed_sequence, sequence_before + 1)

        duplicate = self._http_json(port, "/api/correction/record-cash", body)
        self.assertEqual(duplicate["command"]["status"], "DUPLICATE")
        self.assertFalse(duplicate["money_movement"])
        self.assertEqual(int(owner.verify_integrity()["sequence"]), committed_sequence)
        self.assertEqual(owner.export_continuity(), committed_bytes)

        changed_input = dict(CASH_CORRECTION_COMMAND)
        changed_input["amount_cents"] += 1
        with self.assertRaises(FinancialConflictError) as changed_payment:
            owner.record_payment_evidence(
                **changed_input,
                expected_revision=original_revision,
            )
        self.assertEqual(str(changed_payment.exception), "payment_request_conflict")
        self.assertEqual(int(owner.verify_integrity()["sequence"]), committed_sequence)
        self.assertEqual(owner.export_continuity(), committed_bytes)

    def test_staff_correction_rejects_changed_binding_and_unrelated_snapshot(self) -> None:
        workflow = self._workflow()
        owner = workflow.mirror.owner

        altered = self._review_body(workflow)
        # Binding v2 carries the receipt digest (which binds the input snapshot
        # the Mirror withholds from staff); a changed one is a stale review.
        altered["read_binding"]["input"]["receipt_digest"] = "F" * 128
        before = owner.export_continuity()
        with self.assertRaises(FinancialRevisionError) as changed_input:
            workflow.reject_offset_and_authorize_correction(altered)
        self.assertEqual(str(changed_input.exception), "obligation_revision_conflict")
        self.assertEqual(owner.export_continuity(), before)

        stale = self._review_body(workflow)
        owner.record_support_evidence(
            item_id="item-01",
            evidence_id="evidence:support:item-01:late-v2",
            common_origin_id="origin:support:01:late-v2",
            source_id="fixture-source",
            source_version="support-v2",
            local_ref="ref:support:01:late-v2",
            applicable_at_ms=SUPPORT_EVENT_MS,
            event_at_ms=SUPPORT_EVENT_MS + 1,
        )
        after_unrelated_change = owner.export_continuity()
        with self.assertRaises(FinancialRevisionError) as stale_snapshot:
            workflow.reject_offset_and_authorize_correction(stale)
        self.assertEqual(str(stale_snapshot.exception), "obligation_revision_conflict")
        self.assertEqual(owner.export_continuity(), after_unrelated_change)

    def test_staff_mutations_require_revision_and_never_take_an_actor_from_the_request(self) -> None:
        workflow = self._workflow()
        bodies = {
            workflow.reject_offset_and_authorize_correction: self._review_body(workflow),
            workflow.acknowledge_correction_action: self._revision_body(workflow),
            workflow.record_cash_correction: self._cash_body(workflow),
            workflow.record_reporting_evidence: self._revision_body(workflow),
        }
        position = workflow.mirror.owner.export_continuity()
        for handler, body in bodies.items():
            missing = {key: value for key, value in body.items() if key != "revision"}
            with self.assertRaisesRegex(ValueError, r"\Arequest_shape\Z", msg=handler.__name__):
                handler(missing)
            for field in ("actor_id", "actor_role"):
                with self.assertRaisesRegex(ValueError, r"\Arequest_shape\Z", msg=handler.__name__):
                    handler({**body, field: "synthetic-official"})
        self.assertEqual(workflow.mirror.owner.export_continuity(), position)

        # Every staff command handler passes its actor and the reviewed revision
        # to the Mirror explicitly; none relies on a library default.
        import ast
        import inspect
        from app import right_rail_financial_staff_server as staff_server

        tree = ast.parse(inspect.getsource(staff_server.StaffWorkflow))
        actor_commands = {"reject_offset_and_authorize_correction", "acknowledge_action", "record_reporting_evidence"}
        handlers = {
            "reject_offset_and_authorize_correction",
            "acknowledge_correction_action",
            "record_cash_correction",
            "record_reporting_evidence",
        }
        seen = set()
        for function in ast.walk(tree):
            if not isinstance(function, ast.FunctionDef) or function.name not in handlers:
                continue
            for call in ast.walk(function):
                if not (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Attribute)
                    and call.func.value.attr == "_mirror"
                    and call.func.attr in actor_commands | {"record_payment_evidence"}
                ):
                    continue
                keywords = {keyword.arg for keyword in call.keywords}
                self.assertIn("expected_revision", keywords, function.name)
                if call.func.attr in actor_commands:
                    self.assertTrue({"actor_id", "actor_role"} <= keywords, function.name)
                seen.add(function.name)
        self.assertEqual(seen, handlers)

    def test_staff_binding_v2_withholds_input_snapshot_and_refuses_the_v1_shape(self) -> None:
        workflow = self._workflow()
        owner = workflow.mirror.owner
        body = self._review_body(workflow)
        # One binding scheme: v2 names the receipt digest and never the input snapshot the Mirror withholds.
        self.assertEqual(body["read_binding"]["contract"], "RR/FINANCIAL/STAFF-COMMAND-BINDING/v2")
        self.assertEqual(set(body["read_binding"]["input"]), {"evaluation_id", "evaluation_result_digest", "receipt_digest"})
        self.assertNotIn("input_snapshot_digest", workflow.decision_view()["decision_package"]["evaluation_receipt"])

        # Even the correct hidden value, added back in the v1 shape, is refused without mutation.
        v1_shaped = self._review_body(workflow)
        v1_shaped["read_binding"]["input"]["input_snapshot_digest"] = owner.current_evaluation_receipt(H_ITEM_ID)["input_snapshot_digest"]
        before = owner.export_continuity()
        with self.assertRaises(FinancialInputError) as malformed:
            workflow.reject_offset_and_authorize_correction(v1_shaped)
        self.assertEqual(str(malformed.exception), "staff_command_binding")
        self.assertEqual(owner.export_continuity(), before)

    def test_workspace_uses_one_verified_snapshot_and_has_no_item_detail_fanout(self) -> None:
        workflow = self._workflow(with_correction_release=True)
        first_owner = workflow.mirror.owner
        writer = self._second_owner(first_owner)
        self.assertEqual((writer.mode, writer.owner_id), ("TEST", "continuity-test-owner-v1"))
        before = first_owner.obligation_detail("item-01")
        connections = []
        transaction_states = []
        original_connect = first_owner._connect
        original_detail = first_owner.obligation_detail
        original_verify = independent.verify_database_connection

        def tracked_connect():
            connection = original_connect()
            connections.append(connection)
            return connection

        def tracked_detail(*args, **kwargs):
            return original_detail(*args, **kwargs)

        # The Owner database uses SQLite's rollback journal, so a second writer
        # cannot commit while this read snapshot is open: it waits (busy
        # timeout) and commits once the snapshot closes. The concurrent write
        # therefore runs on its own thread; a same-thread write here could only
        # deadlock into "database is locked".
        writer_threads: list[threading.Thread] = []
        writer_errors: list[BaseException] = []
        writer_pending_during_verification: list[bool] = []
        journal_path = Path(f"{first_owner.path}-journal")

        def concurrent_write() -> None:
            try:
                writer.record_support_evidence(
                    item_id="item-01",
                    evidence_id="evidence:staff-snapshot-interleave:item-01",
                    common_origin_id="origin:staff-snapshot-interleave:item-01",
                    source_id="fixture-source",
                    source_version="staff-interleave-v1",
                    local_ref="ref:staff-snapshot-interleave:item-01",
                    applicable_at_ms=1_767_312_000_000,
                    event_at_ms=1_767_312_000_001,
                    expected_revision=int(before["revision"]),
                )
            except BaseException as error:  # reported by the main thread below
                writer_errors.append(error)

        def write_during_verification(connection, **kwargs):
            transaction_states.append((connection.in_transaction, "before"))
            thread = threading.Thread(target=concurrent_write, daemon=True)
            writer_threads.append(thread)
            thread.start()
            # Wait until the writer is inside its write transaction (its
            # rollback journal exists) before verifying this snapshot.
            deadline = time.monotonic() + 4.0
            while not journal_path.exists() and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.002)
            writer_pending_during_verification.append(journal_path.exists() and thread.is_alive())
            result = original_verify(connection, **kwargs)
            transaction_states.append((connection.in_transaction, "after"))
            writer_pending_during_verification.append(thread.is_alive())
            return result

        with (
            patch.object(first_owner, "_connect", side_effect=tracked_connect) as connect_spy,
            patch.object(first_owner, "obligation_detail", side_effect=tracked_detail) as detail_spy,
            patch.object(independent, "verify_database_connection", side_effect=write_during_verification) as verify_spy,
        ):
            snapshot = workflow.workspace()
        self.assertEqual(len(writer_threads), 1)
        writer_threads[0].join(timeout=15)
        self.assertFalse(writer_threads[0].is_alive())
        self.assertEqual(writer_errors, [])
        # The write was in flight for the whole verification and committed only
        # after the verified snapshot closed.
        self.assertEqual(writer_pending_during_verification, [True, True])

        self.assertEqual(connect_spy.call_count, 1)
        self.assertEqual(detail_spy.call_count, 1)
        self.assertEqual(verify_spy.call_count, 1)
        self.assertEqual(len(connections), 1)
        self.assertEqual(transaction_states, [(True, "before"), (True, "after")])
        self.assertIs(verify_spy.call_args.args[0], connections[0])
        self.assertEqual(snapshot["integrity"]["sequence"], snapshot["summary"]["sequence"])
        self.assertEqual(snapshot["read_envelope"]["verification"]["sequence"], snapshot["summary"]["sequence"])
        self.assertEqual(snapshot["read_envelope"]["verification"]["history_head"], snapshot["integrity"]["history_head"])
        snapshot_item = next(item for item in snapshot["items"] if item["item_id"] == "item-01")
        self.assertEqual(snapshot_item["revision"], before["revision"])
        self.assertEqual(snapshot_item["support_evidence_count"], 1)

        newer = workflow.workspace()
        newer_item = next(item for item in newer["items"] if item["item_id"] == "item-01")
        self.assertEqual(newer_item["revision"], before["revision"] + 1)
        self.assertEqual(newer_item["support_evidence_count"], 2)
        self.assertGreater(newer["summary"]["sequence"], snapshot["summary"]["sequence"])
        self.assertNotEqual(newer["read_envelope"]["history_head"], snapshot["read_envelope"]["history_head"])

    def test_decision_route_reads_only_the_bounded_verified_package(self) -> None:
        workflow = self._workflow()
        with (
            patch.object(workflow.mirror, "list_obligations", side_effect=AssertionError("workspace list read")),
            patch.object(workflow.mirror, "obligation_detail", side_effect=AssertionError("workspace detail read")),
            patch.object(workflow.mirror, "summary", side_effect=AssertionError("workspace summary read")),
        ):
            view = workflow.decision_view()
        self.assertEqual(view["read_envelope"]["query"]["resource"], "decision_package")
        self.assertEqual(view["read_envelope"]["query"]["limit"], 100)
        self.assertIn("decision_package", view)
        self.assertIn("timeline", view)
        self.assertNotIn("items", view)
        self.assertNotIn("summary", view)
        self.assertNotIn("population", view)
        self.assertNotIn("detail", view)

    def test_mirror_fails_closed_on_unallowlisted_snapshot_resource(self) -> None:
        workflow = self._workflow()
        owner = workflow.mirror.owner
        original_snapshot = owner.read_verified_staff_snapshot

        def tampered_snapshot(query):
            raw = original_snapshot(query)
            raw["resources"]["items_page"]["items"][0]["unreviewed_secret"] = "must not escape"
            return raw

        with patch.object(owner, "read_verified_staff_snapshot", side_effect=tampered_snapshot):
            with self.assertRaises(FinancialMirrorContinuityError):
                workflow.workspace()

    def test_unrelated_owner_write_does_not_conflict_with_reviewed_ack_and_retry_order_is_preserved(self) -> None:
        # The correction runs only through the pinned Lean release (Art. V.2).
        workflow = self._workflow(with_correction_release=True)
        workflow.reject_offset_and_authorize_correction(self._review_body(workflow))
        reviewed = self._revision_body(workflow)
        owner = workflow.mirror.owner
        writer = self._second_owner(owner)
        self.assertEqual((writer.mode, writer.owner_id), ("TEST", "continuity-test-owner-v1"))
        unrelated = owner.obligation_detail("item-01")
        sequence_before = owner.summary()["sequence"]
        writer.record_support_evidence(
            item_id="item-01",
            evidence_id="evidence:unrelated-before-h-ack",
            common_origin_id="origin:unrelated-before-h-ack",
            expected_revision=int(unrelated["revision"]),
        )
        self.assertGreater(owner.summary()["sequence"], sequence_before)

        acknowledged = workflow.acknowledge_correction_action(reviewed)
        self.assertEqual(acknowledged["command"]["status"], "ACKNOWLEDGED")
        duplicate = workflow.acknowledge_correction_action(reviewed)
        self.assertEqual(duplicate["command"]["status"], "DUPLICATE")
        with self.assertRaises(FinancialConflictError) as conflict:
            workflow.mirror.acknowledge_action(
                "action:obligation-item-h:correction-v1",
                "ack:conflicting-reference",
                expected_revision=int(reviewed["revision"]),
            )
        self.assertEqual(str(conflict.exception), "acknowledgment_conflict")

    def test_loopback_routes_require_exact_host_and_same_origin_for_commands(self) -> None:
        port = 8765
        origin = f"http://127.0.0.1:{port}"
        self.assertTrue(_request_allowed("127.0.0.1", f"127.0.0.1:{port}", origin, port, mutation=True))
        self.assertFalse(_request_allowed("192.0.2.4", f"127.0.0.1:{port}", origin, port, mutation=True))
        self.assertFalse(_request_allowed("127.0.0.1", f"localhost:{port}", origin, port, mutation=True))
        self.assertFalse(_request_allowed("127.0.0.1", f"127.0.0.1:{port}", "https://other.example", port, mutation=True))
        self.assertFalse(_request_allowed("127.0.0.1", f"127.0.0.1:{port}", None, port, mutation=True))

    def test_http_surface_serves_snapshot_and_rejects_cross_origin_mutation(self) -> None:
        workflow = self._workflow()
        server = self._serve_workflow(workflow)
        port = int(server.server_address[1])
        host = ("Host", f"127.0.0.1:{port}")
        post = (host, ("Origin", f"http://127.0.0.1:{port}"), ("Content-Type", "application/json"))

        def call(method: str, path: str, headers: tuple[tuple[str, str], ...], body: bytes = b"", length: str = "") -> tuple[int, dict[str, str], object]:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            self.addCleanup(connection.close)
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for name, value in (*headers, ("Content-Length", length or str(len(body)))):
                connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read().decode("utf-8"))

        status, headers, body = call("GET", "/api/workspace", (host,))
        self.assertEqual((status, body["summary"]["obligation_count"]), (200, 20))
        self.assertEqual((headers["Server"], headers["Cross-Origin-Resource-Policy"]), ("RightRail", "same-origin"))
        self.assertEqual(call("POST", "/api/action/acknowledge", (host, ("Origin", "https://other.example"), post[2]), b'{"revision":0}')[:3:2],
                         (403, {"error": {"code": "loopback_origin_required"}}))
        # Only the model's declared commands are served; the demo gate routes are not.
        model = json.loads((Path(__file__).resolve().parents[1] / "app" / "staff_workspace" / "interaction-model.json").read_text(encoding="utf-8"))
        self.assertEqual(set(_COMMAND_ROUTES), {c["route"][5:] for c in model["controls"].values() if c["route"].startswith("POST ")})
        self.assertEqual(call("POST", "/api/attempt/wrong-role", post, json.dumps(self._review_body(workflow)).encode())[0], 404)
        # Exact targets and one exact Host; odd framing, duplicate keys and deep nesting get a clean 400.
        self.assertEqual(call("GET", f"http://127.0.0.1:{port}/api/workspace", (host,))[0], 404)
        self.assertEqual(call("GET", "/api/workspace", (host, ("Host", "rebound.example")))[0], 403)
        for body_bytes, length in ((b'{"revision":0,"revision":0}', ""), (b"[" * 5000, ""), (b'{"revision":0}', "1_4")):
            self.assertEqual(call("POST", "/api/action/acknowledge", post, body_bytes, length)[:3:2], (400, {"error": {"code": "invalid_request"}}))
        # Framework refusals and unexpected read failures are JSON with the same headers, and no detail.
        status, headers, body = call("PUT", "/api/workspace", post, b'{"revision":0}')
        self.assertEqual((status, body), (501, {"error": {"code": "invalid_request"}}))
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        with patch.object(workflow, "workspace", side_effect=RuntimeError("internal detail")):
            self.assertEqual(call("GET", "/api/workspace", (host,))[:3:2], (503, {"error": {"code": "owner_read_unavailable"}}))
        with patch.object(workflow, "acknowledge_correction_action", side_effect=FinancialBusyError("store_busy")):  # a transient lock is not a 409
            status, headers, body = call("POST", "/api/action/acknowledge", post, b'{"revision":0}')
        self.assertEqual((status, headers.get("Retry-After"), body), (503, "1", {"error": {"code": "store_busy"}, "changed": False}))

    def test_http_refuses_ambiguous_short_and_slow_bodies_before_dispatch(self) -> None:
        workflow = self._workflow()
        server = self._serve_workflow(workflow)
        port = int(server.server_address[1])
        before = workflow.mirror.owner.export_continuity()
        cases = (
            ("Content-Length: 2\r\nContent-Length: 2", b"{}", True),
            ("Content-Length: 1\r\nContent-Length: 2", b"{}", True),
            ("Content-Length: 2\r\nTransfer-Encoding: chunked", b"{}", True),
            ("Transfer-Encoding: identity", b"{}", True),
            ("Content-Length: 2\r\nContent-Type: text/plain", b"{}", True),
            ("Content-Length: 3", b"{}", True),  # valid JSON, truncated frame
            ("Content-Length: 3", b"{}", False),  # peer never finishes or half-closes
            ("Content-Length: 8193", b"x" * 8193, True),
        )
        with patch.object(workflow, "command", return_value={}) as command, patch("app.right_rail_financial_staff_server.HTTP_BODY_TIMEOUT_SECONDS", 0.15):
            for framing, body, eof in cases:
                with self.subTest(framing=framing, eof=eof), socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
                    request = f"POST /api/action/acknowledge HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\n{framing}\r\n\r\n".encode() + body
                    peer.sendall(request)
                    if eof:
                        peer.shutdown(socket.SHUT_WR)
                    response = http.client.HTTPResponse(peer)
                    response.begin()
                    self.assertEqual((response.status, response.getheader("Connection"), json.loads(response.read())),
                                     (400, "close", {"error": {"code": "invalid_request"}}))
            command.assert_not_called()
        self.assertEqual(workflow.mirror.owner.export_continuity(), before)

    def test_http_head_refusal_has_no_body_and_closes(self) -> None:
        workflow = self._workflow()
        port = int(self._serve_workflow(workflow).server_address[1])
        with socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
            peer.sendall(f"HEAD /api/workspace HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
            peer.shutdown(socket.SHUT_WR)
            with peer.makefile("rb") as received:
                headers, body = received.read(8192).split(b"\r\n\r\n", 1)
        self.assertTrue(headers.startswith(b"HTTP/1.1 501"))
        self.assertIn(b"Connection: close", headers)
        self.assertEqual(body, b"")

    def test_a_lock_taken_right_after_a_commit_never_answers_changed_false(self) -> None:
        for released in (False, True):  # held through the answer: cannot tell; released after the failed read-back: it committed
            (workspace := Path(self.temp_dir.name) / f"released-{released}").mkdir()
            workflow = self._workflow(workspace_dir=workspace)
            server = self._serve_workflow(workflow)
            owner, port, body = workflow.mirror.owner, int(server.server_address[1]), json.dumps(self._revision_body(workflow))
            holder = sqlite3.connect(owner.path, isolation_level=None, check_same_thread=False)  # used from the server thread
            self.addCleanup(holder.close)
            real_record, real_snapshot, before = workflow.mirror.record_reporting_evidence, owner._read_snapshot, owner.summary()["sequence"]

            def commit_then_lock(**arguments: object) -> object:
                result = real_record(**arguments)  # the owner has committed
                holder.execute("BEGIN EXCLUSIVE")
                return result

            @contextmanager
            def snapshot(**arguments: object):  # type: ignore[no-untyped-def]
                try:
                    with real_snapshot(**arguments) as connection:
                        yield connection
                except FinancialBusyError:
                    if released and holder.in_transaction:
                        holder.execute("ROLLBACK")
                    raise

            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
            self.addCleanup(connection.close)
            with patch.object(workflow.mirror, "record_reporting_evidence", commit_then_lock), patch.object(owner, "_read_snapshot", snapshot):
                connection.request("POST", "/api/reporting/record", body, {"Origin": f"http://127.0.0.1:{port}", "Content-Type": "application/json"})
                response = connection.getresponse()
                answer = (response.status, response.getheader("Retry-After"), json.loads(response.read().decode("utf-8")))
            if holder.in_transaction:
                holder.execute("ROLLBACK")
            code = "store_busy" if released else "store_busy_outcome_unknown"
            self.assertEqual(answer, (503, None, {"error": {"code": code}, "changed": True if released else None}))
            self.assertGreater(owner.summary()["sequence"], before)  # it did commit

    def test_another_process_committing_during_a_busy_command_is_not_claimed_as_its_change(self) -> None:
        workflow = self._workflow()
        owner, body = workflow.mirror.owner, self._revision_body(workflow)
        other = self._second_owner(owner)  # a second server process on the same store
        holder = sqlite3.connect(owner.path, isolation_level=None, check_same_thread=False)
        self.addCleanup(holder.close)
        real_record, before = workflow.mirror.record_reporting_evidence, owner.summary()["sequence"]

        def other_commits_then_holds(**arguments: object) -> object:
            other.record_support_evidence(item_id="item-01", evidence_id="evidence:other-process:1", common_origin_id="origin:other-process")
            holder.execute("BEGIN IMMEDIATE")  # the other process's next write outlasts this command's busy timeout
            release = threading.Timer(7.0, lambda: holder.execute("ROLLBACK"))
            release.start()
            self.addCleanup(release.join)
            return real_record(**arguments)
        with patch.object(workflow.mirror, "record_reporting_evidence", other_commits_then_holds), self.assertRaises(FinancialBusyError) as busy:
            workflow.command("record_reporting_evidence", body)
        self.assertIsNone(busy.exception.changed)  # the store moved, but not by this command
        self.assertGreater(owner.summary()["sequence"], before)
        with closing(sqlite3.connect(owner.path)) as check:
            self.assertEqual(check.execute("SELECT COUNT(*) FROM evidence WHERE evidence_id='evidence:report:h:original'").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
