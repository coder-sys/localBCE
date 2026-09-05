from __future__ import annotations

import hashlib
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import app.minimal_clearance_composition as composition
import app.minimal_clearance_source_auth_verifier_adapter as source_auth_adapter
from app.minimal_clearance_composition import (
    ClearanceCompositionStoreV2,
    CompositionConfigV2,
    StateDispositionControl,
    build_synthetic_acknowledgment,
)
from app.minimal_clearance_source_auth_verifier_adapter import (
    MinimalClearanceSourceAuthVerifierAdapter,
    SOURCE_AUTH_EXECUTABLE_SHA256,
    SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
)
from app.minimal_clearance_verification_queue import (
    ACTIVE_PROCESS_LIMIT,
    ADMISSION_CAP_BYTES,
    IssuedVerificationBatch,
    OperationTemplate,
    QueueConfig,
    VolatileProofHandoff,
    _build_statement,
    _compute_batch_root_from_refs,
)
from app.minimal_clearance_verifier_process import ContainedVerifierResult, VerifierProcessError, run_contained_verifier_stream
from profile11_source_boundary import (
    Profile11SourceBoundaryCaller,
    SourceApplianceConfig,
    SourceBoundaryError,
    SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
    SOURCE_APPLIANCE_PROTOCOL_VERSION,
    SOURCE_APPLIANCE_REQUEST_MAGIC,
    SOURCE_AUTH_FRAME_BYTES,
    SOURCE_AUTH_INPUT_BYTES,
    SOURCE_AUTH_OPERATION_COUNT,
    SOURCE_AUTH_ORDERED_REFS_BYTES,
    SOURCE_AUTH_REQUEST_BYTES,
    SOURCE_AUTH_REQUEST_EPOCH_OFFSET,
    SOURCE_AUTH_REQUEST_REFS_OFFSET,
    SOURCE_AUTH_REQUEST_ROOT_OFFSET,
    SOURCE_AUTH_REQUEST_STATEMENT_OFFSET,
    SOURCE_AUTH_REQUEST_VERSION_OFFSET,
    SOURCE_AUTH_REQUEST_RESERVED_OFFSET,
    SOURCE_AUTH_STDERR_CAP_BYTES,
    SOURCE_AUTH_STDOUT_CAP_BYTES,
    build_request_record,
)


E2E_ROOT = Path(r"C:\Users\neers\Documents\Codex\2026-08-31\blind-profile11-e2e-v1")
SOURCE_REPO = Path(r"C:\Users\neers\Documents\Codex\2026-09-01\blind-profile11-source-transaction-v1")
SOURCE_C_REPO = Path(r"C:\Users\neers\Documents\Codex\2026-08-31\blind-zkbpp-c-profile11-extmu-v1")
QUEUE_REPO = Path(r"C:\Users\neers\Documents\Codex\2026-08-31\blind-queue-profile11-outbox-batch-v1")
SOURCE_HOST = E2E_ROOT / "experiments" / "profile11_source_host" / "target" / "release" / "profile11_source_host.exe"
SOURCE_HOST_SIZE = 480_768
SOURCE_HOST_SHA256 = "3D2C0A468303E68AA63B2A6A52BA922422231695D589ED1562E4F1CA3A8F5562"
SOURCE_AUTH_C_BUILD = Path(r"C:\Users\neers\Documents\Codex\2026-09-01\blind-zkbpp-c-profile11-extmu-v1-prod-msvc\Release")
SOURCE_AUTH_C_VERIFIER = Path(r"C:\Users\neers\Documents\Codex\2026-08-31\build-profile11-throughput-v1\Release\blind_source_auth_verify_process_v1.exe")
SOURCE_AUTH_C_LIBRARIES = (
    (SOURCE_AUTH_C_BUILD / "blind_source_auth_v1.lib", 152_624, "D4F5FD22F80CB1ECA9BAEF944E18F5427AB6F8192BB210278D69EBBB05B28841"),
    (SOURCE_AUTH_C_BUILD / "blind_range100_cdg_direct_v1.lib", 109_342, "1B190B727D612CCC53C37E211BDC04C7BB1EA971D9E694FDD9B97C67549A7C30"),
)
SOURCE_AUTH_C_HEAD = "9ca1ba2ccb6fa78384e3c3e21cfd3dfd0cb38eb2"
SOURCE_AUTH_C_TREE = "178a5f20c6738f7272cd38f77315da83650bbac0"
SOURCE_AUTH_C_VERIFIER_SIZE = 52_736
SOURCE_AUTH_C_VERIFIER_SHA256 = "4834D0A6A7E198A98EA0018F1009F6C180C510680EE61F2757E8342EF8B4032C"
SOURCE_RUST_HEAD = "0538862de4b7580bf0a5613ee8f86d71de032cf8"
SOURCE_RUST_TREE = "fa18bfd8aec72643ad1d494c63fdbe1ede5245de"
QUEUE_HEAD = "412b53e68091561657106345a22a772699761945"
QUEUE_TREE = "72746eb68e667698fdb0a72c8aea7c9bf027076a"
SOURCE_TEST_PUBLIC_KEY = bytes.fromhex(
    "89AB36C9633840787796E3493C8A212B929B1B41EFB929D76CAC848DC7E252402FA2B48A933E2E47C8E482C7AF7A279F23E1D3496216148488594EDB684E1166C30B985DB10AB4074FEEA621B571A0FCFDE6AB41700B0147AB593F7A34F128C2EAF811D5A4397C23C490F8A37C78CF59BB09CA4F5F88EA60E8FC284D08F4671950A32781D524F6AC2A943295F4ECC0A96A9FB5F2285F3C70EE0D8E80B9C2B19F8BCDDB8154568B81E258BA083989B483DBEE26E6D76A403E860018CCF7E48B9EE06DDD5FD1A1F1BD97CDD5B5A58492D5382548D1097CA37DD922BA4E292959B32B1D62E4A4B9F7594C3592935C37D28FD956D363F9A161667FCBB9FC3E920C50BA56D6443580A9B886A7DB5997B0128EEE62CED669C2876C2A3B365F688D39F15C40AB1DB454B1A64FF08E4255143E764AB6C15CD1B5D27D652BEDFDB3B2B801398E4525BE63412E9CE850FDD07111CBB9E46BCAF2D1941C79CF395699700B5B1B53DBA6CEC7B3830E3065EFC13EB5B32BEB9FE089EE6C1149F260BFE64416E89AD817A438AD3B20F28B9C2218B796082B30F0F9EE36831D962B1AB6910689A1C618B9B31D42C4D2C8BB01E08A3B366442DD90CEE4CE3297559F72AD0C95C7390C3994D047821FB997430F642FA87460F71B1893F02E565B28E5B371621B2A52F723A709DD56C8D71601588D493315E7EAEBD54CA009310EA8CE7217AA2E18BC26EE005B3264597C6283291D2CFC34A2EEF4EF9691656A8B52ED15B7DE5AAB2DFE634CEB4C50F75FCFCE1C0834D13901E5A2451EC2B78E9F0183D9FB87059DA0B420EB27C5824D98BF7E21DFD28B20D4717BE5A82EE47184F1EAF40DAF0A99200B6BAC28062E0B133937D2DF5791351649377252D1A9BB89BBEEFF46BA2A474334EBDDF343746E1C61E9A5530DEB3E957140935662801DA2FE9D96B6C88F6D70CC5ECBED612A0F51995D1388CA8B8E421625B726CA261658A2F3F4CAECB4D33A598448743A124368B7062E90BDB8252AB769CCEF3A3429ED1F32517570A6392C6E8A749881C23ECBB6B74DE443ED076B0C6AC7D18569C5CF13A77922F1FDFFEF7CE8CFA4EAE8652398B571C49F7C952B04A908F4B5CCC4E66A80264004AD1FB4FB3CE1EC7821A96B6B7F945C2D5435D68F7DD019B53B26B9D205242C9E377B1B48AA734B153205830966C15B1757918992902BBD9FFC700B8206B4323185586D1D42B2A31329758820864AB2729034D52BE27B8674F244BCE1AA4C335AA0AB8770BD7EBCE2E5D2A5FDCA03D2F16CA8B9292211DBE44CFDDCD74ADBE956A226AE209ECF1527A173EB4EB7BED5288837A4ED207122A5E7C26B020B22114240A1A4F8C3EB4E3D50EA30CB7380DC96B226D1D56B00D9FAA3D19BA8E6FAB63261F458CA189C86C3780241D769D61D4212C21353D06ED4860E6B01D93F078D8C1464285BB1119D683ECD9806F92413A2BC685354B3C742FC30004C8F285C977FA7323D406CDE82FC2A6B3DD9D99E07DA718440642DC56C2FC418335BC0B5790563987F2424E4A4812009C0FC4E0A395A89088B1A6697B4B6E39DB7766701A4896A4804C9C3532C6DC9101E4FE696A494A6246A855EABCF4B0AED504DD3A12905F47F355A96EDB7791EAFFBABB557FDF60554DDC39C37ED9ACA14A44B9563786E0306E1AF758310B56DB849CEE7BBD0A1BF5033F08323E46E2E08D2FDC85F7A4F1C6C2B6F478B325172792D5C9CE20B999C3E9D47C3FCD9A66DADFCFA7B67DEDADEDF3F6E3D9377DBD872B8ADEA7B766C36786192E46A0DE31D03474F7F1C8E05681103A50430838FBA02B7EFC3FD7EBEC1600C94805099D95900358DAAAB359E353DDE44DB7A5C6555982E89C54F2A42F232CAF3BC57D1B73C6A0CD9B1489A9D33B7A1D3575635B106D6BB699EF8C879051BC7FCB84932A60B5DBAA9FD7D3AAA2F4D7BFA69BEE32DE6F722D61B5BC72E850EBBA1AD5EF1729B0CD5288A714D1A02D1937BEB0407CDD818D7A83DC3DEB729B81889161BDB39952273C856D3EAFCD988FF7A23E8CEB62A5AD9E262841ABB13A61536D7C1D5D589A21926106D35E5F3D187D62C04074029C937B764F0BFFB213237E897CC71077A684566F60E4E9DE85B9B465E5796023DAD608CE20DAF4A2485F1D7488FA97280FBF727640258898320D2DE387004FA54B489957FF672B119CBEA8C27915AE1B155568FD6661C67EEF05F2F51963619338C6A3039BBD4AC85A810268831A2C0840A966292F6ADD7B5CF5302B7E952DD03FB9B2343D7E5E388C3C5724A2AADDD57F55B8BE73A03F80822CDE793190A561D608D7D970F7EFA34F3DC47602AAF6BE51B74ACD0CAB3C6038B7DFA6784C191B39FEB0748CD93DC1A988C91E2FCE8DDC865ACCE4195B818FD6F862188C20D447FDB9CF3EB3F1366BA6DE76BD91D5868D7713792CEAE3159EE8C1C71D6CAC87935ED2D909405EEE5A1A6BB5C68C537A618C6689ED4E91D15217891264BA50E21C6899785282F53BF06D1C66232997FFCBD9346BD454D8BF445ED948A2B6D1BEE7AD49834545D1C2859CBEA2CB786400BFCA4BBA9D5DF14A9E00C6880B76C4D774160A8E20466A8A37FCBE58A6BA4FC04910C7215227846FC552037B8852AAA9054744C2D7F9FD046E35470D645580A60FF4E347EDE64B714C9AD8200C76470C28568BB38F3206E5A0EAE374A12778E0ABA5A2589A85C1B531D46A7B7EE36468D44F171EC8166698CC6D0C6B98B204095A91A9220F7A9433008AF53985B7F4CACE79F2835EB220E560DE4E1147EAB0F4D18D8983E6E0AFB792540BA2747210583328D177DACAC6CF7C4A0462F506A2A6D05CAD79166E74D212DD7F9FC73293DE569F2B94F194E712584FC20FBB6ED7A0FF7FE367CA7D4A41EDB48DD4A10B6450B2EE7EC2FCB435A0514F32A26991ED2FD135472CBF5214BCCCA060217BC06E144D2164620E14CB9FC86F12F947CF8E9C545EC3E64DC6A0BE592243D8F0199FE48F8D9AD9F4E54FECA84346EB5EEA760CF172C22B6B624BC2BAD466354BE5EBF9E49024386F92068EFA5C00341BB5289D0185375059D276BEC3025C900E68CF7A022E09AC49779D7ED57B1D3CB1CEA137E9EE1528D81688762F9E3CCF29E82B650BEB9C08ECA075E3CEF2B59D6C0241906FE56E611420901D85E0D28C42F27419C0F354B8584313AE93E7E5E9F410263197058D44103373BD8BEA104A7CDC5D2C315E23BC34366D7AEB2963379360687DC375B93FC7AF9C7868656625E7E2B71CDD38B5A381B09C7A9F70EC8CAE5509346B218BF4847E8BFE8ED2E366DBE6E0907D7B6543C9DBED156DCB1B432477E766B72393FDB7039D5242BE8FB6549C04E810A4D8D977306DCEE47C1469033255508B60473A25E8D80858E22826422837DB5984BDE77DF83C8AC17B09EBFC4A14C5B733C317CECCE0A9AAEEF7375E19ACBD597901F4CCB3F636A9B1399F8607FEE0A5492E9E020916BEFCA46E071AEC2830D3C97E924CE5E870B67509CE89E504EE556D7C4EB22D618956C993D53EBEBB60FBD8A99B3C545136D8405B90F88EDE1432CAEF1297C35B2A2816094D888CA86F88A05210FCB870BF93DDB5F3EAA31E852DF742517C90FD3971C1F9D34D017F6971A3F4BC2964BDC0519B90377B55EE4A34F10BD1463C60053A94C86"
)


def _assert_pinned_file(test: unittest.TestCase, path: Path, expected_bytes: int, expected_sha256: str) -> None:
    test.assertTrue(path.is_file(), path)
    test.assertEqual(path.stat().st_size, expected_bytes, path)
    test.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest().upper(), expected_sha256, path)


def _assert_git_pin(test: unittest.TestCase, path: Path, head: str, tree: str) -> None:
    test.assertEqual(subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip(), head)
    test.assertEqual(subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD^{tree}"], capture_output=True, text=True, check=True).stdout.strip(), tree)
    test.assertEqual(subprocess.run(["git", "-C", str(path), "status", "--short"], capture_output=True, text=True, check=True).stdout, "")


def _contained(*, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0, timed_out: bool = False, peak_job_commit_bytes: int = 1024, child_process_count: int = 1, process_tree_complete: bool = True, measurement_complete: bool = True, cleanup_complete: bool = True, cap_enforced: bool = True) -> ContainedVerifierResult:
    return ContainedVerifierResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        peak_job_commit_bytes=peak_job_commit_bytes,
        cap_bytes=ADMISSION_CAP_BYTES,
        cap_enforced=cap_enforced,
        active_process_limit=ACTIVE_PROCESS_LIMIT,
        timed_out=timed_out,
        child_process_count=child_process_count,
        process_tree_complete=process_tree_complete,
        measurement_complete=measurement_complete,
        cleanup_complete=cleanup_complete,
        pagefile_growth_evidence="unavailable",
    )


class _StateDispositionPort:
    def __init__(self) -> None:
        self.calls = 0

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome: object) -> dict[bytes, StateDispositionControl]:
        del batch_id, verification_outcome
        self.calls += 1
        profile = bytes([0x11]) * 64
        state_id = state_bytes = continuity = audit = clearance = bytes(64)
        controls: dict[bytes, StateDispositionControl] = {}
        for index, operation_ref in enumerate(operation_refs):
            control = StateDispositionControl(
                operation_ref=operation_ref,
                policy_result="MISSING",
                state_profile_identity=profile,
                predecessor_state_id=state_id,
                predecessor_state_bytes=state_bytes,
                sequence_before=index,
                predecessor_continuity_root=continuity,
                predecessor_audit_head=audit,
                predecessor_clearance_root=clearance,
            )
            controls[operation_ref] = control
            state_id, state_bytes = control.state_after_id, control.state_after_bytes
            continuity = control.state_after_continuity_root
            audit = composition._sha(composition._STATE, audit, control.decision_id, control.effective_directive.encode("ascii"))
        return controls


class _SyntheticReceiver:
    def __init__(self, config: object) -> None:
        self.config = config
        self.calls: list[tuple[bytes, bytes]] = []
        self.lookup_calls: list[dict[str, object]] = []
        self.cache: dict[bytes, bytes] = {}

    def identity_sha256(self) -> bytes:
        return self.config.receiver_identity  # type: ignore[attr-defined]

    def epoch(self) -> int:
        return self.config.receiver_epoch  # type: ignore[attr-defined]

    def acknowledgment_profile(self) -> object:
        return self.config.acknowledgment_profile  # type: ignore[attr-defined]

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.calls.append((bytes(envelope_bytes), bytes(idempotency_key)))
        if idempotency_key not in self.cache:
            self.cache[idempotency_key] = build_synthetic_acknowledgment(
                envelope_bytes,
                config=self.config,  # type: ignore[arg-type]
                idempotency_key=idempotency_key,
                accepted_ms=1_700_000_000_000 + len(self.calls),
            )
        return self.cache[idempotency_key]

    def lookup_acknowledgment(self, **query: object) -> bytes | None:
        self.lookup_calls.append(dict(query))
        if query.get("receiver_identity") != self.config.receiver_identity or query.get("receiver_epoch") != self.config.receiver_epoch:  # type: ignore[attr-defined]
            return None
        idempotency_key = query.get("idempotency_key")
        if type(idempotency_key) is not bytes:
            return None
        return self.cache.get(idempotency_key)


class Profile11SourceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="blind-profile11-e2e-")
        cls.root = Path(cls.temp.name)
        cls.source_workspace = cls.root / "source-workspace"
        cls.verifier_workspace = cls.root / "verifier-workspace"
        cls.state_root = cls.root / "state"
        cls.source_workspace.mkdir()
        cls.verifier_workspace.mkdir()
        cls.state_root.mkdir()
        checker = unittest.TestCase()
        _assert_pinned_file(checker, SOURCE_HOST, SOURCE_HOST_SIZE, SOURCE_HOST_SHA256)
        _assert_pinned_file(checker, SOURCE_AUTH_C_VERIFIER, SOURCE_AUTH_C_VERIFIER_SIZE, SOURCE_AUTH_C_VERIFIER_SHA256)
        for path, size, digest in SOURCE_AUTH_C_LIBRARIES:
            _assert_pinned_file(checker, path, size, digest)
        _assert_git_pin(checker, SOURCE_REPO, SOURCE_RUST_HEAD, SOURCE_RUST_TREE)
        _assert_git_pin(checker, SOURCE_C_REPO, SOURCE_AUTH_C_HEAD, SOURCE_AUTH_C_TREE)
        _assert_git_pin(checker, QUEUE_REPO, QUEUE_HEAD, QUEUE_TREE)
        cls.queue_config = QueueConfig("queue-profile11-source-e2e", SOURCE_AUTH_OPERATION_COUNT, source_key_epoch=0x0102_0304_0506_0708)
        cls.caller = Profile11SourceBoundaryCaller(SourceApplianceConfig(SOURCE_HOST, cls.source_workspace, SOURCE_HOST_SIZE, bytes.fromhex(SOURCE_HOST_SHA256), 180.0))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def _template(self) -> OperationTemplate:
        valid_from_ms = time.time_ns() // 1_000_000 - 60_000
        return OperationTemplate("assertion", 1, "state-profile-v11", valid_from_ms, valid_from_ms + 3_000_000, None, self.queue_config.qualification_flags)

    def _batch(self) -> IssuedVerificationBatch:
        template = self._template()
        refs = tuple(bytes([index + 1]) + bytes(31) for index in range(SOURCE_AUTH_OPERATION_COUNT))
        root = _compute_batch_root_from_refs(template, refs)
        statement = _build_statement(batch_root=root, session_ref=bytes(range(64)), valid_from_ms=template.valid_from_ms, valid_until_ms=template.valid_until_ms)
        return IssuedVerificationBatch(b"b" * 32, template, refs, root, bytes(range(64)), statement, 1, b"i" * 64)

    def test_public_v2_request_is_exact_and_contains_no_private_source_fields(self) -> None:
        batch = self._batch()
        request = build_request_record(batch=batch, source_key_epoch=self.queue_config.source_key_epoch)
        try:
            self.assertEqual(len(request), SOURCE_AUTH_REQUEST_BYTES)
            self.assertEqual(request[:16], SOURCE_APPLIANCE_REQUEST_MAGIC)
            self.assertEqual(int.from_bytes(request[SOURCE_AUTH_REQUEST_VERSION_OFFSET:SOURCE_AUTH_REQUEST_VERSION_OFFSET + 2], "little"), SOURCE_APPLIANCE_PROTOCOL_VERSION)
            self.assertEqual(request[SOURCE_AUTH_REQUEST_RESERVED_OFFSET:SOURCE_AUTH_REQUEST_RESERVED_OFFSET + 2], b"\0\0")
            self.assertEqual(int.from_bytes(request[SOURCE_AUTH_REQUEST_EPOCH_OFFSET:SOURCE_AUTH_REQUEST_EPOCH_OFFSET + 8], "little"), self.queue_config.source_key_epoch)
            self.assertEqual(request[SOURCE_AUTH_REQUEST_ROOT_OFFSET:SOURCE_AUTH_REQUEST_ROOT_OFFSET + 64], batch.batch_root)
            self.assertEqual(request[SOURCE_AUTH_REQUEST_REFS_OFFSET:SOURCE_AUTH_REQUEST_REFS_OFFSET + SOURCE_AUTH_ORDERED_REFS_BYTES], b"".join(batch.operation_refs))
            self.assertEqual(request[SOURCE_AUTH_REQUEST_STATEMENT_OFFSET:], batch.proof_statement)
            self.assertNotIn(b"BL-SRC-REQ-V1", request)
            self.assertFalse(hasattr(__import__("profile11_source_boundary"), "build_provision_record"))
            self.assertFalse(hasattr(__import__("profile11_source_boundary"), "SOURCE_AUTH_SECRET_KEY_BYTES"))
        finally:
            for index in range(len(request)):
                request[index] = 0
            request.clear()

    def test_source_caller_forwards_one_public_request_and_wipes_it(self) -> None:
        batch = self._batch()
        expected_frame = b"f" * SOURCE_AUTH_FRAME_BYTES
        captured: dict[str, object] = {}

        def runner(executable: Path, arguments: tuple[str, ...], payload: bytearray, **kwargs: object) -> ContainedVerifierResult:
            captured.update(executable=executable, arguments=arguments, payload=bytes(payload), payload_type=type(payload), kwargs=kwargs)
            return _contained(stdout=expected_frame)

        with patch("profile11_source_boundary.run_contained_verifier_stream", side_effect=runner):
            frame = self.caller.prove_one(batch=batch, source_key_epoch=self.queue_config.source_key_epoch)
        self.assertEqual(frame, bytearray(expected_frame))
        self.assertEqual(captured["executable"], SOURCE_HOST)
        self.assertEqual(captured["arguments"], ())
        self.assertIs(captured["payload_type"], bytearray)
        self.assertEqual(len(captured["payload"]), SOURCE_AUTH_REQUEST_BYTES)
        self.assertEqual(captured["kwargs"]["expected_input_bytes"], SOURCE_AUTH_INPUT_BYTES)  # type: ignore[index]
        self.assertEqual(captured["kwargs"]["stdout_cap_bytes"], SOURCE_AUTH_STDOUT_CAP_BYTES)  # type: ignore[index]
        self.assertEqual(captured["kwargs"]["stderr_cap_bytes"], SOURCE_AUTH_STDERR_CAP_BYTES)  # type: ignore[index]

    def test_real_host_emits_exact_frame_only_stdout_and_empty_stderr(self) -> None:
        batch = self._batch()
        request = build_request_record(batch=batch, source_key_epoch=self.queue_config.source_key_epoch)
        try:
            result = run_contained_verifier_stream(
                SOURCE_HOST,
                (),
                request,
                workspace=self.source_workspace,
                timeout_seconds=180.0,
                expected_executable_size_bytes=SOURCE_HOST_SIZE,
                expected_executable_sha256=bytes.fromhex(SOURCE_HOST_SHA256),
                stdout_cap_bytes=SOURCE_AUTH_STDOUT_CAP_BYTES,
                stderr_cap_bytes=SOURCE_AUTH_STDERR_CAP_BYTES,
                stdout_ascii=False,
                expected_input_bytes=SOURCE_AUTH_INPUT_BYTES,
            )
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(len(result.stdout), SOURCE_AUTH_FRAME_BYTES)
            self.assertEqual(result.stderr, b"")
            self.assertTrue(result.process_tree_complete)
            self.assertTrue(result.measurement_complete)
            self.assertTrue(result.cleanup_complete)
            self.assertEqual(list(self.source_workspace.iterdir()), [])
        finally:
            for index in range(len(request)):
                request[index] = 0
            request.clear()

    def test_source_caller_fails_closed_on_timeout_shape_or_containment(self) -> None:
        batch = self._batch()
        complete = b"f" * SOURCE_AUTH_FRAME_BYTES
        cases = (
            (_contained(timed_out=True), "source_timeout"),
            (_contained(stdout=complete[:-1]), "source_frame_truncated"),
            (_contained(stdout=complete + b"x"), "source_frame_trailing"),
            (_contained(stderr=b"x"), "source_stderr"),
            (_contained(exit_code=1), "source_process"),
            (_contained(child_process_count=0), "source_process"),
            (_contained(process_tree_complete=False), "source_process"),
            (_contained(measurement_complete=False), "source_process"),
            (_contained(cleanup_complete=False), "source_process"),
            (_contained(cap_enforced=False), "source_process"),
        )
        for result, code in cases:
            with self.subTest(code=code):
                with patch("profile11_source_boundary.run_contained_verifier_stream", return_value=result):
                    with self.assertRaisesRegex(SourceBoundaryError, code):
                        self.caller.prove_one(batch=batch, source_key_epoch=self.queue_config.source_key_epoch)

    def test_source_caller_maps_runner_failures_without_leaking_text(self) -> None:
        batch = self._batch()
        for failure, code in ((VerifierProcessError("verifier_timeout"), "source_timeout"), (VerifierProcessError("verifier_workspace_changed"), "source_workspace"), (VerifierProcessError("verifier_stream_input_incomplete"), "source_process"), (RuntimeError("raw failure text"), "source_process")):
            with self.subTest(code=code):
                with patch("profile11_source_boundary.run_contained_verifier_stream", side_effect=failure):
                    with self.assertRaisesRegex(SourceBoundaryError, code) as raised:
                        self.caller.prove_one(batch=batch, source_key_epoch=self.queue_config.source_key_epoch)
                self.assertEqual(str(raised.exception), code)

    def test_real_host_rejects_truncation_trailing_and_two_requests(self) -> None:
        batch = self._batch()
        request = build_request_record(batch=batch, source_key_epoch=self.queue_config.source_key_epoch)
        try:
            for payload in (request[:-1], request + b"x", request + request):
                with self.subTest(length=len(payload)):
                    result = run_contained_verifier_stream(
                        SOURCE_HOST,
                        (),
                        bytearray(payload),
                        workspace=self.source_workspace,
                        timeout_seconds=180.0,
                        expected_executable_size_bytes=SOURCE_HOST_SIZE,
                        expected_executable_sha256=bytes.fromhex(SOURCE_HOST_SHA256),
                        stdout_cap_bytes=SOURCE_AUTH_STDOUT_CAP_BYTES,
                        stderr_cap_bytes=SOURCE_AUTH_STDERR_CAP_BYTES,
                        stdout_ascii=False,
                    )
                    self.assertEqual((result.exit_code, result.stdout, result.stderr), (1, b"", b""))
                    self.assertTrue(result.process_tree_complete)
                    self.assertTrue(result.measurement_complete)
                    self.assertTrue(result.cleanup_complete)
                    self.assertEqual(list(self.source_workspace.iterdir()), [])
        finally:
            for index in range(len(request)):
                request[index] = 0
            request.clear()

    def test_one_public_request_one_frame_one_c_verification_one_state_batch_and_100_acks(self) -> None:
        from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime

        verifier_config = source_auth_adapter.SourceAuthVerifierConfig(
            queue_config=self.queue_config,
            executable_path=SOURCE_AUTH_C_VERIFIER,
            executable_size_bytes=SOURCE_AUTH_C_VERIFIER_SIZE,
            executable_sha256=bytes.fromhex(SOURCE_AUTH_C_VERIFIER_SHA256),
            workspace=self.verifier_workspace,
            ml_dsa_87_public_key=SOURCE_TEST_PUBLIC_KEY,
            timeout_seconds=30.0,
        )
        state_port = _StateDispositionPort()
        composition_config = CompositionConfigV2(
            self.queue_config.queue_id,
            self.queue_config.digest,
            verifier_profile_identity=bytes([8]) * 32,
            receiver_identity=bytes([7]) * 32,
        )
        receiver = _SyntheticReceiver(composition_config)
        runtime = MinimalClearanceVerificationRuntime.from_source_auth(
            root=self.state_root,
            source_auth_config=verifier_config,
            state_disposition_port=state_port,
            composition_config=composition_config,
            receiver=receiver,
            lookup=receiver,
        )
        frame_snapshot = b""
        try:
            batch = runtime.issue_batch(template=self._template())
            frame = self.caller.prove_one(batch=batch, source_key_epoch=self.queue_config.source_key_epoch)
            frame_snapshot = bytes(frame)
            self.assertEqual(len(frame), SOURCE_AUTH_FRAME_BYTES)
            runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(frame))
            outcome = runtime.run(max_batches=1, dispatch_batches=1)
            self.assertEqual((outcome.outcome, outcome.accepted_operation_count, outcome.verified_batch_count, outcome.rejected_batch_count, outcome.held_batch_count), ("PROCESSED", 100, 1, 0, 0))
            self.assertIsNotNone(outcome.delivery)
            assert outcome.delivery is not None
            self.assertEqual((outcome.delivery.operation, outcome.delivery.batch_count, outcome.delivery.attempted_operation_count, outcome.delivery.acknowledged_operation_count, outcome.delivery.unconfirmed_operation_count), ("DIRECT_DELIVERY", 1, SOURCE_AUTH_OPERATION_COUNT, SOURCE_AUTH_OPERATION_COUNT, 0))
            self.assertEqual(len(receiver.calls), SOURCE_AUTH_OPERATION_COUNT)
            self.assertEqual((runtime.reconcile_outbox().outcome, len(receiver.lookup_calls)), ("EMPTY", 0))
            self.assertEqual(state_port.calls, 1)
            runtime._verify_integrity()
            database = runtime._database_path
        finally:
            runtime.close()

        connection = sqlite3.connect(database)
        try:
            outbox_statuses = connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall()
            self.assertEqual(outbox_statuses, [("ACKNOWLEDGED", SOURCE_AUTH_OPERATION_COUNT)])
            self.assertEqual(connection.execute("SELECT active_dispatch_count FROM composition_meta WHERE id=1").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_members").fetchone()[0], SOURCE_AUTH_OPERATION_COUNT)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], SOURCE_AUTH_OPERATION_COUNT)
            self.assertEqual(set(connection.execute("SELECT effective_directive FROM composition_transactions").fetchall()), {("HOLD",)})
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events WHERE event_kind='APPLIED'").fetchone()[0], SOURCE_AUTH_OPERATION_COUNT)
        finally:
            connection.close()
        composition_store = ClearanceCompositionStoreV2(path=database, config=composition_config)
        try:
            composition_store.verify_integrity()
        finally:
            composition_store.close()
        durable = database.read_bytes()
        self.assertNotIn(frame_snapshot, durable)
        self.assertNotIn(SOURCE_TEST_PUBLIC_KEY, durable)
        allowed = {"state.sqlite", "state.sqlite-journal", "state.sqlite-wal", "state.sqlite-shm", "state.sqlite.runtime-lock"}
        self.assertTrue({path.name for path in self.state_root.iterdir()} <= allowed)
        self.assertEqual(list(self.source_workspace.iterdir()), [])
        self.assertEqual(list(self.verifier_workspace.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
