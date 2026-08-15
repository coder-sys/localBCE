from __future__ import annotations

from io import BytesIO
from pathlib import Path

import experiments.bl_pq512_crypto_foundation.semantic_v3_strict_coin_client as client
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.selected_public_coin_v3 import (
    SemanticV3Geometry,
    SemanticV3GovernedContext,
)


class _Input:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False

    def write(self, value: bytes) -> int:
        self.data.extend(value)
        return len(value)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _Process:
    def __init__(self, command: list[str]) -> None:
        output = Path(command[-1])
        (output / client.SEMANTIC_KEY_FILE).write_bytes(b"key")
        (output / client.SEMANTIC_STRICT_BUNDLE_FILE).write_bytes(b"bundle")
        zero = Fp16.zero().encode().hex()
        one = Fp16.one().encode().hex()
        self.stdout = BytesIO(
            b"READY\n"
            + f"CHALLENGE 0 2 {zero} {one} {'09' * 128}\n".encode("ascii")
            + f"FINISHED {'0a' * 128} {'0b' * 128}\n".encode("ascii")
        )
        self.stdin = _Input()
        self.stderr = BytesIO()
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.returncode = -9


def _context() -> SemanticV3GovernedContext:
    return SemanticV3GovernedContext(
        profile_code=1,
        semantic_program_commitment=bytes((1,)) * 64,
        parameter_commitment=bytes((2,)) * 64,
        statement_commitment=bytes((3,)) * 64,
        composite_parent_schedule_commitment=bytes((4,)) * 64,
        contributor_set_commitment=bytes((5,)) * 64,
        geometry=SemanticV3Geometry(1, 4, 2),
    )


def test_strict_client_uses_exact_messages_and_publishes_native_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    service = (tmp_path / "strict-service.exe").resolve()
    service.write_bytes(b"fixture")
    output = (tmp_path / "output").resolve()
    output.mkdir()
    observed: dict[str, object] = {}

    def popen(command: list[str], **kwargs: object) -> _Process:
        observed["command"] = command
        observed["kwargs"] = kwargs
        process = _Process(command)
        observed["process"] = process
        return process

    monkeypatch.setattr(client.subprocess, "Popen", popen)
    strict = client.SemanticV3StrictCoinClient(
        service_executable=service,
        context=_context(),
        session_id=bytes((6,)) * 64,
        attempt=0,
        output_directory=output,
        timeout_seconds=1,
    )
    challenge = strict.absorb_message(b"parent-900")
    assert challenge.ordinal == 0
    assert challenge.field_elements == (Fp16.zero(), Fp16.one())
    assert challenge.transcript_root == bytes((9,)) * 128
    finished = strict.finish()
    assert finished.pre_final_transcript_root == bytes((10,)) * 128
    assert finished.final_transcript_root == bytes((11,)) * 128
    assert finished.context_path.read_bytes() == _context().encode()
    assert finished.key_path.read_bytes() == b"key"
    assert finished.bundle_path.read_bytes() == b"bundle"
    process = observed["process"]
    assert isinstance(process, _Process)
    assert bytes(process.stdin.data) == b"ROUND " + b"parent-900".hex().encode() + b"\nFINISH\n"
    assert observed["command"] == [
        str(service),
        str(output / client.SEMANTIC_CONTEXT_FILE),
        (bytes((6,)) * 64).hex(),
        "0",
        str(output),
    ]
