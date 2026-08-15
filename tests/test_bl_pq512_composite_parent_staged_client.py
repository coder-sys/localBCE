from __future__ import annotations

from hashlib import sha3_512
from io import BytesIO
from pathlib import Path

import experiments.bl_pq512_crypto_foundation.composite_parent_staged_client as client
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import CirclePoint
from experiments.bl_pq512_crypto_foundation.selected_public_coin_v3 import (
    SemanticV3ContinuationEvidence,
    SemanticV3PrefixEvidence,
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
    def __init__(self, output: Path, pre: bytes, quotient: bytes, final: bytes) -> None:
        root_900 = bytes((9,)) * 64
        root_901 = bytes((11,)) * 64
        accepted_901 = quotient[:20] + root_900 + quotient[84:]
        accepted_902 = final[:12] + root_901 + final[76:]
        metadata = [bytes((10 + index,)) * 64 for index in range(7)]
        metadata[1] = root_901
        bundle = b"verified-parent-bundle"
        (output / client.PARENT_BUNDLE_FILE).write_bytes(bundle)
        self.stdout = BytesIO(
            b"READY\n"
            + b"ROUND900_ACCEPTED " + pre.hex().encode() + b" " + root_900.hex().encode() + b"\n"
            + b"ROUND901_ACCEPTED " + accepted_901.hex().encode() + b" "
            + b" ".join(value.hex().encode() for value in metadata) + b"\n"
            + b"ROUND902_PREPARED " + accepted_902.hex().encode() + b"\n"
            + f"FINISHED {len(bundle)} {sha3_512(bundle).hexdigest()}\n".encode()
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


def test_staged_parent_provider_preserves_exact_transaction(monkeypatch, tmp_path: Path) -> None:
    service = (tmp_path / "parent.exe").resolve()
    coin = (tmp_path / "coin.exe").resolve()
    service.write_bytes(b"fixture")
    coin.write_bytes(b"fixture")
    output = (tmp_path / "output").resolve()
    output.mkdir()
    pre = b"p" * client.PARENT_PRE_ALPHA_BYTES
    quotient = b"q" * client.PARENT_QUOTIENT_BYTES
    final = b"f" * client.PARENT_FINAL_BYTES
    observed: dict[str, object] = {}

    def popen(command: list[str], **kwargs: object) -> _Process:
        observed["command"] = command
        observed["kwargs"] = kwargs
        process = _Process(output, pre, quotient, final)
        observed["process"] = process
        return process

    monkeypatch.setattr(client.subprocess, "Popen", popen)
    provider = client.StagedCompositeParentProvider(
        service_executable=service,
        chained_coin_service=coin,
        output_directory=output,
        pre_alpha_builder=lambda prefix, root: pre,
        quotient_builder=lambda alpha: quotient,
        final_builder=lambda continuation, root: final,
        anchor_observer=lambda point: observed.setdefault("anchor", point),
        timeout_seconds=1,
    )
    zero = Fp16.zero()
    prefix = SemanticV3PrefixEvidence(
        b"p", bytes((1,)) * 64, bytes((2,)) * 64, bytes((3,)) * 64,
        bytes((4,)) * 64, bytes((5,)) * 64, bytes((6,)) * 64,
        zero, zero, zero, bytes((7,)) * 64, (), (),
    )
    round_900 = provider(prefix, bytes((8,)) * 64)
    round_901 = round_900.advance(Fp16.one())
    z = CirclePoint(Fp16.zero(), Fp16.one())
    anchor = round_901.anchor(z)
    continuation = SemanticV3ContinuationEvidence(b"c", bytes((20,)) * 64, zero, (), bytes((21,)) * 64, ())
    round_902 = round_901.prepare_final(continuation, bytes((22,)) * 128)
    parent = round_902.commit(Fp16.one())

    assert anchor == parent.anchor_state
    assert observed["anchor"] == z
    assert parent.parent_bundle == b"verified-parent-bundle"
    assert round_901.prover_message[20:84] == bytes((9,)) * 64
    assert round_902.prover_message[12:76] == bytes((11,)) * 64
    process = observed["process"]
    assert isinstance(process, _Process)
    assert bytes(process.stdin.data) == b"".join((
        b"ROUND900 " + pre.hex().encode() + b"\n",
        b"ROUND901 " + quotient.hex().encode() + b"\n",
        b"PREPARE902 " + final.hex().encode() + b"\n",
        b"COMMIT902 " + round_902.prover_message.hex().encode() + b"\n",
    ))
    assert observed["command"] == [str(service), str(coin), str(output)]


def test_parent_template_encoders_use_canonical_fixed_shapes() -> None:
    zero = Fp16.zero()
    semantic_program = bytes((30,)) * 64
    prefix_encoded = (
        b"BLV3SP01" + b"\x00\x01\x00\x00" + bytes((31,)) * 64
        + bytes((32,)) * 64 + semantic_program + b"tail"
    )
    prefix = SemanticV3PrefixEvidence(
        prefix_encoded, bytes((1,)) * 64, bytes((2,)) * 64,
        bytes((3,)) * 64, bytes((4,)) * 64, bytes((5,)) * 64,
        bytes((6,)) * 64, zero, zero, zero, bytes((7,)) * 64, (), (),
    )
    pre = client.encode_parent_pre_alpha_template(
        profile_code=1, composite_session_id=bytes((8,)) * 64, attempt=0,
        schedule_commitment=bytes((9,)) * 64,
        parent_program_commitment=bytes((10,)) * 64,
        candidate_descriptor_commitment=bytes((11,)) * 64,
        statement_commitment=bytes((12,)) * 64, prefix=prefix,
        semantic_composition_root=bytes((13,)) * 64,
        h4_child_final_root=bytes((14,)) * 64,
        h4_ordered_shard_root_receipt=bytes((15,)) * 64,
        h4_source_root=bytes((16,)) * 64, h4_b_tensor_root=bytes((17,)) * 64,
        h4_n_tensor_root=bytes((18,)) * 64, h4_a_tensor_root=bytes((19,)) * 64,
        bridge_mask_base_aggregate_root=bytes((20,)) * 64,
        bridge_mask_pad_aggregate_root=bytes((21,)) * 64,
    )
    coefficients = tuple(zero for _ in range(4_789))
    quotient = client.encode_parent_quotient_template(
        profile_code=1, answer_aggregate_root=bytes((22,)) * 64,
        message_coefficients=coefficients, digest_coefficients=coefficients,
    )
    continuation = SemanticV3ContinuationEvidence(
        b"continuation", bytes((23,)) * 64, zero, (), bytes((24,)) * 64, ()
    )
    final = client.encode_parent_final_template(
        continuation=continuation,
        post_z_response_oracle_root=bytes((25,)) * 64,
        post_z_claim_vector_commitment=bytes((26,)) * 64,
        semantic_component_package_commitment=bytes((27,)) * 64,
        h4_component_package_commitment=bytes((28,)) * 64,
        typed_component_package_commitment=bytes((29,)) * 64,
        typed_verified_receipt_commitment=bytes((30,)) * 64,
        h4_booleanity_receipt_commitment=bytes((31,)) * 64,
        h4_global_padding_receipt_commitment=bytes((32,)) * 64,
        bridge_privacy_ledger_commitment=bytes((33,)) * 64,
        semantic_exposure_ledger_commitment=bytes((34,)) * 64,
        h4_exposure_ledger_commitment=bytes((35,)) * 64,
    )
    assert len(pre) == client.PARENT_PRE_ALPHA_BYTES
    assert pre[348:412] == semantic_program
    assert len(quotient) == client.PARENT_QUOTIENT_BYTES
    assert quotient[20:84] == bytes(64)
    assert len(final) == client.PARENT_FINAL_BYTES
    assert final[12:76] == bytes(64)
