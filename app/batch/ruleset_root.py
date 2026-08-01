from __future__ import annotations

from typing import Mapping

from app.batch.poseidon import domain_poseidon_hash


INLINE_POLICY_MODE = 1
ARTIFACT_POLICY_MODE = 2


def _bytes_to_words(data: bytes) -> tuple[int, ...]:
    if not data:
        return (0,)
    return tuple(int.from_bytes(data[index : index + 16], "big") for index in range(0, len(data), 16))


def _text_commitment(value: str) -> int:
    raw = value.encode("utf-8")
    words = _bytes_to_words(raw)
    acc = domain_poseidon_hash("ruleset", [len(raw), len(words)])
    for index, word in enumerate(words):
        acc = domain_poseidon_hash("ruleset", [len(raw), len(words), index, acc, word])
    return acc


def _hex32_words(value: str) -> tuple[int, int]:
    clean = str(value).lower().removeprefix("0x")
    if len(clean) != 64:
        raise ValueError("ruleset artifact digest must be 32-byte hex")
    parsed = int(clean, 16)
    return parsed >> 128, parsed & (2**128 - 1)


def ruleset_artifact_manifest_commitment(artifacts: Mapping[str, str]) -> int:
    ordered = tuple(sorted((str(path), str(digest)) for path, digest in artifacts.items()))
    acc = domain_poseidon_hash("ruleset", [ARTIFACT_POLICY_MODE, len(ordered)])
    for index, (path, digest) in enumerate(ordered):
        path_commitment = _text_commitment(path)
        high, low = _hex32_words(digest)
        acc = domain_poseidon_hash(
            "ruleset",
            [ARTIFACT_POLICY_MODE, len(ordered), index, acc, path_commitment, high, low],
        )
    return acc


def ruleset_inline_policy_commitment(policy_content: str) -> int:
    return _text_commitment(policy_content)


def ruleset_policy_digest(
    ruleset_version: str,
    *,
    policy_content: str | None = None,
    artifacts: Mapping[str, str] | None = None,
) -> int:
    mode, version_commitment, payload_commitment = ruleset_policy_digest_inputs(
        ruleset_version,
        policy_content=policy_content,
        artifacts=artifacts,
    )
    return domain_poseidon_hash("ruleset", [mode, version_commitment, payload_commitment])


def ruleset_policy_digest_inputs(
    ruleset_version: str,
    *,
    policy_content: str | None = None,
    artifacts: Mapping[str, str] | None = None,
) -> tuple[int, int, int]:
    version_commitment = _text_commitment(ruleset_version)
    if policy_content is None:
        if artifacts is None:
            raise ValueError("artifact policy bundle requires artifacts")
        mode = ARTIFACT_POLICY_MODE
        payload_commitment = ruleset_artifact_manifest_commitment(artifacts)
    else:
        mode = INLINE_POLICY_MODE
        payload_commitment = ruleset_inline_policy_commitment(policy_content)
    return mode, version_commitment, payload_commitment


def ruleset_policy_digest_hex(
    ruleset_version: str,
    *,
    policy_content: str | None = None,
    artifacts: Mapping[str, str] | None = None,
) -> str:
    return f"{ruleset_policy_digest(ruleset_version, policy_content=policy_content, artifacts=artifacts):064x}"
