"""Audit the exact public Hint-MLWE implementation without modifying it."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from experiments.bl_pq512_hint_mlwe_392.parameter_gate import (
    EXPECTED_UPSTREAM_COMMIT,
)


@dataclass(frozen=True, slots=True)
class SourceAudit:
    checkout: str
    commit: str
    commit_matches: bool
    lambda_values: tuple[int, ...]
    challenge_space_bits: tuple[int, ...]
    shake128_occurrences: int
    fiat_shamir_occurrences: int
    repetition_formula_uses_failure_probability: bool
    challenge_sampler_norm_check_present: bool | None
    lazar_gitlink_commit: str
    estimator_gitlink_commit: str
    findings: tuple[str, ...]


def _read_texts(root: Path, pattern: str) -> tuple[tuple[Path, str], ...]:
    return tuple(
        (path, path.read_text(encoding="utf-8", errors="strict"))
        for path in sorted(root.glob(pattern))
        if path.is_file()
    )


def inspect_source_texts(
    script_texts: tuple[str, ...], source_texts: tuple[str, ...]
) -> tuple[tuple[int, ...], tuple[int, ...], int, int, bool]:
    joined_scripts = "\n".join(script_texts)
    joined_sources = "\n".join(source_texts)
    lambda_values = tuple(
        sorted(
            {
                int(value)
                for value in re.findall(
                    r"(?m)^\s*LAMBDA\s*=\s*(\d+)\s*$", joined_scripts
                )
            }
        )
    )
    challenge_bits = tuple(
        sorted(
            {
                int(value)
                for value in re.findall(
                    r"(?m)^\s*Csize\s*=\s*2\s*\*\*\s*(\d+)\s*$",
                    joined_scripts,
                )
            }
        )
    )
    return (
        lambda_values,
        challenge_bits,
        joined_sources.lower().count("shake128"),
        joined_sources.lower().count("fiat-shamir"),
        bool(
            re.search(
                r"lmbda\s*=\s*2\s*\*\s*ceil\s*\(\s*param_sec\s*/",
                joined_scripts,
            )
        ),
    )


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _gitlink(root: Path, name: str) -> str:
    line = _git(root, "ls-tree", "HEAD", "--", name)
    if not line:
        return ""
    fields = line.split()
    return fields[2] if len(fields) >= 4 and fields[1] == "commit" else ""


def challenge_sampler_enforces_norm(sampler_text: str) -> bool | None:
    match = re.search(
        r"_intvec_urandom_autostable\s*\([^)]*\)\s*\{(?P<body>.*?)\n\s*\}",
        sampler_text,
        re.DOTALL,
    )
    if match is None:
        return None
    body = match.group("body").lower()
    return any(token in body for token in ("eta", "norm", "l1"))


def audit_checkout(checkout: Path) -> SourceAudit:
    root = checkout.resolve(strict=True)
    commit = _git(root, "rev-parse", "HEAD")
    scripts = _read_texts(root / "scripts", "*.sage")
    sources = _read_texts(root / "src", "*.c")
    (
        lambda_values,
        challenge_bits,
        shake_count,
        fs_count,
        repetition_probability,
    ) = inspect_source_texts(
            tuple(text for _, text in scripts),
            tuple(text for _, text in sources),
        )
    lazar_commit = _gitlink(root, "lazer")
    estimator_commit = _gitlink(root, "lattice-estimator")
    sampler_path = root / "lazer" / "src" / "intvec.c"
    sampler_norm_check = (
        challenge_sampler_enforces_norm(
            sampler_path.read_text(encoding="utf-8", errors="strict")
        )
        if sampler_path.is_file()
        else None
    )
    findings: list[str] = []
    if commit != EXPECTED_UPSTREAM_COMMIT:
        findings.append("upstream_commit_mismatch")
    if lambda_values != (128,):
        findings.append(f"unexpected_lambda_values:{lambda_values!r}")
    else:
        findings.append("published_parameter_generator_is_128_bit")
    if not challenge_bits:
        findings.append("challenge_spaces_not_detected")
    elif min(challenge_bits) < 392:
        findings.append(
            "published_challenge_space_below_392:"
            + ",".join(str(value) for value in challenge_bits)
        )
    if shake_count:
        findings.append(f"shake128_present:{shake_count}")
    if fs_count:
        findings.append(f"fiat_shamir_present:{fs_count}")
    if repetition_probability:
        findings.append("repetition_formula_uses_failure_probability_not_bits")
    if sampler_norm_check is False:
        findings.append("challenge_sampler_does_not_enforce_eta")
    elif sampler_norm_check is None:
        findings.append("challenge_sampler_not_inspected")
    if not lazar_commit:
        findings.append("lazer_gitlink_not_pinned")
    if not estimator_commit:
        findings.append("lattice_estimator_gitlink_not_pinned")
    return SourceAudit(
        checkout=str(root),
        commit=commit,
        commit_matches=commit == EXPECTED_UPSTREAM_COMMIT,
        lambda_values=lambda_values,
        challenge_space_bits=challenge_bits,
        shake128_occurrences=shake_count,
        fiat_shamir_occurrences=fs_count,
        repetition_formula_uses_failure_probability=repetition_probability,
        challenge_sampler_norm_check_present=sampler_norm_check,
        lazar_gitlink_commit=lazar_commit,
        estimator_gitlink_commit=estimator_commit,
        findings=tuple(findings),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkout", type=Path)
    arguments = parser.parse_args()
    report = audit_checkout(arguments.checkout)
    print(json.dumps(asdict(report), indent=2, sort_keys=True))
    return 1 if not report.commit_matches else 0


if __name__ == "__main__":
    raise SystemExit(main())
