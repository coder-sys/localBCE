#!/usr/bin/env python3
"""Fail closed on common committed credential forms with narrow test-key exceptions."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".json", ".md", ".py", ".rs", ".sh", ".sol", ".toml", ".yaml", ".yml", ".env"}
PATTERNS = {
    "github_token": re.compile(r"\bgh[ps]_[A-Za-z0-9]{30,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "pem_private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "assigned_hex_private_key": re.compile(
        r"(?i)(?:private[_ -]?key|secret[_ -]?key)[^\n]{0,40}[=:]\s*[\"']?(0x[0-9a-f]{64})"
    ),
}
TEST_KEYS = {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x00000000000000000000000000000000000000000000000000000000000a11ce",
}
TEST_KEY_FILES = {
    "scripts/validate_stark_runtime_settlement.sh",
    "scripts/validate_stark_v2_anvil.sh",
    "scripts/validate_stark_bridge_chain.sh",
    "blind-ledger-app-layer/l2/anvil.devnet.json",
    "rust-engine/config.json",
    "rust-engine/src/main.rs",
}


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def main() -> int:
    findings: list[str] = []
    for relative in tracked_files():
        path = ROOT / relative
        if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for name, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                secret = next((group for group in match.groups() if group), match.group(0)).lower()
                if relative in TEST_KEY_FILES and secret in TEST_KEYS:
                    continue
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{relative}:{line}: {name}")
    if findings:
        print("[FAIL] possible committed secrets:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("[OK] tracked-and-untracked secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
