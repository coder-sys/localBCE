from __future__ import annotations

import os
from pathlib import Path


def load_env_file(workdir: Path) -> None:
    env_path = find_env_file(workdir)
    if env_path is None:
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def find_env_file(workdir: Path) -> Path | None:
    candidates = [
        workdir / ".env",
        workdir / "gov-rules-kg-prototype" / ".env",
        Path(__file__).resolve().parents[2] / ".env",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None
