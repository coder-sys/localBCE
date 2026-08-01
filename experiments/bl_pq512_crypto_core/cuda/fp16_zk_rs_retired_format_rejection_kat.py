"""Fail-closed KAT for proof formats retired by the complete GKR-mask binding."""

import struct
import subprocess
from pathlib import Path


def reject(executable, payload, expected_error, label):
    result = subprocess.run(
        [str(executable)],
        input=payload,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if (
        result.returncode != 2
        or result.stdout
        or expected_error not in result.stderr
    ):
        raise SystemExit(
            f"{label}_not_rejected="
            f"status={result.returncode};stdout={result.stdout!r};"
            f"stderr={result.stderr!r}"
        )


def main():
    release = Path(__file__).resolve().parents[1] / "target" / "release"
    answer_code = release / "fp16_zk_rs_answer_code_verify.exe"
    answer_target = release / "fp16_zk_rs_answer_target.exe"
    spotcheck = release / "fp16_zk_rs_spotcheck_verify.exe"
    interleaved = release / "fp16_zk_rs_interleaved_verify.exe"
    for executable in (
        answer_code,
        answer_target,
        spotcheck,
        interleaved,
    ):
        if not executable.is_file():
            raise SystemExit(f"native_verifier_missing={executable}")

    for version in (1, 2, 3):
        reject(
            answer_code,
            f"BLRSCV0{version}".encode("ascii"),
            b"ERR:magic",
            f"answer_code_v{version}",
        )
    reject(
        answer_target,
        b"BLRSTA01",
        b"ERR:input_magic",
        "answer_target_v1",
    )
    for version in (1, 2):
        reject(
            spotcheck,
            f"BLSPOT0{version}".encode("ascii"),
            b"ERR:magic",
            f"spotcheck_v{version}",
        )
    for segment_count in (16, 19, 32, 35):
        reject(
            interleaved,
            b"BLZKRSV1" + struct.pack(">I", segment_count),
            b"ERR:segment_count:expected=20|36",
            f"interleaved_segments_{segment_count}",
        )

    print("kat=fp16_zk_rs_retired_format_rejection_v1")
    print("retired_answer_code_formats_rejected=3/3")
    print("retired_answer_target_formats_rejected=1/1")
    print("retired_spotcheck_formats_rejected=2/2")
    print("incomplete_segment_counts_rejected=4/4")
    print("fail_closed=true")


if __name__ == "__main__":
    main()
