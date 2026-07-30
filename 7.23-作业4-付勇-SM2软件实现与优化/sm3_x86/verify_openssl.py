#!/usr/bin/env python3
"""Differential-test the auto-dispatch implementation against OpenSSL SM3."""

from __future__ import annotations

import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    cli = root / "sm3_x86_cli"
    if not cli.exists():
        subprocess.run(["make", "sm3_x86_cli"], cwd=root, check=True)

    probe = subprocess.run(
        ["openssl", "list", "-digest-algorithms"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if probe.returncode != 0 or "SM3" not in probe.stdout.upper():
        print("OpenSSL in this environment does not expose SM3", file=sys.stderr)
        return 2

    rng = random.Random(0x534D33)
    lengths = [
        0, 1, 2, 3, 54, 55, 56, 57, 62, 63, 64, 65,
        119, 120, 121, 127, 128, 129, 1024, 4096, 8192,
    ]
    lengths.extend(rng.randrange(0, 8193) for _ in range(128))

    with tempfile.TemporaryDirectory(prefix="sm3-x86-") as tmp:
        paths: list[Path] = []
        for index, length in enumerate(lengths):
            path = Path(tmp) / f"case-{index:03d}-{length}.bin"
            path.write_bytes(os.urandom(length))
            paths.append(path)

        output = subprocess.check_output(
            [str(cli), *(str(path) for path in paths)], text=True
        ).splitlines()
        if len(output) != len(paths):
            print("unexpected CLI output line count", file=sys.stderr)
            return 1

        for index, (path, actual_hex) in enumerate(zip(paths, output)):
            expected = subprocess.check_output(
                ["openssl", "dgst", "-sm3", "-binary", str(path)]
            ).hex()
            if actual_hex.strip() != expected:
                print(
                    f"mismatch case={index} len={lengths[index]}\n"
                    f"expected={expected}\nactual  ={actual_hex}",
                    file=sys.stderr,
                )
                return 1

    print(
        f"[PASS] {len(lengths)} files matched OpenSSL SM3; "
        f"backend={subprocess.check_output([str(root / 'sm3_x86_test')], text=True).splitlines()[2]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
