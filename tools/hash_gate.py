#!/usr/bin/env python3
"""Read-only identity gate for the two authorized FW 14.00 artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import BinaryIO


ARTIFACTS = {
    "capture": (
        44040192,
        "8b2fe4b1c1ef3504cbf871bea31b4fb6d36b83158fcabf58bd89fc2c872ca0a2",
    ),
    "analysis-elf": (
        44040192,
        "b20a94820aef512490d6167497eb00f9eaa5c780814fe19361b4f00cb7713c3b",
    ),
}


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def digest_stream(stream: BinaryIO) -> str:
    result = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        result.update(chunk)
    stream.seek(0)
    return result.hexdigest()


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return digest_stream(stream)


def identify_stream(stream: BinaryIO, expected: str = "any") -> dict[str, object]:
    if expected != "any" and expected not in ARTIFACTS:
        raise ValueError(f"unknown expected artifact: {expected}")
    before = os.fstat(stream.fileno())
    if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
        raise ValueError("input is not a regular file")
    size = before.st_size
    candidates = ARTIFACTS.items() if expected == "any" else [(expected, ARTIFACTS[expected])]
    size_matches = [(kind, values) for kind, values in candidates if values[0] == size]
    if not size_matches:
        raise ValueError(f"unrecognized size: {size}")
    value = digest_stream(stream)
    after = os.fstat(stream.fileno())
    if _identity(before) != _identity(after):
        raise ValueError("input changed while hashing")
    for kind, (_, known) in size_matches:
        if value == known:
            return {"recognized": True, "kind": kind, "size": size, "sha256": value}
    raise ValueError(f"unrecognized SHA-256 for {size}-byte input: {value}")


def identify(path: Path, expected: str = "any") -> dict[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        return identify_stream(stream, expected)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only exact-hash gate for the FW 14.00 capture and prepared ELF."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--expect", choices=("any", *ARTIFACTS), default="any")
    args = parser.parse_args()
    try:
        result = identify(args.input, args.expect)
    except (OSError, ValueError) as error:
        parser.exit(2, f"error: {error}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
