#!/usr/bin/env python3
"""Validate private exporter shards and emit content-free coverage facts."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import BinaryIO


EXPECTED_COUNT = 19809
EXPECTED_OK = 19808
EXPECTED_FAILURE_INDICES = [16151]
ANALYSIS_SHA256 = "b20a94820aef512490d6167497eb00f9eaa5c780814fe19361b4f00cb7713c3b"
GHIDRA_VERSION = "12.1.3"
TOOL = f"Ghidra {GHIDRA_VERSION}"
SCHEMA = "ps4-fw14-private-" + "coverage.v1"
SHARD_SCHEMA = "ps4-fw14-private-" + "shard.v1"
MAX_SHARD_COUNT = 10000
MAX_METADATA_SIZE = 64 * 1024 * 1024
MAX_COMPRESSED_SIZE = 512 * 1024 * 1024
MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024
MAX_LINE_SIZE = 4 * 1024 * 1024
MAX_FIELD_SIZE = 1024 * 1024
NAME = re.compile(r"^shard-(\d{6})-(\d{6})\.(metadata\.tsv|pseudocode\.txt\.gz)$")
PSEUDOCODE_MARKER = re.compile(r"^===== " r"FUNCTION (\d+) =====\n$")
HEADER = ["index", "status", "address", "name", "signature", "error"]
STATUSES = {"ok", "decompile_failed"}
REPOSITORY = Path(__file__).resolve().parents[1]


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
def _same_opened_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )



def _require_path_identity(path: Path, expected: os.stat_result, label: str) -> None:
    try:
        current = os.lstat(path)
    except OSError as error:
        raise ValueError(f"{label} path changed while reading: {path.name}") from error
    if not _same_opened_object(current, expected):
        raise ValueError(f"{label} path changed while reading: {path.name}")



def _within(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((os.path.normcase(str(path)), os.path.normcase(str(parent)))) == os.path.normcase(
            str(parent)
        )
    except ValueError:
        return False


def _open_regular(path: Path, maximum_size: int) -> tuple[BinaryIO, os.stat_result]:
    try:
        path_info = os.lstat(path)
    except OSError as error:
        raise ValueError(f"cannot inspect shard path: {path.name}") from error
    if (
        not stat.S_ISREG(path_info.st_mode)
        or stat.S_ISLNK(path_info.st_mode)
        or _is_reparse(path_info)
    ):
        raise ValueError(f"non-regular shard path: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or _is_reparse(info):
            raise ValueError(f"non-regular shard path: {path.name}")
        if not _same_opened_object(path_info, info):
            raise ValueError(f"shard path changed before opening: {path.name}")
        if info.st_size > maximum_size:
            raise ValueError(f"oversized shard path: {path.name}")
        return os.fdopen(descriptor, "rb"), info
    except Exception:
        os.close(descriptor)
        raise


def _sha256_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _preamble(start: int, count: int) -> list[str]:
    return [
        f"# schema={SHARD_SCHEMA}\n",
        f"# program_sha256={ANALYSIS_SHA256}\n",
        f"# ghidra_version={GHIDRA_VERSION}\n",
        f"# start={start}\n",
        f"# count={count}\n",
    ]


def _read_metadata(path: Path, start: int, count: int) -> tuple[list[tuple[int, str]], str]:
    stream, before = _open_regular(path, MAX_METADATA_SIZE)
    with stream:
        data = stream.read(MAX_METADATA_SIZE + 1)
        after = os.fstat(stream.fileno())
    if len(data) != before.st_size or _identity(before) != _identity(after):
        raise ValueError(f"metadata changed while reading: {path.name}")
    _require_path_identity(path, after, "metadata")
    digest = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"invalid UTF-8 metadata: {path.name}") from error

    source = io.StringIO(text, newline="")
    for expected in _preamble(start, count):
        if source.readline() != expected:
            raise ValueError(f"invalid shard provenance in {path.name}")

    previous_limit = csv.field_size_limit()
    csv.field_size_limit(MAX_FIELD_SIZE)
    try:
        reader = csv.DictReader(source, delimiter="\t")
        if reader.fieldnames != HEADER:
            raise ValueError(f"invalid metadata header in {path.name}")
        rows: list[tuple[int, str]] = []
        for row in reader:
            if len(rows) >= count:
                raise ValueError(f"row count mismatch in {path.name}")
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"malformed metadata row in {path.name}")
            try:
                index = int(row["index"])
            except ValueError as error:
                raise ValueError(f"invalid index in {path.name}") from error
            status = row["status"]
            if status not in STATUSES:
                raise ValueError(f"invalid status in {path.name}")
            rows.append((index, status))
    finally:
        csv.field_size_limit(previous_limit)

    if len(rows) != count:
        raise ValueError(f"row count mismatch in {path.name}")
    indices = [index for index, _status in rows]
    if indices != list(range(start, start + count)):
        raise ValueError(f"non-contiguous indices in {path.name}")
    return rows, digest


def _read_pseudocode_indices(path: Path, expected_count: int) -> tuple[list[int], str]:
    stream, before = _open_regular(path, MAX_COMPRESSED_SIZE)
    with stream:
        compressed_hash = _sha256_stream(stream)
        stream.seek(0)
        indices: list[int] = []
        decompressed_size = 0
        try:
            with gzip.GzipFile(fileobj=stream, mode="rb") as pseudocode:
                while True:
                    line = pseudocode.readline(MAX_LINE_SIZE + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE_SIZE:
                        raise ValueError(f"oversized pseudocode line in {path.name}")
                    decompressed_size += len(line)
                    if decompressed_size > MAX_DECOMPRESSED_SIZE:
                        raise ValueError(f"oversized decompressed pseudocode in {path.name}")
                    try:
                        decoded = line.decode("utf-8")
                    except UnicodeError as error:
                        raise ValueError(f"invalid pseudocode UTF-8 in {path.name}") from error
                    match = PSEUDOCODE_MARKER.fullmatch(decoded)
                    if match:
                        indices.append(int(match.group(1)))
                        if len(indices) > expected_count:
                            raise ValueError(f"too many pseudocode markers in {path.name}")
        except (gzip.BadGzipFile, EOFError) as error:
            raise ValueError(f"invalid pseudocode gzip {path.name}") from error
        after = os.fstat(stream.fileno())
    if _identity(before) != _identity(after):
        raise ValueError(f"pseudocode shard changed while reading: {path.name}")
    _require_path_identity(path, after, "pseudocode shard")
    return indices, compressed_hash


def aggregate(directory: Path) -> dict[str, object]:
    try:
        root_info = os.lstat(directory)
    except OSError as error:
        raise ValueError(f"cannot inspect private shard directory: {error}") from error
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode) or _is_reparse(root_info):
        raise ValueError("private shard directory is not a regular directory")
    shard_root = directory.resolve(strict=True)
    if _within(shard_root, REPOSITORY):
        raise ValueError("private shard directory must be outside the public repository")

    pairs: dict[tuple[int, int], dict[str, Path]] = {}
    try:
        entries = sorted(directory.iterdir())
    except OSError as error:
        raise ValueError(f"cannot enumerate private shard directory: {error}") from error
    _require_path_identity(directory, root_info, "private shard directory")
    if not entries:
        raise ValueError("private shard directory is empty")
    for path in entries:
        match = NAME.fullmatch(path.name)
        if match is None:
            raise ValueError(f"unexpected or malformed shard path: {path.name}")
        start, count = int(match.group(1)), int(match.group(2))
        if count == 0:
            raise ValueError(f"zero-count shard: {path.name}")
        if count > MAX_SHARD_COUNT:
            raise ValueError(f"oversized shard range: {path.name}")
        if start + count > EXPECTED_COUNT:
            raise ValueError(f"out-of-range shard: {path.name}")
        kind = match.group(3)
        record = pairs.setdefault((start, count), {})
        if kind in record:
            raise ValueError(f"duplicate shard member: {path.name}")
        record[kind] = path

    seen: list[int] = []
    categories: Counter[str] = Counter()
    failures: list[int] = []
    shard_hashes: list[dict[str, object]] = []
    for (start, count), pair in sorted(pairs.items()):
        if set(pair) != {"metadata.tsv", "pseudocode.txt.gz"}:
            raise ValueError(f"orphan shard at {start}+{count}")
        metadata = pair["metadata.tsv"]
        pseudocode = pair["pseudocode.txt.gz"]
        rows, metadata_hash = _read_metadata(metadata, start, count)
        pseudocode_indices, pseudocode_hash = _read_pseudocode_indices(pseudocode, count)
        indices = [index for index, _status in rows]
        if pseudocode_indices != indices:
            raise ValueError(f"pseudocode marker sequence mismatch at {start}+{count}")
        for index, status in rows:
            categories[status] += 1
            if status == "decompile_failed":
                failures.append(index)
        seen.extend(indices)
        shard_hashes.append(
            {
                "metadata_sha256": metadata_hash,
                "pseudocode_gzip_sha256": pseudocode_hash,
                "start": start,
                "count": count,
            }
        )
    _require_path_identity(directory, root_info, "private shard directory")

    counts = Counter(seen)
    missing = [index for index in range(EXPECTED_COUNT) if counts[index] == 0]
    duplicates = sorted(index for index, amount in counts.items() if amount > 1)
    structurally_complete = not missing and not duplicates
    matches_observed = (
        structurally_complete
        and categories == Counter({"ok": EXPECTED_OK, "decompile_failed": len(EXPECTED_FAILURE_INDICES)})
        and failures == EXPECTED_FAILURE_INDICES
    )
    return {
        "schema": SCHEMA,
        "expected_functions": EXPECTED_COUNT,
        "observed_rows": len(seen),
        "status_counts": dict(sorted(categories.items())),
        "decompile_failed_indices": failures,
        "expected_manual_fallback_indices": EXPECTED_FAILURE_INDICES,
        "missing_indices": missing,
        "duplicate_indices": duplicates,
        "out_of_range_indices": [],
        "complete": structurally_complete,
        "matches_observed_automated_coverage": matches_observed,
        "producer_claims": {
            "input_sha256": ANALYSIS_SHA256,
            "tool": TOOL,
            "shard_schema": SHARD_SCHEMA,
        },
        "provenance_verified": False,
        "provenance_note": (
            "Shard preambles are validated exporter claims, not a cryptographic attestation; "
            "manual fallback correctness requires separate private review."
        ),
        "shards": shard_hashes,
    }


def _reject_linked_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            continue
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise ValueError(f"refusing symlink/reparse output component: {current}")


def _remove_owned_summary(path: Path, expected: os.stat_result) -> None:
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(current.st_mode)
        or _is_reparse(current)
        or not _same_opened_object(current, expected)
    ):
        raise ValueError(f"refusing to remove changed summary path: {path}")
    path.unlink()


def write_summary_no_clobber(output: Path, text: str) -> None:
    output = Path(os.path.abspath(output))
    _reject_linked_components(output)
    if _within(output.resolve(strict=False), REPOSITORY):
        raise ValueError("summary output must be outside the public repository")
    if os.path.lexists(output):
        raise ValueError("refusing to overwrite or follow summary output")
    output.parent.mkdir(parents=True, exist_ok=True)
    _reject_linked_components(output.parent)
    temporary_path: Path | None = None
    temporary_identity: os.stat_result | None = None
    target_created = False
    completed = False
    primary_failure: BaseException | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(text)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_identity = os.fstat(temporary.fileno())
            path_info = os.lstat(temporary_path)
            if (
                not stat.S_ISREG(temporary_identity.st_mode)
                or _is_reparse(temporary_identity)
                or temporary_identity.st_nlink != 1
                or not _same_opened_object(temporary_identity, path_info)
            ):
                raise ValueError("summary temporary file is not bound to its path")
        _reject_linked_components(output.parent)
        if os.path.lexists(output):
            raise ValueError("refusing to overwrite summary output")
        if not _same_opened_object(temporary_identity, os.lstat(temporary_path)):
            raise ValueError("summary temporary file changed before publication")
        try:
            os.link(temporary_path, output, follow_symlinks=False)
        except FileExistsError as error:
            raise ValueError("refusing to overwrite summary output") from error
        target_created = True
        if not _same_opened_object(temporary_identity, os.lstat(output)):
            raise ValueError("published summary is not the validated temporary file")
        _remove_owned_summary(temporary_path, temporary_identity)
        temporary_path = None
        final_info = os.lstat(output)
        if (
            not _same_opened_object(temporary_identity, final_info)
            or final_info.st_nlink != 1
        ):
            raise ValueError("published summary identity changed during commit")
        completed = True
    except BaseException as error:
        primary_failure = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if temporary_path is not None and temporary_identity is not None:
            try:
                _remove_owned_summary(temporary_path, temporary_identity)
            except BaseException as error:
                cleanup_errors.append(error)
        if target_created and not completed and temporary_identity is not None:
            try:
                _remove_owned_summary(output, temporary_identity)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if isinstance(primary_failure, Exception):
                cleanup_detail = "; ".join(str(error) for error in cleanup_errors)
                raise ValueError(
                    f"{primary_failure}; cleanup failure: {cleanup_detail}"
                ) from primary_failure
            if primary_failure is None:
                raise cleanup_errors[0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate canonical private Ghidra shards and emit privacy-safe JSON."
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        shard_root = args.directory.resolve(strict=True)
        result = aggregate(args.directory)
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            output = Path(os.path.abspath(args.output)).resolve(strict=False)
            if _within(output, shard_root):
                raise ValueError("summary output must be outside the shard directory")
            write_summary_no_clobber(output, text)
        else:
            print(text, end="")
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(2, f"error: {error}\n")
    return 0 if result["complete"] and result["matches_observed_automated_coverage"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
