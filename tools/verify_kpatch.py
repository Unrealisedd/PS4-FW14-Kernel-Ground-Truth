#!/usr/bin/env python3
"""Read-only verifier for the canonical FW 14.00 public kpatch replacement map."""
from __future__ import annotations

import argparse
import hashlib
import json
import io
import os
from pathlib import Path
import struct
import stat
import sys
from typing import Any, BinaryIO

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hash_gate

EH = struct.Struct("<16sHHIQQQIHHHHHH")
PH = struct.Struct("<IIQQQQQQ")
ANALYSIS_SHA256 = "b20a94820aef512490d6167497eb00f9eaa5c780814fe19361b4f00cb7713c3b"
SOURCE_COMMIT = "b9d961a4f4ea5328f6f40166390c2c4da426a500"
SOURCE_URL = (
    "https://github.com/Al-Azif/ps4-exploit-kpatches/blob/"
    + SOURCE_COMMIT
    + "/1400.c"
)
SEMANTICS = "Public replacement-byte map only; values are not stock-byte guards."
CANONICAL_MAP = Path(__file__).resolve().parents[1] / "firmware" / "1400-kpatch.json"
GROUP_COUNTS = {"do_patch": 27, "optional_aio": 12}
EXPECTED_OTHER = {"0x1102d80", "0x1102d88"}
MAX_IMAGE_SIZE = 44040192
EXPECTED_SITES_SHA256 = "8bbbd787305024bf33a3a6e87689691601f735d49e6c6c1436e11a45b5b3d319"
MAX_MAP_SIZE = 1024 * 1024

def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_nlink == right.st_nlink
    )



def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 2:
        raise ValueError(f"{label}: replacement_hex must be nonempty even-length hex")
    try:
        parsed = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label}: invalid replacement_hex") from error
    if not parsed:
        raise ValueError(f"{label}: empty replacement")
    return parsed


def validate_map(spec: Any) -> list[tuple[dict[str, Any], int, int]]:
    if not isinstance(spec, dict):
        raise ValueError("patch map must be an object")
    if set(spec) != {"schema", "firmware", "source", "semantics", "capture_observation", "sites"}:
        raise ValueError("patch map has unexpected fields")
    if spec.get("schema") != "ps4-fw14-kpatch-replacements.v1" or spec.get("firmware") != "14.00":
        raise ValueError("unexpected patch-map schema or firmware")
    if spec.get("semantics") != SEMANTICS:
        raise ValueError("unexpected patch-map semantics")
    source = spec.get("source")
    if not isinstance(source, dict) or source != {
        "repository": "https://github.com/Al-Azif/ps4-exploit-kpatches",
        "file": "1400.c",
        "license": "AGPL-3.0-or-later",
        "commit": SOURCE_COMMIT,
        "commit_url": SOURCE_URL,
    }:
        raise ValueError("unexpected patch-map source revision")
    observation = spec.get("capture_observation")
    if not isinstance(observation, dict):
        raise ValueError("missing capture observation")
    required_observation = {
        "capture_state": "post-HEN",
        "replacement_fields_matching": 37,
        "replacement_fields_total": 39,
        "differences": ["sysent[11].sy_narg", "sysent[11].sy_call"],
        "matching_special_field": "sysent[11].sy_thrcnt",
        "caveat": "Clean stock bytes cannot be derived from this capture.",
        "analysis_elf_sha256": ANALYSIS_SHA256,
    }
    if observation != required_observation:
        raise ValueError("unexpected capture observation")

    sites = spec.get("sites")
    if not isinstance(sites, list) or len(sites) != 39:
        raise ValueError("patch map must contain exactly 39 sites")
    ids: set[str] = set()
    names: set[str] = set()
    ranges: list[tuple[int, int, str]] = []
    groups = {key: 0 for key in GROUP_COUNTS}
    dynamic_count = 0
    validated: list[tuple[dict[str, Any], int, int]] = []
    for site in sites:
        if not isinstance(site, dict):
            raise ValueError("site must be an object")
        identifier = site.get("id")
        name = site.get("name")
        if not isinstance(identifier, str) or not identifier or identifier in ids:
            raise ValueError("site IDs must be nonempty and unique")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("site names must be nonempty and unique")
        ids.add(identifier)
        names.add(name)
        group = site.get("group")
        if group not in GROUP_COUNTS:
            raise ValueError(f"{identifier}: invalid group")
        groups[group] += 1
        rva_text = site.get("rva")
        if not isinstance(rva_text, str) or not rva_text.startswith("0x"):
            raise ValueError(f"{identifier}: invalid RVA")
        try:
            rva = int(rva_text, 16)
        except ValueError as error:
            raise ValueError(f"{identifier}: invalid RVA") from error
        if rva < 0 or rva >= MAX_IMAGE_SIZE:
            raise ValueError(f"{identifier}: RVA outside analysis image")
        has_hex = "replacement_hex" in site
        has_dynamic = "replacement_dynamic" in site
        if has_hex == has_dynamic:
            raise ValueError(f"{identifier}: exactly one replacement form is required")
        expected_keys = {"id", "name", "rva", "group", "expected_status"}
        expected_keys.add("replacement_hex" if has_hex else "replacement_dynamic")
        if set(site) != expected_keys:
            raise ValueError(f"{identifier}: unexpected site fields")
        if has_hex:
            expected = _hex_bytes(site["replacement_hex"], identifier)
        else:
            dynamic_count += 1
            dynamic = site["replacement_dynamic"]
            if dynamic != {
                "kind": "kernel_base_plus_rva",
                "target_rva": "0x250be",
                "width": 8,
            }:
                raise ValueError(f"{identifier}: invalid dynamic replacement")
            expected = b"\0" * 8
        end = rva + len(expected)
        if end > MAX_IMAGE_SIZE:
            raise ValueError(f"{identifier}: replacement extends outside analysis image")
        for previous_start, previous_end, previous_id in ranges:
            if rva < previous_end and previous_start < end:
                raise ValueError(f"{identifier}: overlaps {previous_id}")
        ranges.append((rva, end, identifier))
        expected_status = "other" if rva_text in EXPECTED_OTHER else "replacement"
        if site.get("expected_status") != expected_status:
            raise ValueError(f"{identifier}: invalid expected status")
        validated.append((site, rva, len(expected)))
    if groups != GROUP_COUNTS or dynamic_count != 1:
        raise ValueError("invalid patch-map group or dynamic-site counts")
    if sum(site[0]["expected_status"] == "replacement" for site in validated) != 37:
        raise ValueError("invalid expected status counts")
    sites_payload = json.dumps(
        sites, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    if hashlib.sha256(sites_payload).hexdigest() != EXPECTED_SITES_SHA256:
        raise ValueError("patch sites diverge from the pinned public-source transcription")
    return validated


def load_canonical_map(path: Path) -> tuple[dict[str, Any], list[tuple[dict[str, Any], int, int]], str]:
    requested = Path(os.path.abspath(path))
    canonical = Path(os.path.abspath(CANONICAL_MAP))
    if os.path.normcase(str(requested)) != os.path.normcase(str(canonical)):
        raise ValueError("custom patch maps are not accepted")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(canonical, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        path_before = os.lstat(canonical)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
            or not _same_file_snapshot(opened, path_before)
        ):
            raise ValueError("canonical patch map is not a stable regular file")
        raw = stream.read(MAX_MAP_SIZE + 1)
        final = os.fstat(stream.fileno())
        path_after = os.lstat(canonical)
    if len(raw) > MAX_MAP_SIZE:
        raise ValueError("canonical patch map is too large")
    if (
        len(raw) != opened.st_size
        or not _same_file_snapshot(opened, final)
        or not _same_file_snapshot(final, path_after)
    ):
        raise ValueError("canonical patch map changed while reading")
    try:
        spec = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid patch-map JSON") from error
    validated = validate_map(spec)
    return spec, validated, hashlib.sha256(raw).hexdigest()


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def kernel_base(stream: BinaryIO) -> int:
    stream.seek(0)
    raw = stream.read(EH.size)
    if len(raw) != EH.size:
        raise ValueError("truncated ELF header")
    header = EH.unpack(raw)
    if header[0][:7] != b"\x7fELF\x02\x01\x01" or header[2] != 62:
        raise ValueError("not a little-endian x86-64 ELF")
    program_offset, entry_size, count = header[5], header[9], header[10]
    if entry_size != PH.size or not 1 <= count <= 64:
        raise ValueError("unsafe program-header table")
    bases: list[int] = []
    for index in range(count):
        stream.seek(program_offset + index * entry_size)
        row = stream.read(entry_size)
        if len(row) != entry_size:
            raise ValueError("truncated program-header table")
        program = PH.unpack(row)
        if program[0] == 1 and program[6]:
            bases.append(program[3] - program[2])
    if not bases or len(set(bases)) != 1:
        raise ValueError("inconsistent load base")
    return bases[0]


def verify(image: Path, manifest: Path = CANONICAL_MAP) -> dict[str, object]:
    _spec, sites, map_hash = load_canonical_map(manifest)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(image, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        identity = hash_gate.identify_stream(stream, "analysis-elf")
        stream.seek(0)
        snapshot = stream.read(MAX_IMAGE_SIZE + 1)
        if len(snapshot) != identity["size"] or hashlib.sha256(snapshot).hexdigest() != identity["sha256"]:
            raise ValueError("analysis image changed after the identity gate")
        snapshot_stream = io.BytesIO(snapshot)
        base = kernel_base(snapshot_stream)
        results: list[dict[str, str]] = []
        for site, rva, width in sites:
            if "replacement_hex" in site:
                expected = bytes.fromhex(site["replacement_hex"])
            else:
                expected = (base + 0x250BE).to_bytes(width, "little")
            snapshot_stream.seek(rva)
            actual = snapshot_stream.read(width)
            if len(actual) != width:
                raise ValueError(f"site outside image: {site['id']}")
            results.append(
                {
                    "id": site["id"],
                    "name": site["name"],
                    "rva": site["rva"],
                    "group": site["group"],
                    "expected_status": site["expected_status"],
                    "status": "replacement" if actual == expected else "other",
                }
            )
        after = os.fstat(stream.fileno())
        if _file_identity(before) != _file_identity(after):
            raise ValueError("analysis image changed during verification")
    counts = {
        status: sum(result["status"] == status for result in results)
        for status in ("replacement", "other")
    }
    return {
        "schema": "ps4-fw14-kpatch-verification.v1",
        "input_sha256": identity["sha256"],
        "map_sha256": map_hash,
        "read_only": True,
        "counts": counts,
        "matches_expected_statuses": all(
            result["status"] == result["expected_status"] for result in results
        ),
        "sites": results,
        "note": "Statuses compare only with public replacement values; 'other' is not asserted to be stock.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only comparison of the exact FW 14.00 analysis ELF with the canonical public kpatch map."
    )
    parser.add_argument("analysis_elf", type=Path)
    parser.add_argument("--map", type=Path, default=CANONICAL_MAP, help="canonical map path (custom maps are rejected)")
    args = parser.parse_args()
    try:
        result = verify(args.analysis_elf, args.map)
    except (OSError, ValueError, KeyError, struct.error) as error:
        parser.exit(2, f"error: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
