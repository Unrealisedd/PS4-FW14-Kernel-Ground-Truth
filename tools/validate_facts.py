#!/usr/bin/env python3
"""Validate the exact public FW 14.00 fact record without third-party packages."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import verify_kpatch

CAPTURE_SHA256 = "8b2fe4b1c1ef3504cbf871bea31b4fb6d36b83158fcabf58bd89fc2c872ca0a2"
ANALYSIS_SHA256 = "b20a94820aef512490d6167497eb00f9eaa5c780814fe19361b4f00cb7713c3b"
FACT_SCHEMA_SHA256 = "ee73985fd4c27d18f8b84aa1bca00e93ff959fdb66d2c75dd06bf3fb2df2a5dd"
ANCHORS = {
    ("xfast_syscall", "0x1c0", "public_sdk_constant"),
    ("copyout", "0x2bd950", "local_read_only_anchor_check"),
    ("prison0", "0x111fa18", "public_sdk_constant"),
    ("rootvnode", "0x2136e90", "public_sdk_constant"),
}
CAVEATS = [
    "KASLR-relocated live image; not a canonical retail SELF",
    "Capture may contain HEN patches",
]
SYSENT_EVIDENCE = [
    "Al-Azif public 1400.c addresses sysent[11] at RVA 0x1102d80",
    "The table RVA follows from 0x1102d80 - 11 * 0x30",
    "Exact-capture read-only checks found coherent adjacent entries at stride 0x30",
]


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} has unexpected fields")
    return value

def validate_schema(schema: Any) -> None:
    if not isinstance(schema, dict):
        raise ValueError("fact schema must be an object")
    payload = json.dumps(
        schema, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    if hashlib.sha256(payload).hexdigest() != FACT_SCHEMA_SHA256:
        raise ValueError("fact schema diverges from the pinned public contract")


def validate(facts: Any, kpatch: Any) -> None:
    facts = _exact_keys(
        facts,
        {"schema", "firmware", "provenance", "capture_caveats", "tool", "coverage", "anchors", "sysent"},
        "facts",
    )
    if facts["schema"] != "ps4-fw-kernel-ground-truth.v1" or facts["firmware"] != "14.00":
        raise ValueError("unexpected facts schema or firmware")
    provenance = _exact_keys(
        facts["provenance"], {"capture_size", "capture_sha256", "analysis_elf_sha256"}, "provenance"
    )
    if provenance != {
        "capture_size": 44040192,
        "capture_sha256": CAPTURE_SHA256,
        "analysis_elf_sha256": ANALYSIS_SHA256,
    }:
        raise ValueError("unexpected provenance constants")
    if facts["capture_caveats"] != CAVEATS:
        raise ValueError("unexpected capture caveats")
    if facts["tool"] != {"name": "Ghidra", "version": "12.1.3"}:
        raise ValueError("unexpected tool provenance")
    if facts["coverage"] != {
        "functions": 19809,
        "automated_pseudocode": 19808,
        "manual_instruction_exact_fallbacks": 1,
        "manual_instruction_exact_fallback_indices": [16151],
    }:
        raise ValueError("unexpected coverage constants")
    anchors = facts["anchors"]
    if not isinstance(anchors, list) or len(anchors) != 4:
        raise ValueError("exactly four anchors are required")
    tuples = []
    for anchor in anchors:
        anchor = _exact_keys(anchor, {"name", "rva", "evidence"}, "anchor")
        tuples.append((anchor["name"], anchor["rva"], anchor["evidence"]))
    if len(set(tuples)) != 4 or set(tuples) != ANCHORS:
        raise ValueError("anchor tuples must be exact and unique")

    sysent = _exact_keys(
        facts["sysent"],
        {"table_rva", "entry_stride", "syscall_11_entry_rva", "entry_661_rva", "evidence", "provisional_value_correction"},
        "sysent",
    )
    geometry = (
        sysent["table_rva"],
        sysent["entry_stride"],
        sysent["syscall_11_entry_rva"],
        sysent["entry_661_rva"],
    )
    if not all(isinstance(value, str) for value in geometry):
        raise ValueError("sysent geometry fields must be strings")
    if geometry != ("0x1102b70", "0x30", "0x1102d80", "0x110a760"):
        raise ValueError("unexpected sysent table geometry")
    table, stride, entry_11, entry_661 = (int(value, 0) for value in geometry)
    if entry_11 != table + 11 * stride or entry_661 != table + 661 * stride:
        raise ValueError("sysent entry equations do not hold")
    if sysent["evidence"] != SYSENT_EVIDENCE:
        raise ValueError("invalid sysent evidence")
    if sysent["provisional_value_correction"] != (
        "0x110a760 is entry 661 (0x1102b70 + 661 * 0x30), not the table base"
    ):
        raise ValueError("invalid sysent correction")

    if not isinstance(kpatch, dict) or kpatch.get("schema") != "ps4-fw14-kpatch-replacements.v1":
        raise ValueError("unexpected kpatch schema")
    observation = kpatch.get("capture_observation")
    if not isinstance(observation, dict) or observation.get("analysis_elf_sha256") != provenance["analysis_elf_sha256"]:
        raise ValueError("cross-file analysis hash mismatch")
    verify_kpatch.validate_map(kpatch)


def load_and_validate(facts_path: Path, kpatch_path: Path, schema_path: Path) -> None:
    try:
        facts = json.loads(facts_path.read_text(encoding="utf-8"))
        kpatch = json.loads(kpatch_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load fact data: {error}") from error
    validate_schema(schema)
    validate(facts, kpatch)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Validate exact FW 14.00 public fact invariants.")
    parser.add_argument("--facts", type=Path, default=root / "firmware" / "1400.json")
    parser.add_argument("--kpatch", type=Path, default=root / "firmware" / "1400-kpatch.json")
    parser.add_argument("--schema", type=Path, default=root / "firmware" / "1400.schema.json")
    args = parser.parse_args()
    try:
        load_and_validate(args.facts, args.kpatch, args.schema)
    except ValueError as error:
        parser.exit(2, f"error: {error}\n")
    print("firmware facts validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
