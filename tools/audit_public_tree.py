#!/usr/bin/env python3
"""Fail closed when a candidate public tree contains unexpected or private artifacts."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path, PurePosixPath
import stat

MAX_SIZE = 2 * 1024 * 1024
READ_LIMIT = MAX_SIZE + 1
MAX_FILES = 128
MAX_TREE_SIZE = 8 * 1024 * 1024
BAD_SUFFIXES = {
    ".elf", ".self", ".pup", ".bin", ".img", ".dump", ".core",
    ".gpr", ".rep", ".gzf", ".idb", ".i64", ".bndb", ".til", ".nam",
    ".map", ".lst", ".asm", ".dis", ".zip", ".7z", ".rar", ".tar",
    ".gz", ".tgz", ".bz2", ".xz", ".zst", ".lz", ".lz4", ".lzh",
    ".cab", ".iso", ".jar", ".war", ".whl", ".apk", ".deb", ".rpm",
    ".cpio", ".ar",
}
BAD_PARTS = {"private", "private-output", "analysis-output", "exports", "__pycache__"}
BAD_NAMES = {
    "kernel.elf", "kernel.analysis.elf", "kernel.bin", "kernel.manifest.json",
    "project.gpr", "project.rep",
}
BAD_NAME_FRAGMENTS = (".metadata.tsv", ".pseudocode.txt.gz")
# Split literals keep this auditor from matching its own source.
MARKERS = (
    b"OMS-" + b"FUNCTION",
    b"===== " + b"FUNCTION",
    b"FUN_" + b"ffffffff",
    b"PCODE" + b"OP",
    b"FUNCTION " + b"index=",
    b"// Decompiled " + b"by",
    b"BEGIN " + b"PSEUDOCODE",
    b"Ghidra " + b"Project File",
    b"oms.ps4-fw14-kernel-elf-" + b"manifest.v1",
    b"ps4-fw14-private-" + b"coverage.v1",
    b"index\tstatus\taddress\tname\tsignature\terror",
)
LFS_PREFIXES = (
    b"version https://git-lfs.github.com/spec/v1\n",
    b"version https://git-lfs.github.com/spec/v1\r\n",
)
ARMOR_MARKERS = (
    b"-----BEGIN " + b"CERTIFICATE-----",
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN " + b"ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN " + b"RSA PRIVATE KEY-----",
    b"-----BEGIN " + b"EC PRIVATE KEY-----",
    b"-----BEGIN " + b"DSA PRIVATE KEY-----",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
    b"-----BEGIN " + b"PGP ",
)
PROHIBITED_MAGICS = (
    b"\x7fELF",
    b"MZ",
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"7z\xbc\xaf\x27\x1c",
    b"SQLite format 3\x00",
    b"%PDF-",
)
LONG_BASE64 = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{1024,}={0,2}(?![A-Za-z0-9+/=])")
LONG_HEX = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2048,}(?![0-9A-Fa-f])")
WRAPPED_BASE64 = re.compile(rb"(?:[A-Za-z0-9+/]{60,76}={0,2}\r?\n){12,}")
GITHUB_TOKEN = re.compile(
    rb"(?<![A-Za-z0-9_])(?:gh" + rb"[pousr]_[A-Za-z0-9]{36,255}|github_" +
    rb"pat_[A-Za-z0-9_]{82,255})(?![A-Za-z0-9_])"
)
AWS_ACCESS_KEY = re.compile(
    rb"(?<![A-Z0-9])(?:" + rb"AK" + rb"IA|" + rb"AS" + rb"IA)[A-Z0-9]{16}(?![A-Z0-9])"
)
PRIVATE_VA = re.compile(
    rb"(?i)(?<![0-9a-f])(?:0x)?f{8}[89a-f][0-9a-f]{7}(?![0-9a-f])"
)
ALLOWED_SYNTHETIC_PRIVATE_VAS = {
    "tests/test_prepare_kernel_elf.py": {
        (b"0xFFFFFFFF" + b"A2200000").lower(),
    },
    "tests/test_verify_kpatch.py": {
        (b"0xFFFFFFFF" + b"90000000").lower(),
    },
}


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)



def _is_reparse(info: os.stat_result) -> bool:
    value = getattr(info, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(value & flag)


def _load_allowlist(root: Path) -> set[str]:
    path = root / "public-files.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read public-files.json: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != "ps4-fw14-public-files.v1":
        raise ValueError("invalid public-files.json schema")
    files = value.get("files")
    if not isinstance(files, list) or not files or any(not isinstance(item, str) for item in files):
        raise ValueError("invalid public file list")
    normalized: set[str] = set()
    for item in files:
        candidate = PurePosixPath(item)
        if (
            not item
            or "\\" in item
            or candidate.is_absolute()
            or candidate.as_posix() != item
            or any(part in {".", ".."} for part in candidate.parts)
            or any(
                ":" in part or any(ord(character) < 0x20 for character in part)
                for part in candidate.parts
            )
        ):
            raise ValueError("public file list contains an unsafe or non-canonical path")
        normalized.add(item)
    if len(normalized) != len(files) or "public-files.json" not in normalized:
        raise ValueError("public file list must be unique and include itself")
    return normalized


def audit(root: Path, enforce_allowlist: bool = False) -> list[str]:
    findings: list[str] = []
    try:
        original_info = root.stat(follow_symlinks=False)
        if root.is_symlink() or _is_reparse(original_info):
            return ["root is a symlink/reparse directory"]
        root = root.resolve(strict=True)
        root_info = root.stat(follow_symlinks=False)
    except OSError as error:
        return [f"cannot stat root: {error}"]
    if not stat.S_ISDIR(root_info.st_mode) or _is_reparse(root_info):
        return ["root is not a regular directory"]

    expected: set[str] | None = None
    if enforce_allowlist:
        try:
            expected = _load_allowlist(root)
        except ValueError as error:
            findings.append(str(error))

    observed: set[str] = set()
    total_files = 0
    total_size = 0

    def visit(directory: Path, relative: Path) -> None:
        nonlocal total_files, total_size
        try:
            directory_before = os.stat(directory, follow_symlinks=False)
        except OSError as error:
            findings.append(f"cannot stat directory {relative.as_posix() or '.'}: {error}")
            return
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            findings.append(f"cannot enumerate {relative.as_posix() or '.'}: {error}")
            return
        for entry in entries:
            rel = relative / entry.name
            rel_text = rel.as_posix()
            try:
                info = os.lstat(entry.path)
            except OSError as error:
                findings.append(f"cannot stat {rel_text}: {error}")
                continue
            if entry.is_symlink() or _is_reparse(info):
                findings.append(f"symlink/reparse entry: {rel_text}")
                continue
            if not relative.parts and entry.name == ".git":
                if stat.S_ISDIR(info.st_mode):
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_size <= 4096:
                    try:
                        gitfile = Path(entry.path).read_text(encoding="ascii")
                    except (OSError, UnicodeError) as error:
                        findings.append(f"invalid root Git file: {error}")
                    else:
                        lines = gitfile.splitlines()
                        if len(lines) != 1 or not lines[0].startswith("gitdir: ") or not lines[0][8:].strip():
                            findings.append("invalid root Git file")
                    continue
                findings.append("invalid root Git state")
                continue
            if entry.name.lower() == ".git":
                findings.append(f"nested Git state or gitlink-like entry: {rel_text}")
                continue
            if stat.S_ISDIR(info.st_mode):
                directory_name = entry.name.lower()
                if directory_name in BAD_PARTS or Path(directory_name).suffix in {".gpr", ".rep"}:
                    findings.append(f"private/non-public directory: {rel_text}")
                visit(Path(entry.path), rel)
                continue
            if not stat.S_ISREG(info.st_mode):
                findings.append(f"non-regular entry: {rel_text}")
                continue
            observed.add(rel_text)
            total_files += 1
            total_size += info.st_size
            if total_files > MAX_FILES:
                findings.append(f"public tree exceeds {MAX_FILES} files")
            if total_size > MAX_TREE_SIZE:
                findings.append(f"public tree exceeds {MAX_TREE_SIZE} bytes")
            low_parts = {part.lower() for part in rel.parts}
            name = entry.name.lower()
            suffix = Path(name).suffix
            if low_parts & BAD_PARTS:
                findings.append(f"private output path: {rel_text}")
            if name in BAD_NAMES or any(name.endswith(fragment) for fragment in BAD_NAME_FRAGMENTS):
                findings.append(f"private artifact name: {rel_text}")
            if suffix in BAD_SUFFIXES:
                findings.append(f"prohibited file type: {rel_text}")
            if info.st_size > MAX_SIZE:
                findings.append(f"oversized unexpected file: {rel_text}")
                continue
            descriptor: int | None = None
            try:
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(entry.path, flags)
                opened_info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened_info.st_mode)
                    or opened_info.st_nlink != 1
                    or info.st_nlink != 1
                    or _file_identity(opened_info) != _file_identity(info)
                ):
                    raise OSError("file identity, type, size, or link count changed during audit")
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = None
                    data = stream.read(READ_LIMIT)
                    final_info = os.fstat(stream.fileno())
                final_path_info = os.lstat(entry.path)
                if (
                    _file_identity(opened_info) != _file_identity(final_info)
                    or _file_identity(final_info) != _file_identity(final_path_info)
                    or final_info.st_nlink != 1
                    or final_path_info.st_nlink != 1
                    or not stat.S_ISREG(final_path_info.st_mode)
                    or _is_reparse(final_path_info)
                ):
                    raise OSError("file identity or content changed during audit")
            except OSError as error:
                findings.append(f"cannot read {rel_text}: {error}")
                continue
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if data.startswith(LFS_PREFIXES):
                findings.append(f"Git LFS pointer: {rel_text}")
            if data.startswith(PROHIBITED_MAGICS):
                findings.append(f"prohibited binary magic: {rel_text}")
            try:
                text = data.decode("utf-8")
            except UnicodeError:
                findings.append(f"non-UTF-8 content: {rel_text}")
                text = ""
            if any(ord(character) < 0x20 and character not in "\t\n\r" for character in text) or "\x7f" in text:
                findings.append(f"text control byte: {rel_text}")
            if b"\x00" in data:
                findings.append(f"binary NUL content: {rel_text}")
            folded = data.lower()
            if any(marker.lower() in folded for marker in MARKERS):
                findings.append(f"private/decompiler marker: {rel_text}")
            if any(marker in data for marker in ARMOR_MARKERS):
                findings.append(f"armored payload: {rel_text}")
            if LONG_BASE64.search(data) or WRAPPED_BASE64.search(data) or LONG_HEX.search(data):
                findings.append(f"suspicious encoded payload: {rel_text}")
            if GITHUB_TOKEN.search(data) or AWS_ACCESS_KEY.search(data):
                findings.append(f"plaintext credential token: {rel_text}")
            allowed_addresses = ALLOWED_SYNTHETIC_PRIVATE_VAS.get(rel_text, set())
            if any(match.group(0).lower() not in allowed_addresses for match in PRIVATE_VA.finditer(data)):
                findings.append(f"private virtual address: {rel_text}")
        try:
            directory_after = os.stat(directory, follow_symlinks=False)
        except OSError as error:
            findings.append(f"cannot re-stat directory {relative.as_posix() or '.'}: {error}")
        else:
            if _directory_identity(directory_before) != _directory_identity(directory_after):
                findings.append(f"directory changed during audit: {relative.as_posix() or '.'}")

    visit(root, Path())
    if expected is not None:
        for item in sorted(observed - expected):
            findings.append(f"unexpected public path: {item}")
        for item in sorted(expected - observed):
            findings.append(f"missing public path: {item}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed audit of the exact public repository tree.")
    parser.add_argument("root", type=Path, nargs="?", default=Path.cwd())
    parser.add_argument("--content-only", action="store_true", help="skip the repository path allowlist (fixture use only)")
    args = parser.parse_args()
    findings = audit(args.root, enforce_allowlist=not args.content_only)
    if findings:
        for item in findings:
            print(f"ERROR: {item}")
        return 2
    print("public-tree audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
