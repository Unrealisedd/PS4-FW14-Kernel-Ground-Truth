#!/usr/bin/env python3
"""Validate an authorized PS4 FW 14.00 live-kernel capture and emit an analysis ELF."""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import stat
import tempfile
from typing import Any
import hash_gate


SCHEMA = "oms.ps4-fw14-kernel-dump.v1"
MANIFEST_SCHEMA = "oms.ps4-fw14-kernel-elf-" + "manifest.v1"
EXPECTED_FIRMWARE = "14.00"
EXPECTED_DUMPER_COMMIT = "42fce7e6f2cf65b25e39a38373ab697593a19f12"
EXPECTED_SDK_COMMIT = "b7326416c23ce14639e9180a24093bdc5eedb579"
PAGE_SIZE = 0x4000
MAX_KERNEL_SIZE = 0x08000000
MAX_METADATA_SIZE = 64 * 1024
MAX_PROGRAM_HEADERS = 64
PT_LOAD = 1
PT_SCE_RELRO = 0x61000010
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
REPOSITORY = Path(__file__).resolve().parents[1]


class ValidationError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)

def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino

def _same_stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_object(left, right)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_nlink == right.st_nlink
    )


def _validated_directory(path: Path) -> os.stat_result:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise ValidationError(f"output parent is not a regular directory: {path}")
    return info


def _validate_parent_generation(path: Path, expected: os.stat_result) -> None:
    current = _validated_directory(path)
    if not _same_object(current, expected):
        raise ValidationError(f"output parent changed while writing: {path}")


def _validate_open_temporary(
    stream: Any, path: Path, parent: Path, parent_identity: os.stat_result
) -> os.stat_result:
    _validate_parent_generation(parent, parent_identity)
    descriptor_info = os.fstat(stream.fileno())
    path_info = os.lstat(path)
    if (
        not stat.S_ISREG(descriptor_info.st_mode)
        or not stat.S_ISREG(path_info.st_mode)
        or _is_reparse(descriptor_info)
        or _is_reparse(path_info)
        or not _same_object(descriptor_info, path_info)
    ):
        raise ValidationError("temporary output is not bound to the validated parent")
    return descriptor_info


def _validate_closed_temporary(
    path: Path, parent: Path, parent_identity: os.stat_result
) -> os.stat_result:
    _validate_parent_generation(parent, parent_identity)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise ValidationError("temporary output changed before commit")
    return info


def _create_private_stage(parent: Path) -> tuple[Path, os.stat_result, os.stat_result]:
    parent_identity = _validated_directory(parent)
    stage = Path(tempfile.mkdtemp(prefix=".fw14-kernel-stage-", dir=parent))
    probe = stage / ".hardlink-probe"
    probe_target = parent / f".{stage.name}.hardlink-probe"
    probe_info: os.stat_result | None = None
    try:
        os.chmod(stage, 0o700)
        stage_identity = _validated_directory(stage)
        _validate_parent_generation(parent, parent_identity)
        with probe.open("xb") as stream:
            probe_info = os.fstat(stream.fileno())
        os.link(probe, probe_target, follow_symlinks=False)
        if not _same_object(probe_info, os.lstat(probe_target)):
            raise ValidationError("output filesystem failed the hard-link identity probe")
        probe_target.unlink()
        probe.unlink()
        _validate_parent_generation(stage, stage_identity)
        _validate_parent_generation(parent, parent_identity)
        return stage, parent_identity, stage_identity
    except BaseException:
        _remove_owned_file(probe_target, probe_info)
        _remove_owned_file(probe, probe_info)
        try:
            stage.rmdir()
        except OSError:
            pass
        raise


def _remove_owned_stage(stage: Path, stage_identity: os.stat_result) -> None:
    try:
        current = os.lstat(stage)
    except FileNotFoundError:
        return
    if _same_object(current, stage_identity) and stat.S_ISDIR(current.st_mode) and not _is_reparse(current):
        stage.rmdir()

def _remove_owned_file(path: Path, identity: os.stat_result | None) -> None:
    if identity is None:
        return
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return
    if _same_object(current, identity) and stat.S_ISREG(current.st_mode) and not _is_reparse(current):
        path.unlink()

def _within(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((os.path.normcase(str(path)), os.path.normcase(str(parent)))) == os.path.normcase(
            str(parent)
        )
    except ValueError:
        return False


def _reject_linked_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            continue
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise ValidationError(f"refusing symlink/reparse path component: {current}")


def _require_private_paths(paths: dict[str, Path]) -> None:
    for label, path in paths.items():
        absolute = Path(os.path.abspath(path))
        _reject_linked_components(absolute)
        if _within(absolute.resolve(strict=False), REPOSITORY):
            raise ValidationError(f"{label} must be outside the public repository")


def path_identity(path: Path) -> str:
    """Return a case-normalized target identity, including for an absent leaf."""
    if os.path.lexists(path) and not path.exists():
        raise ValidationError(f"{path}: dangling symlink or inaccessible path")
    if path.exists():
        return os.path.normcase(os.path.realpath(path))
    return os.path.normcase(str(path.parent.resolve(strict=False) / path.name))


def reject_path_aliases(paths: dict[str, Path]) -> None:
    identities: dict[str, str] = {}
    items = list(paths.items())
    for label, path in items:
        identity = path_identity(path)
        previous = identities.get(identity)
        if previous is not None:
            raise ValidationError(f"{label} aliases {previous}")
        identities[identity] = label
    for index, (left_label, left) in enumerate(items):
        if not left.exists():
            continue
        for right_label, right in items[index + 1 :]:
            if right.exists() and os.path.samefile(left, right):
                raise ValidationError(f"{right_label} aliases {left_label}")


def commit_no_clobber(
    temporary: Path,
    target: Path,
    stage: Path,
    stage_identity: os.stat_result,
    parent_identity: os.stat_result,
) -> os.stat_result:
    """Publish a staged file without replacement in a quiescent trusted parent."""
    source_info = _validate_closed_temporary(temporary, stage, stage_identity)
    _validate_parent_generation(target.parent, parent_identity)
    target_created = False
    try:
        os.link(temporary, target, follow_symlinks=False)
        target_created = True
        target_info = os.lstat(target)
        _validate_parent_generation(stage, stage_identity)
        _validate_parent_generation(target.parent, parent_identity)
        if not _same_object(source_info, target_info):
            raise ValidationError("published output is not the validated staged file")
        temporary.unlink()
        final_info = os.lstat(target)
        if (
            not _same_object(source_info, final_info)
            or not stat.S_ISREG(final_info.st_mode)
            or _is_reparse(final_info)
            or final_info.st_nlink != 1
        ):
            raise ValidationError("published output identity changed during commit")
        return final_info
    except BaseException:
        if target_created:
            try:
                current = os.lstat(target)
                if _same_object(source_info, current):
                    target.unlink()
            except OSError:
                pass
        raise

def sha256_range(path: Path, offset: int, size: int) -> str:
    if offset < 0 or size < 0:
        raise ValidationError("hash range must not be negative")
    digest = hashlib.sha256()
    remaining = size
    with path.open("rb") as stream:
        stream.seek(offset)
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValidationError(
                    f"{path}: hash range {offset:#x}+{size:#x} exceeds the file"
                )
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()

def _read_owned_snapshot(
    path: Path, expected: os.stat_result, maximum_size: int
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        path_before = os.lstat(path)
        if (
            not _same_stable_file(expected, opened)
            or not _same_stable_file(opened, path_before)
            or not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
            or path_before.st_nlink != 1
            or opened.st_size > maximum_size
        ):
            raise ValidationError("published output is not the committed regular file")
        snapshot = stream.read(maximum_size + 1)
        final = os.fstat(stream.fileno())
        path_after = os.lstat(path)
    if (
        len(snapshot) != opened.st_size
        or not _same_stable_file(opened, final)
        or not _same_stable_file(final, path_after)
        or final.st_nlink != 1
    ):
        raise ValidationError("published output changed while hashing")
    return snapshot

def _sha256_buffer_range(data: mmap.mmap, offset: int, size: int) -> str:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValidationError("buffer hash range lies outside the capture")
    digest = hashlib.sha256()
    view = memoryview(data)
    try:
        digest.update(view[offset : offset + size])
    finally:
        view.release()
    return digest.hexdigest()




def parse_metadata(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or _is_reparse(info):
            raise ValidationError("metadata input is not a regular file")
        if info.st_size > MAX_METADATA_SIZE:
            raise ValidationError("metadata input exceeds the size limit")
        raw = stream.read(MAX_METADATA_SIZE + 1)
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise ValidationError("metadata input is not ASCII") from error
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if not raw_line or raw_line.startswith("#"):
            continue
        key, separator, value = raw_line.partition("=")
        if not separator or not key or not value:
            raise ValidationError(f"{path}:{line_number}: malformed metadata line")
        if key in values:
            raise ValidationError(f"{path}:{line_number}: duplicate metadata key {key!r}")
        values[key] = value

    required = {
        "schema": SCHEMA,
        "firmware": EXPECTED_FIRMWARE,
        "dumper_commit": EXPECTED_DUMPER_COMMIT,
        "sdk_commit": EXPECTED_SDK_COMMIT,
    }
    for key, expected in required.items():
        if values.get(key) != expected:
            raise ValidationError(f"metadata {key!r} must be {expected!r}")
    expected_keys = set(required) | {"kernel_base", "kernel_size"}
    if set(values) != expected_keys:
        missing = sorted(expected_keys - set(values))
        unexpected = sorted(set(values) - expected_keys)
        raise ValidationError(
            f"metadata keys must match the exact contract; missing={missing}, unexpected={unexpected}"
        )
    return values

def derive_compatibility_metadata(capture: Path) -> str:
    """Derive the private six-field record for the exact hash-gated capture."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(capture, flags)
    with os.fdopen(descriptor, "rb") as stream:
        capture_info = os.fstat(stream.fileno())
        identity = hash_gate.identify_stream(stream, "capture")
        raw = stream.read(ELF_HEADER.size)
        if len(raw) != ELF_HEADER.size:
            raise ValidationError("capture is too small for metadata derivation")
        header = ELF_HEADER.unpack(raw)
        if header[0][:7] != b"\x7fELF\x02\x01\x01" or header[2] != 62:
            raise ValidationError("capture is not the expected ELF64 image")
        program_offset, entry_size, count = header[5], header[9], header[10]
        if (
            entry_size != PROGRAM_HEADER.size
            or not 1 <= count <= MAX_PROGRAM_HEADERS
            or program_offset < ELF_HEADER.size
            or program_offset + count * entry_size > PAGE_SIZE
        ):
            raise ValidationError("capture has unsafe program-header metadata")
        bases: list[int] = []
        for index in range(count):
            stream.seek(program_offset + index * entry_size)
            row = stream.read(entry_size)
            if len(row) != entry_size:
                raise ValidationError("capture has a truncated program-header table")
            fields = PROGRAM_HEADER.unpack(row)
            if fields[0] in (PT_LOAD, PT_SCE_RELRO) and fields[6]:
                bases.append(fields[3])
        final_identity = hash_gate.identify_stream(stream, "capture")
        if (
            final_identity != identity
            or _identity(capture_info) != _identity(os.fstat(stream.fileno()))
        ):
            raise ValidationError("capture changed while deriving compatibility metadata")
    if not bases:
        raise ValidationError("capture has no loadable segment")
    kernel_base = min(bases)
    if kernel_base >> 48 != 0xFFFF or kernel_base & (PAGE_SIZE - 1):
        raise ValidationError("derived kernel base is invalid")
    return (
        f"schema={SCHEMA}\n"
        f"firmware={EXPECTED_FIRMWARE}\n"
        f"kernel_base=0x{kernel_base:016x}\n"
        f"kernel_size={identity['size']}\n"
        f"dumper_commit={EXPECTED_DUMPER_COMMIT}\n"
        f"sdk_commit={EXPECTED_SDK_COMMIT}\n"
    )


def write_metadata_no_clobber(capture: Path, target: Path) -> None:
    paths = {"capture": capture, "metadata output": target}
    _require_private_paths(paths)
    reject_path_aliases(paths)
    target.parent.mkdir(parents=True, exist_ok=True)
    _reject_linked_components(target.parent)
    stage, parent_identity, stage_identity = _create_private_stage(target.parent)
    temporary_path: Path | None = None
    temporary_identity: os.stat_result | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            dir=stage,
            prefix=f".{target.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary_identity = _validate_open_temporary(
                temporary, temporary_path, stage, stage_identity
            )
            temporary.write(derive_compatibility_metadata(capture))
            temporary.flush()
            os.fsync(temporary.fileno())
        commit_no_clobber(
            temporary_path,
            target,
            stage,
            stage_identity,
            parent_identity,
        )
        temporary_path = None
    finally:
        if temporary_path is not None:
            _remove_owned_file(temporary_path, temporary_identity)
        _remove_owned_stage(stage, stage_identity)


def parse_integer(value: str, key: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise ValidationError(f"metadata {key!r} is not an integer") from error
    if parsed < 0:
        raise ValidationError(f"metadata {key!r} must not be negative")
    return parsed


def is_power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def inspect_capture(data: mmap.mmap, kernel_base: int, expected_size: int) -> dict[str, Any]:
    actual_size = len(data)
    if actual_size != expected_size:
        raise ValidationError(
            f"capture size {actual_size:#x} does not match metadata {expected_size:#x}"
        )
    if actual_size < PAGE_SIZE or actual_size > MAX_KERNEL_SIZE:
        raise ValidationError(f"capture size {actual_size:#x} is outside the safe range")
    if kernel_base >> 48 != 0xFFFF:
        raise ValidationError("kernel base is not a canonical high-half address")
    if kernel_base & (PAGE_SIZE - 1):
        raise ValidationError("kernel base is not page-aligned")
    if actual_size < ELF_HEADER.size:
        raise ValidationError("capture is too small for an ELF64 header")

    header = ELF_HEADER.unpack_from(data, 0)
    ident = header[0]
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1 or ident[6] != 1:
        raise ValidationError("capture is not a little-endian ELF64 image")
    machine = header[2]
    program_offset = header[5]
    header_size = header[8]
    program_entry_size = header[9]
    program_count = header[10]
    section_offset = header[6]
    section_entry_size = header[11]
    section_count = header[12]
    section_name_index = header[13]
    if machine != 62:
        raise ValidationError(f"ELF machine is {machine}, not x86-64")
    if header_size != ELF_HEADER.size or program_entry_size != PROGRAM_HEADER.size:
        raise ValidationError("unexpected ELF or program-header entry size")
    if not 1 <= program_count <= MAX_PROGRAM_HEADERS:
        raise ValidationError(f"unsafe program-header count {program_count}")
    program_table_end = program_offset + program_count * program_entry_size
    if program_offset < ELF_HEADER.size or program_table_end > PAGE_SIZE:
        raise ValidationError("program-header table lies outside the first captured page")

    segments: list[dict[str, int]] = []
    max_end = 0
    saw_base_segment = False
    for index in range(program_count):
        table_offset = program_offset + index * program_entry_size
        fields = PROGRAM_HEADER.unpack_from(data, table_offset)
        segment_type, flags, file_offset, virtual_address, physical_address, file_size, memory_size, alignment = fields
        if segment_type not in (PT_LOAD, PT_SCE_RELRO):
            continue
        if memory_size == 0:
            continue
        if virtual_address < kernel_base:
            raise ValidationError(f"segment {index} starts below the live kernel base")
        relative_offset = virtual_address - kernel_base
        if relative_offset == 0:
            saw_base_segment = True
        effective_alignment = alignment or 1
        if not is_power_of_two(effective_alignment) or effective_alignment > MAX_KERNEL_SIZE:
            raise ValidationError(f"segment {index} has invalid alignment {alignment:#x}")
        if file_size > memory_size:
            raise ValidationError(f"segment {index} has p_filesz larger than p_memsz")
        if memory_size > actual_size or relative_offset > actual_size - memory_size:
            raise ValidationError(f"segment {index} lies outside the captured memory image")
        segment_end = relative_offset + memory_size
        max_end = max(max_end, (segment_end + effective_alignment - 1) & -effective_alignment)
        segments.append(
            {
                "index": index,
                "table_offset": table_offset,
                "original_type": segment_type,
                "flags": flags,
                "original_file_offset": file_offset,
                "virtual_address": virtual_address,
                "physical_address": physical_address,
                "original_file_size": file_size,
                "memory_size": memory_size,
                "alignment": alignment,
                "analysis_type": PT_LOAD,
                "analysis_file_offset": relative_offset,
                "analysis_file_size": memory_size,
            }
        )

    if not segments or not saw_base_segment:
        raise ValidationError("ELF has no non-empty loadable segment at the kernel base")
    if max_end != actual_size:
        raise ValidationError(
            f"program headers describe {max_end:#x} bytes, capture contains {actual_size:#x}"
        )

    if section_offset == 0:
        sections_valid = section_count == 0 and section_name_index == 0
    else:
        sections_valid = (
            section_entry_size == 64
            and section_count > 0
            and section_offset <= actual_size
            and section_count <= (actual_size - section_offset) // section_entry_size
            and (section_name_index == 0 or section_name_index < section_count)
        )
    return {
        "header": header,
        "program_offset": program_offset,
        "program_entry_size": program_entry_size,
        "segments": segments,
        "sections_valid": sections_valid,
    }


def build_analysis_elf(
    data: mmap.mmap, output: Path, inspection: dict[str, Any]
) -> tuple[list[str], os.stat_result]:
    if output.exists() or os.path.lexists(output):
        raise ValidationError("refusing to overwrite analysis output")
    output.parent.mkdir(parents=True, exist_ok=True)
    _reject_linked_components(output.parent)
    stage, parent_identity, stage_identity = _create_private_stage(output.parent)
    transformations: list[str] = []
    temporary_path: Path | None = None
    temporary_identity: os.stat_result | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=stage, prefix=f".{output.name}.", delete=False) as temporary:
            temporary_path = Path(temporary.name)
            temporary_identity = _validate_open_temporary(
                temporary, temporary_path, stage, stage_identity
            )
            view = memoryview(data)
            try:
                for offset in range(0, len(view), 1024 * 1024):
                    temporary.write(view[offset : offset + 1024 * 1024])
            finally:
                view.release()
            for segment in inspection["segments"]:
                temporary.seek(segment["table_offset"])
                temporary.write(
                    PROGRAM_HEADER.pack(
                        segment["analysis_type"],
                        segment["flags"],
                        segment["analysis_file_offset"],
                        segment["virtual_address"],
                        segment["physical_address"],
                        segment["analysis_file_size"],
                        segment["memory_size"],
                        segment["alignment"],
                    )
                )
                if segment["original_type"] == PT_SCE_RELRO:
                    transformations.append(
                        f"program header {segment['index']}: PT_SCE_RELRO -> PT_LOAD"
                    )
                if segment["original_file_offset"] != segment["analysis_file_offset"]:
                    transformations.append(
                        f"program header {segment['index']}: p_offset "
                        f"{segment['original_file_offset']:#x} -> {segment['analysis_file_offset']:#x}"
                    )
                if segment["original_file_size"] != segment["analysis_file_size"]:
                    transformations.append(
                        f"program header {segment['index']}: p_filesz "
                        f"{segment['original_file_size']:#x} -> {segment['analysis_file_size']:#x}"
                    )
            if not inspection["sections_valid"]:
                header = list(inspection["header"])
                header[6] = 0
                header[11] = 0
                header[12] = 0
                header[13] = 0
                temporary.seek(0)
                temporary.write(ELF_HEADER.pack(*header))
                transformations.append("discarded invalid section-header metadata")
            temporary.flush()
            os.fsync(temporary.fileno())
        output_identity = commit_no_clobber(
            temporary_path,
            output,
            stage,
            stage_identity,
            parent_identity,
        )
        temporary_path = None
    finally:
        if temporary_path is not None:
            _remove_owned_file(temporary_path, temporary_identity)
        _remove_owned_stage(stage, stage_identity)
    return transformations, output_identity


def prepare(capture: Path, metadata_path: Path, output: Path, manifest_path: Path) -> dict[str, Any]:
    paths = {
        "capture": capture,
        "metadata": metadata_path,
        "analysis output": output,
        "manifest": manifest_path,
    }
    _require_private_paths(paths)
    reject_path_aliases(paths)
    if output.exists() or os.path.lexists(output) or manifest_path.exists() or os.path.lexists(manifest_path):
        raise ValidationError("refusing to overwrite existing analysis output or manifest")
    metadata = parse_metadata(metadata_path)
    kernel_base = parse_integer(metadata["kernel_base"], "kernel_base")
    kernel_size = parse_integer(metadata["kernel_size"], "kernel_size")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(capture, flags)
    with os.fdopen(descriptor, "rb") as stream:
        capture_info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(capture_info.st_mode)
            or _is_reparse(capture_info)
            or capture_info.st_size < PAGE_SIZE
            or capture_info.st_size > MAX_KERNEL_SIZE
        ):
            raise ValidationError("capture is not a bounded regular kernel image")

        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            inspection = inspect_capture(data, kernel_base, kernel_size)
            transformations, output_identity = build_analysis_elf(data, output, inspection)
            output_owned = True
            manifest_stage: Path | None = None
            manifest_stage_identity: os.stat_result | None = None
            manifest_temporary: Path | None = None
            manifest_temporary_identity: os.stat_result | None = None
            manifest_identity: os.stat_result | None = None
            completed = False
            try:
                source_sha256 = _sha256_buffer_range(data, 0, len(data))
                analysis_snapshot = _read_owned_snapshot(
                    output, output_identity, MAX_KERNEL_SIZE
                )
                analysis_sha256 = hashlib.sha256(analysis_snapshot).hexdigest()
                segment_records: list[dict[str, Any]] = []
                analysis_view = memoryview(analysis_snapshot)
                try:
                    for segment in inspection["segments"]:
                        record = {
                            key: value
                            for key, value in segment.items()
                            if key != "table_offset"
                        }
                        offset = segment["analysis_file_offset"]
                        size = segment["analysis_file_size"]
                        record["source_memory_sha256"] = _sha256_buffer_range(
                            data, offset, size
                        )
                        record["analysis_memory_sha256"] = hashlib.sha256(
                            analysis_view[offset : offset + size]
                        ).hexdigest()
                        segment_records.append(record)
                finally:
                    analysis_view.release()

                if _identity(capture_info) != _identity(os.fstat(stream.fileno())):
                    raise ValidationError("capture changed while preparing the analysis ELF")

                manifest: dict[str, Any] = {
                    "schema": MANIFEST_SCHEMA,
                    "firmware": EXPECTED_FIRMWARE,
                    "kernel_base": f"0x{kernel_base:016x}",
                    "kernel_size": kernel_size,
                    "source": {
                        "file": capture.name,
                        "sha256": source_sha256,
                        "metadata_file": metadata_path.name,
                        "dumper_commit": metadata["dumper_commit"],
                        "sdk_commit": metadata["sdk_commit"],
                    },
                    "analysis_elf": {
                        "file": output.name,
                        "sha256": analysis_sha256,
                        "transformations": transformations,
                    },
                    "segments": segment_records,
                }
                manifest_path.parent.mkdir(parents=True, exist_ok=True)
                _reject_linked_components(manifest_path.parent)
                (
                    manifest_stage,
                    manifest_parent_identity,
                    manifest_stage_identity,
                ) = _create_private_stage(manifest_path.parent)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=manifest_stage,
                    prefix=f".{manifest_path.name}.",
                    delete=False,
                ) as temporary:
                    manifest_temporary = Path(temporary.name)
                    manifest_temporary_identity = _validate_open_temporary(
                        temporary,
                        manifest_temporary,
                        manifest_stage,
                        manifest_stage_identity,
                    )
                    temporary.write(json.dumps(manifest, indent=2) + "\n")
                    temporary.flush()
                    os.fsync(temporary.fileno())
                manifest_identity = commit_no_clobber(
                    manifest_temporary,
                    manifest_path,
                    manifest_stage,
                    manifest_stage_identity,
                    manifest_parent_identity,
                )
                manifest_temporary = None
                _remove_owned_stage(manifest_stage, manifest_stage_identity)
                manifest_stage = None
                completed = True
                output_owned = False
                return manifest
            finally:
                if manifest_temporary is not None:
                    _remove_owned_file(manifest_temporary, manifest_temporary_identity)
                if manifest_stage is not None and manifest_stage_identity is not None:
                    _remove_owned_stage(manifest_stage, manifest_stage_identity)
                if not completed:
                    _remove_owned_file(manifest_path, manifest_identity)
                if output_owned:
                    _remove_owned_file(output, output_identity)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a PS4 FW 14.00 live-kernel capture and emit a debugger-friendly ELF."
    )
    parser.add_argument("capture", type=Path, help="exact kernel.elf written by the console payload")
    parser.add_argument("--metadata", type=Path, help="payload metadata (default: kernel.meta.txt beside capture)")
    parser.add_argument("--output", type=Path, help="analysis ELF (default: kernel.analysis.elf beside capture)")
    parser.add_argument("--manifest", type=Path, help="JSON manifest (default: kernel.manifest.json beside capture)")
    parser.add_argument(
        "--write-metadata",
        type=Path,
        help="derive a private compatibility metadata file for the exact hash-gated capture, then exit",
    )
    args = parser.parse_args()
    if args.write_metadata is not None:
        if args.metadata is not None or args.output is not None or args.manifest is not None:
            parser.error("--write-metadata cannot be combined with preparation output options")
        try:
            write_metadata_no_clobber(args.capture, args.write_metadata)
        except (OSError, UnicodeError, ValueError, struct.error) as error:
            parser.exit(2, f"error: {error}\n")
        print("private compatibility metadata written")
        return 0

    capture = args.capture
    metadata = args.metadata or capture.with_name("kernel.meta.txt")
    output = args.output or capture.with_name("kernel.analysis.elf")
    manifest_path = args.manifest or capture.with_name("kernel.manifest.json")
    if output.exists() or manifest_path.exists():
        parser.exit(2, "error: refusing to overwrite existing analysis output or manifest\n")
    try:
        manifest = prepare(capture, metadata, output, manifest_path)
    except (OSError, UnicodeError, ValueError, struct.error) as error:
        parser.exit(2, f"error: {error}\n")
    print(f"validated capture size: {manifest['kernel_size']:#x}")
    print(f"capture sha256: {manifest['source']['sha256']}")
    print(f"analysis sha256: {manifest['analysis_elf']['sha256']}")
    print("private analysis ELF and manifest written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
