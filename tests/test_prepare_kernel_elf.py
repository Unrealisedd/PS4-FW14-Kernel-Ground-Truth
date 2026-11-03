#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import prepare_kernel_elf as kernel_elf


BASE = 0xFFFFFFFFA2200000
SIZE = 0xC000


def write_fixture(directory: Path) -> tuple[Path, Path]:
    capture = directory / "kernel.elf"
    metadata = directory / "kernel.meta.txt"
    image = bytearray(SIZE)
    for offset in range(kernel_elf.PAGE_SIZE, SIZE):
        image[offset] = (offset // kernel_elf.PAGE_SIZE) + 0x30

    ident = bytearray(16)
    ident[:7] = b"\x7fELF\x02\x01\x01"
    header = kernel_elf.ELF_HEADER.pack(
        bytes(ident),
        2,
        62,
        1,
        BASE + 0x100,
        kernel_elf.ELF_HEADER.size,
        0,
        0,
        kernel_elf.ELF_HEADER.size,
        kernel_elf.PROGRAM_HEADER.size,
        3,
        0,
        0,
        0,
    )
    image[: len(header)] = header
    programs = (
        (kernel_elf.PT_LOAD, 5, 0x4000, BASE, BASE, 0x2000, 0x4000, 0x4000),
        (kernel_elf.PT_SCE_RELRO, 4, 0x8000, BASE + 0x4000, BASE + 0x4000, 0x1000, 0x4000, 0x4000),
        (kernel_elf.PT_LOAD, 6, 0xC000, BASE + 0x8000, BASE + 0x8000, 0x2000, 0x4000, 0x4000),
    )
    for index, program in enumerate(programs):
        offset = kernel_elf.ELF_HEADER.size + index * kernel_elf.PROGRAM_HEADER.size
        image[offset : offset + kernel_elf.PROGRAM_HEADER.size] = kernel_elf.PROGRAM_HEADER.pack(*program)
    capture.write_bytes(image)
    metadata.write_text(
        "\n".join(
            (
                f"schema={kernel_elf.SCHEMA}",
                f"firmware={kernel_elf.EXPECTED_FIRMWARE}",
                f"kernel_base=0x{BASE:016x}",
                f"kernel_size={SIZE}",
                f"dumper_commit={kernel_elf.EXPECTED_DUMPER_COMMIT}",
                f"sdk_commit={kernel_elf.EXPECTED_SDK_COMMIT}",
                "",
            )
        ),
        encoding="ascii",
    )
    return capture, metadata


class PrepareKernelElfTests(unittest.TestCase):
    def test_prepare_rewrites_memory_segments_and_records_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, metadata = write_fixture(directory)
            output = directory / "kernel.analysis.elf"
            manifest_path = directory / "kernel.manifest.json"

            manifest = kernel_elf.prepare(capture, metadata, output, manifest_path)

            self.assertEqual(output.stat().st_size, SIZE)
            output_data = output.read_bytes()
            rewritten = []
            for index in range(3):
                offset = kernel_elf.ELF_HEADER.size + index * kernel_elf.PROGRAM_HEADER.size
                rewritten.append(kernel_elf.PROGRAM_HEADER.unpack_from(output_data, offset))
            self.assertEqual([program[0] for program in rewritten], [1, 1, 1])
            self.assertEqual([program[2] for program in rewritten], [0, 0x4000, 0x8000])
            self.assertEqual([program[5] for program in rewritten], [0x4000, 0x4000, 0x4000])
            self.assertEqual(manifest["firmware"], "14.00")
            self.assertEqual(manifest["kernel_size"], SIZE)
            self.assertEqual(manifest["source"]["sha256"], kernel_elf.sha256_file(capture))
            self.assertEqual(manifest["analysis_elf"]["sha256"], kernel_elf.sha256_file(output))
            for segment in manifest["segments"]:
                offset = segment["analysis_file_offset"]
                size = segment["analysis_file_size"]
                self.assertEqual(
                    segment["source_memory_sha256"],
                    kernel_elf.sha256_range(capture, offset, size),
                )
                self.assertEqual(
                    segment["analysis_memory_sha256"],
                    kernel_elf.sha256_range(output, offset, size),
                )
            self.assertEqual(json.loads(manifest_path.read_text(encoding="utf-8")), manifest)

    def test_derives_exact_contract_without_claiming_producer_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _metadata = write_fixture(directory)
            with mock.patch.object(
                kernel_elf.hash_gate,
                "identify_stream",
                return_value={"kind": "capture", "size": SIZE, "sha256": "0" * 64},
            ):
                text = kernel_elf.derive_compatibility_metadata(capture)
            self.assertIn(f"kernel_base=0x{BASE:016x}\n", text)
            self.assertIn(f"kernel_size={SIZE}\n", text)
            target = directory / "derived.meta.txt"
            target.write_text(text, encoding="ascii")
            self.assertEqual(kernel_elf.parse_metadata(target)["firmware"], "14.00")

    def test_prepare_rejects_metadata_size_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, metadata = write_fixture(directory)
            metadata.write_text(
                metadata.read_text(encoding="ascii").replace(
                    f"kernel_size={SIZE}", f"kernel_size={SIZE - 1}"
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(kernel_elf.ValidationError, "does not match metadata"):
                kernel_elf.prepare(
                    capture,
                    metadata,
                    directory / "kernel.analysis.elf",
                    directory / "kernel.manifest.json",
                )

    def test_prepare_rejects_untrusted_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, metadata = write_fixture(directory)
            metadata.write_text(
                metadata.read_text(encoding="ascii").replace("firmware=14.00", "firmware=13.50"),
                encoding="ascii",
            )
            with self.assertRaisesRegex(kernel_elf.ValidationError, "firmware"):
                kernel_elf.prepare(
                    capture,
                    metadata,
                    directory / "kernel.analysis.elf",
                    directory / "kernel.manifest.json",
                )

    def test_prepare_rejects_unknown_metadata_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, metadata = write_fixture(directory)
            with metadata.open("a", encoding="ascii") as stream:
                stream.write("unreviewed=value\n")
            with self.assertRaisesRegex(kernel_elf.ValidationError, "exact contract"):
                kernel_elf.prepare(
                    capture,
                    metadata,
                    directory / "kernel.analysis.elf",
                    directory / "kernel.manifest.json",
                )

    def test_prepare_rejects_non_ascii_and_oversized_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, metadata = write_fixture(directory)
            metadata.write_bytes(b"\xff")
            with self.assertRaisesRegex(kernel_elf.ValidationError, "not ASCII"):
                kernel_elf.prepare(
                    capture,
                    metadata,
                    directory / "kernel.analysis.elf",
                    directory / "kernel.manifest.json",
                )
            metadata.write_bytes(b"A" * (kernel_elf.MAX_METADATA_SIZE + 1))
            with self.assertRaisesRegex(kernel_elf.ValidationError, "size limit"):
                kernel_elf.prepare(
                    capture,
                    metadata,
                    directory / "kernel.analysis.elf",
                    directory / "kernel.manifest.json",
                )

    def test_prepare_rejects_public_repository_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, metadata = write_fixture(directory)
            public_output = kernel_elf.REPOSITORY / "forbidden-analysis.elf"
            with self.assertRaisesRegex(kernel_elf.ValidationError, "outside the public repository"):
                kernel_elf.prepare(
                    capture,
                    metadata,
                    public_output,
                    directory / "kernel.manifest.json",
                )
            self.assertFalse(public_output.exists())

    def test_prepare_rejects_output_manifest_same_absent_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, metadata = write_fixture(directory)
            same_path = directory / "same-output"
            with self.assertRaisesRegex(kernel_elf.ValidationError, "aliases"):
                kernel_elf.prepare(capture, metadata, same_path, same_path)
            self.assertFalse(same_path.exists())


if __name__ == "__main__":
    unittest.main()
