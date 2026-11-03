from __future__ import annotations

import csv
import gzip
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import aggregate_private as aggregate


def shard(root: Path, start: int, statuses: list[str]) -> tuple[Path, Path]:
    count = len(statuses)
    stem = f"shard-{start:06d}-{count:06d}"
    metadata = root / f"{stem}.metadata.tsv"
    pseudocode = root / f"{stem}.pseudocode.txt.gz"
    with metadata.open("w", encoding="utf-8", newline="") as stream:
        stream.writelines(aggregate._preamble(start, count))
        writer = csv.DictWriter(stream, fieldnames=aggregate.HEADER, delimiter="\t")
        writer.writeheader()
        for index, status in enumerate(statuses, start):
            writer.writerow(
                {
                    "index": index,
                    "status": status,
                    "address": "SECRET_ADDRESS",
                    "name": "SECRET_NAME",
                    "signature": "SECRET_SIGNATURE",
                    "error": "",
                }
            )
    with gzip.open(pseudocode, "wt", encoding="utf-8", newline="") as stream:
        for index in range(start, start + count):
            stream.write(f"===== {''}FUNCTION {index} =====\nSECRET_PSEUDOCODE\n")
    return metadata, pseudocode


def canonical_shards(root: Path) -> None:
    shard(root, 0, ["ok"] * aggregate.MAX_SHARD_COUNT)
    statuses = ["ok"] * (aggregate.EXPECTED_COUNT - aggregate.MAX_SHARD_COUNT)
    for index in aggregate.EXPECTED_FAILURE_INDICES:
        statuses[index - aggregate.MAX_SHARD_COUNT] = "decompile_failed"
    shard(root, aggregate.MAX_SHARD_COUNT, statuses)


class AggregateTests(unittest.TestCase):
    def test_canonical_coverage_validates_claims_without_calling_them_attested(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical_shards(root)
            result = aggregate.aggregate(root)
            self.assertTrue(result["complete"])
            self.assertTrue(result["matches_observed_automated_coverage"])
            self.assertEqual(result["decompile_failed_indices"], [16134, 16151])
            self.assertEqual(result["producer_claims"]["input_sha256"], aggregate.ANALYSIS_SHA256)
            self.assertEqual(result["producer_claims"]["tool"], "Ghidra 12.1.3")
            self.assertFalse(result["provenance_verified"])
            rendered = str(result)
            for secret in ("SECRET_ADDRESS", "SECRET_NAME", "SECRET_SIGNATURE", "SECRET_PSEUDOCODE"):
                self.assertNotIn(secret, rendered)

    def test_reports_missing_duplicate_and_wrong_status_vector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shard(root, 0, ["ok", "ok"])
            shard(root, 1, ["ok"])
            result = aggregate.aggregate(root)
            self.assertFalse(result["complete"])
            self.assertFalse(result["matches_observed_automated_coverage"])
            self.assertEqual(result["duplicate_indices"], [1])
            self.assertIn(2, result["missing_indices"])

    def test_rejects_noncontiguous_metadata_marker_and_provenance_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata, pseudocode = shard(root, 0, ["ok"])
            metadata.write_text(
                metadata.read_text(encoding="utf-8").replace("0\tok", "1\tok"),
                encoding="utf-8",
                newline="",
            )
            with self.assertRaisesRegex(ValueError, "non-contiguous"):
                aggregate.aggregate(root)

            metadata, pseudocode = shard(root, 0, ["ok"])
            with gzip.open(pseudocode, "wt", encoding="utf-8") as stream:
                stream.write("fixture without marker\n")
            with self.assertRaisesRegex(ValueError, "marker sequence"):
                aggregate.aggregate(root)

            metadata, _pseudocode = shard(root, 0, ["ok"])
            metadata.write_text(
                metadata.read_text(encoding="utf-8").replace(aggregate.ANALYSIS_SHA256, "0" * 64),
                encoding="utf-8",
                newline="",
            )
            with self.assertRaisesRegex(ValueError, "provenance"):
                aggregate.aggregate(root)

    def test_rejects_invalid_status_zero_oversized_orphan_name_and_header(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shard(root, 0, ["manual_fallback"])
            with self.assertRaisesRegex(ValueError, "status"):
                aggregate.aggregate(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "shard-000000-000000.metadata.tsv").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "zero-count"):
                aggregate.aggregate(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "shard-000000-010001.metadata.tsv").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "oversized shard range"):
                aggregate.aggregate(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata, pseudocode = shard(root, 0, ["ok"])
            pseudocode.unlink()
            with self.assertRaisesRegex(ValueError, "orphan"):
                aggregate.aggregate(root)
            metadata.rename(root / "bad-name.tsv")
            with self.assertRaisesRegex(ValueError, "malformed"):
                aggregate.aggregate(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata, _pseudocode = shard(root, 0, ["ok"])
            text = metadata.read_text(encoding="utf-8")
            metadata.write_text(
                text.replace("index\tstatus\taddress\tname\tsignature\terror", "index\tstatus"),
                encoding="utf-8",
                newline="",
            )
            with self.assertRaisesRegex(ValueError, "header"):
                aggregate.aggregate(root)

    def test_summary_write_refuses_overwrite_and_cli_rejects_nested_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "summary.json"
            aggregate.write_summary_no_clobber(output, "{}\n")
            with self.assertRaisesRegex(ValueError, "overwrite"):
                aggregate.write_summary_no_clobber(output, "{}\n")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "summary.json"
            with (
                mock.patch.object(
                    aggregate.os, "link", side_effect=ValueError("publication failed")
                ),
                mock.patch.object(
                    aggregate,
                    "_remove_owned_summary",
                    side_effect=OSError("cleanup failed"),
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError, "publication failed; cleanup failure: cleanup failed"
                ) as raised:
                    aggregate.write_summary_no_clobber(output, "{}\n")
            self.assertIsInstance(raised.exception.__cause__, ValueError)
            self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical_shards(root)
            nested = root / "nested" / "summary.json"
            with mock.patch.object(sys, "argv", ["aggregate_private.py", str(root), "--output", str(nested)]):
                with self.assertRaises(SystemExit) as raised:
                    aggregate.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(nested.exists())


if __name__ == "__main__":
    unittest.main()
