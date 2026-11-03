from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import verify_kpatch


REAL_MAP = Path(__file__).resolve().parents[1] / "firmware" / "1400-kpatch.json"


class KpatchVerifierTests(unittest.TestCase):
    def load_map(self):
        return json.loads(REAL_MAP.read_text(encoding="utf-8"))

    def test_real_map_has_exact_unique_groups_and_status_vector(self):
        spec = self.load_map()
        sites = verify_kpatch.validate_map(spec)
        self.assertEqual(len(sites), 39)
        self.assertEqual(len({site[0]["id"] for site in sites}), 39)
        self.assertEqual(len({site[0]["name"] for site in sites}), 39)
        self.assertEqual(sum(site[0]["group"] == "do_patch" for site in sites), 27)
        self.assertEqual(sum(site[0]["group"] == "optional_aio" for site in sites), 12)
        self.assertEqual(sum(site[0]["expected_status"] == "replacement" for site in sites), 37)
        self.assertEqual(sum(site[0]["expected_status"] == "other" for site in sites), 2)

    def test_rejects_empty_and_duplicate_sites(self):
        empty = self.load_map()
        empty["sites"] = []
        with self.assertRaisesRegex(ValueError, "exactly 39"):
            verify_kpatch.validate_map(empty)
        duplicate = self.load_map()
        duplicate["sites"][1]["id"] = duplicate["sites"][0]["id"]
        with self.assertRaisesRegex(ValueError, "IDs"):
            verify_kpatch.validate_map(duplicate)

    def test_rejects_empty_hex_and_bad_dynamic(self):
        empty_hex = self.load_map()
        empty_hex["sites"][0]["replacement_hex"] = ""
        with self.assertRaisesRegex(ValueError, "nonempty"):
            verify_kpatch.validate_map(empty_hex)
        bad_dynamic = self.load_map()
        dynamic = next(site for site in bad_dynamic["sites"] if "replacement_dynamic" in site)
        dynamic["replacement_dynamic"]["width"] = 4
        with self.assertRaisesRegex(ValueError, "dynamic"):
            verify_kpatch.validate_map(bad_dynamic)

    def test_rejects_structurally_valid_source_divergence(self):
        changed = self.load_map()
        changed["sites"][0]["name"] = "changed_but_unique_name"
        with self.assertRaisesRegex(ValueError, "pinned public-source transcription"):
            verify_kpatch.validate_map(changed)

    def test_rejects_noncanonical_map_path(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "map.json"
            copied.write_bytes(REAL_MAP.read_bytes())
            with self.assertRaisesRegex(ValueError, "custom patch maps"):
                verify_kpatch.load_canonical_map(copied)

    def test_synthetic_read_only_comparison_does_not_disclose_bytes(self):
        spec = self.load_map()
        sites = verify_kpatch.validate_map(spec)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "analysis"
            base = 0xFFFFFFFF90000000
            with image.open("w+b") as stream:
                stream.truncate(verify_kpatch.MAX_IMAGE_SIZE)
                ident = bytearray(16)
                ident[:7] = b"\x7fELF\x02\x01\x01"
                stream.seek(0)
                stream.write(verify_kpatch.EH.pack(bytes(ident), 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0))
                stream.write(verify_kpatch.PH.pack(1, 5, 0, base, 0, verify_kpatch.MAX_IMAGE_SIZE, verify_kpatch.MAX_IMAGE_SIZE, 0x4000))
                for site, rva, width in sites:
                    expected = (
                        bytes.fromhex(site["replacement_hex"])
                        if "replacement_hex" in site
                        else (base + 0x250BE).to_bytes(width, "little")
                    )
                    stream.seek(rva)
                    stream.write(expected)
            before = image.stat()
            image_sha256 = hashlib.sha256(image.read_bytes()).hexdigest()
            with mock.patch.object(
                verify_kpatch.hash_gate,
                "identify_stream",
                return_value={"sha256": image_sha256, "size": verify_kpatch.MAX_IMAGE_SIZE},
            ):
                result = verify_kpatch.verify(image)
            after = image.stat()
            self.assertEqual((before.st_size, before.st_mtime_ns), (after.st_size, after.st_mtime_ns))
            self.assertNotIn("actual", json.dumps(result))
            self.assertEqual(result["counts"]["replacement"], 39)


if __name__ == "__main__":
    unittest.main()
