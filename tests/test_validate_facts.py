from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import validate_facts

ROOT = Path(__file__).resolve().parents[1]


class ValidateFactsTests(unittest.TestCase):
    def setUp(self):
        self.facts = json.loads((ROOT / "firmware" / "1400.json").read_text(encoding="utf-8"))
        self.kpatch = json.loads((ROOT / "firmware" / "1400-kpatch.json").read_text(encoding="utf-8"))
        self.schema = json.loads((ROOT / "firmware" / "1400.schema.json").read_text(encoding="utf-8"))

    def test_repository_facts_validate(self):
        validate_facts.validate(self.facts, self.kpatch)
        validate_facts.validate_schema(self.schema)

    def test_rejects_duplicate_or_changed_anchor(self):
        duplicate = copy.deepcopy(self.facts)
        duplicate["anchors"][1] = copy.deepcopy(duplicate["anchors"][0])
        with self.assertRaisesRegex(ValueError, "anchor"):
            validate_facts.validate(duplicate, self.kpatch)
        changed = copy.deepcopy(self.facts)
        changed["anchors"][0]["rva"] = "0x1c1"
        with self.assertRaisesRegex(ValueError, "anchor"):
            validate_facts.validate(changed, self.kpatch)

    def test_rejects_sysent_equation_failure(self):
        changed = copy.deepcopy(self.facts)
        changed["sysent"]["entry_661_rva"] = "0x110a761"
        with self.assertRaisesRegex(ValueError, "geometry"):
            validate_facts.validate(changed, self.kpatch)

    def test_rejects_sysent_wrong_type_and_evidence_drift(self):
        wrong_type = copy.deepcopy(self.facts)
        wrong_type["sysent"]["table_rva"] = None
        with self.assertRaisesRegex(ValueError, "must be strings"):
            validate_facts.validate(wrong_type, self.kpatch)
        changed_evidence = copy.deepcopy(self.facts)
        changed_evidence["sysent"]["evidence"][0] = "unrelated claim"
        with self.assertRaisesRegex(ValueError, "evidence"):
            validate_facts.validate(changed_evidence, self.kpatch)

    def test_rejects_coverage_provenance_and_cross_file_hash_changes(self):
        coverage = copy.deepcopy(self.facts)
        coverage["coverage"]["functions"] = 19808
        with self.assertRaisesRegex(ValueError, "coverage"):
            validate_facts.validate(coverage, self.kpatch)
        provenance = copy.deepcopy(self.facts)
        provenance["provenance"]["capture_size"] = 1
        with self.assertRaisesRegex(ValueError, "provenance"):
            validate_facts.validate(provenance, self.kpatch)
        kpatch = copy.deepcopy(self.kpatch)
        kpatch["capture_observation"]["analysis_elf_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "cross-file"):
            validate_facts.validate(self.facts, kpatch)

    def test_rejects_fact_schema_drift(self):
        changed = copy.deepcopy(self.schema)
        changed["title"] = "Changed"
        with self.assertRaisesRegex(ValueError, "pinned public contract"):
            validate_facts.validate_schema(changed)


if __name__ == "__main__":
    unittest.main()
