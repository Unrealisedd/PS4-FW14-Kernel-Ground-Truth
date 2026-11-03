from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import audit_public_tree as audit


class AuditTests(unittest.TestCase):
    def test_clean_text_and_fingerprints_pass_content_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "facts.json").write_text(
                '{"sha256":"8b2fe4b1c1ef3504cbf871bea31b4fb6d36b83158fcabf58bd89fc2c872ca0a2"}',
                encoding="utf-8",
            )
            self.assertEqual(audit.audit(root), [])

    def test_clean_opcode_prose_is_not_a_decompiler_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "notes.txt").write_text("Each opcode has a stable meaning.", encoding="utf-8")
            self.assertEqual(audit.audit(root), [])

    def test_root_git_directory_is_skipped_but_nested_git_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / ".git" / "objects").write_text("ignored", encoding="utf-8")
            (root / "nested" / ".git").mkdir(parents=True)
            findings = "\n".join(audit.audit(root))
            self.assertNotIn("objects", findings)
            self.assertIn("nested Git state", findings)

    def test_root_git_file_is_accepted_in_worktree_form(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").write_text("gitdir: ../repository/.git/worktrees/example\n", encoding="ascii")
            (root / "file.txt").write_text("public", encoding="utf-8")
            self.assertEqual(audit.audit(root), [])

    def test_allowlist_rejects_unexpected_markerless_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "public-files.json").write_text(
                json.dumps({"schema": "ps4-fw14-public-files.v1", "files": ["public-files.json"]}),
                encoding="utf-8",
            )
            (root / "renamed.dat").write_text("markerless private material", encoding="utf-8")
            findings = "\n".join(audit.audit(root, enforce_allowlist=True))
            self.assertIn("unexpected public path: renamed.dat", findings)

    def test_allowlist_rejects_noncanonical_paths(self):
        for unsafe in (
            "../escape",
            "./public-files.json",
            "nested\\file.txt",
            "/absolute",
            "C:/absolute",
            "line\nbreak",
        ):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "public-files.json").write_text(
                    json.dumps(
                        {
                            "schema": "ps4-fw14-public-files.v1",
                            "files": ["public-files.json", unsafe],
                        }
                    ),
                    encoding="utf-8",
                )
                findings = "\n".join(audit.audit(root, enforce_allowlist=True))
                self.assertIn("unsafe or non-canonical path", findings)

    def test_detects_private_formats_extensions_magic_nul_and_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "project.gpr").write_text("x", encoding="utf-8")
            (root / "project.rep").write_text("x", encoding="utf-8")
            (root / "symbols.map").write_text("x", encoding="utf-8")
            (root / "kernel.manifest.json").write_text("{}", encoding="utf-8")
            (root / "shard-000000-000001.metadata.tsv").write_text(
                "index\tstatus\taddress\tname\t" + "signature\terror\n", encoding="utf-8"
            )
            (root / "shard-000000-000001.pseudocode.txt").write_bytes(b"===== " + b"FUNCTION 0 =====")
            (root / "hidden.dat").write_bytes(b"\x7fELFmore")
            (root / "nul.txt").write_bytes(b"a\x00b")
            (root / "invalid-utf8.txt").write_bytes(b"\x90\x90\xc3")
            (root / "control.txt").write_bytes(b"a\x01b")
            findings = "\n".join(audit.audit(root))
            self.assertIn("prohibited file type", findings)
            self.assertIn("private artifact name", findings)
            self.assertIn("private/decompiler marker", findings)
            self.assertIn("prohibited binary magic", findings)
            self.assertIn("binary NUL", findings)
            self.assertIn("non-UTF-8 content", findings)
            self.assertIn("text control byte", findings)

    def test_detects_armored_and_long_encoded_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "armor.txt").write_text(
                "-----BEGIN " + "CERTIFICATE-----\n", encoding="ascii"
            )
            (root / "key.txt").write_text(
                "-----BEGIN " + "EC PRIVATE KEY-----\nshort\n", encoding="ascii"
            )
            (root / "base64.txt").write_text("A" * 1024, encoding="ascii")
            (root / "hex.txt").write_text("ab" * 1024, encoding="ascii")
            (root / "pcode.txt").write_text("Pcode" + "Op", encoding="ascii")
            findings = "\n".join(audit.audit(root))
            self.assertIn("armored payload", findings)
            self.assertIn("suspicious encoded payload", findings)
            self.assertIn("private/decompiler marker", findings)

    def test_detects_plaintext_credentials_and_private_virtual_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "secrets.txt").write_text(
                "gh" + "p_" + "A" * 36 + "\n"
                + "AK" + "IA" + "B" * 16 + "\n"
                + "0x" + "ffffffff" + "e1234567\n",
                encoding="ascii",
            )
            synthetic = root / "tests"
            synthetic.mkdir()
            (synthetic / "test_prepare_kernel_elf.py").write_text(
                "0x" + "FFFFFFFF" + "A2200000\n", encoding="ascii"
            )
            (synthetic / "test_verify_kpatch.py").write_text(
                "0x" + "FFFFFFFF" + "90000000\n", encoding="ascii"
            )
            findings = "\n".join(audit.audit(root))
            self.assertIn("plaintext credential token: secrets.txt", findings)
            self.assertIn("private virtual address: secrets.txt", findings)
            self.assertNotIn("private virtual address: tests/", findings)

    def test_rejects_hardlinks_and_preopen_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            alias = root / "alias.txt"
            source.write_text("public", encoding="ascii")
            try:
                os.link(source, alias)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"hard links are unavailable: {error}")
            findings = "\n".join(audit.audit(root))
            self.assertIn("link count changed", findings)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "race.txt"
            replacement = root / "replacement"
            candidate.write_text("clean", encoding="ascii")
            replacement.write_text("other", encoding="ascii")
            real_open = os.open
            swapped = False

            def replace_before_open(path, flags):
                nonlocal swapped
                if not swapped and Path(path) == candidate:
                    os.replace(replacement, candidate)
                    swapped = True
                return real_open(path, flags)

            with mock.patch.object(audit.os, "open", side_effect=replace_before_open):
                findings = "\n".join(audit.audit(root))
            self.assertIn("cannot read race.txt", findings)
            self.assertIn("identity", findings)

    def test_detects_lfs_pointer_and_private_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "private").mkdir()
            (root / "private" / "x.txt").write_text("x", encoding="utf-8")
            (root / "pointer.dat").write_text(
                "version https://git-lfs.github.com/spec/v1\n"
                "oid sha256:" + "0" * 64 + "\nsize 100\n",
                encoding="ascii",
            )
            findings = "\n".join(audit.audit(root))
            self.assertIn("private output path", findings)
            self.assertIn("Git LFS pointer", findings)

    def test_detects_symlink_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("x", encoding="utf-8")
            link = root / "link.txt"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            self.assertIn("symlink/reparse entry", "\n".join(audit.audit(root)))


if __name__ == "__main__":
    unittest.main()
