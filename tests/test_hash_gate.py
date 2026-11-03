from __future__ import annotations
import hashlib, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import hash_gate

class HashGateTests(unittest.TestCase):
 def test_recognizes_synthetic_file_when_contract_is_injected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"sample"; p.write_bytes(b"authorized synthetic fixture")
   known=(p.stat().st_size,hashlib.sha256(p.read_bytes()).hexdigest())
   with mock.patch.dict(hash_gate.ARTIFACTS,{"capture":known},clear=True):
    self.assertEqual(hash_gate.identify(p)["kind"],"capture")
 def test_size_mismatch_fails_closed(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"sample"; p.write_bytes(b"wrong")
   with self.assertRaisesRegex(ValueError,"size"): hash_gate.identify(p)
 def test_hash_mismatch_fails_closed_and_does_not_modify(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"sample"; p.write_bytes(b"same-size-wrong"); before=p.read_bytes()
   with mock.patch.dict(hash_gate.ARTIFACTS,{"capture":(len(before),"0"*64)},clear=True):
    with self.assertRaisesRegex(ValueError,"SHA-256"): hash_gate.identify(p)
   self.assertEqual(p.read_bytes(),before)
if __name__=="__main__": unittest.main()
