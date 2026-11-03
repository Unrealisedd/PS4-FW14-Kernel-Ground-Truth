# Contributing

Contributions must be original, standard-library-only where applicable, and safe for a public tree. Do not submit firmware material, binary-derived listings, decompiler output, full inventories, private project files, speculative offsets, or generated archives. New facts need a public source classification or a narrowly described local read-only verification method. New observable CLI behavior requires deterministic behavioral tests.

Before submitting, run:

```powershell
python tools/audit_public_tree.py .
python tools/validate_facts.py
python -m unittest discover -s tests -v
```

By contributing original tooling or documentation, you agree it is provided under the MIT License.
