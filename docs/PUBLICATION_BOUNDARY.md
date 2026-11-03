# Publication Boundary

## Allowed

Original tooling and prose; exact artifact hashes and sizes; aggregate counts and status categories; missing/duplicate function indices; tool provenance; the four reviewed public anchor RVAs in `firmware/1400.json`; the reviewed `sysent` table/entry geometry and public replacement-map RVAs; compact verification guards; synthetic tests.

## Never publish

Firmware/capture bytes; ELF, SELF, or PUP files; archives containing them; Ghidra, IDA, or Binary Ninja projects; bulk strings; instruction listings; full symbol/function inventories; names/signatures harvested from the binary; pseudocode; reconstructed Sony source; private manifests or exporter shards.

Generated pseudocode remains private even when mechanically produced. A complete original-source decompile is technically unrecoverable, and this repository does not claim otherwise. Run `python tools/audit_public_tree.py .` immediately before every proposed publication, on a quiescent checkout that no other process may mutate during the command. The audit binds opened files to their path identities and checks directory generations; it is not a sandbox against a concurrent writer with checkout access.
