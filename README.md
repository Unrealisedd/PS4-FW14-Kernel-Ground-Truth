# PS4 FW 14.00 Kernel Ground Truth

This repository publishes clean-room-safe tooling and verified facts for owners who independently possess the exact PS4 firmware 14.00 live-kernel capture. It contains **no firmware bytes, Sony source, decompiler database, instruction dump, or pseudocode**. Generated pseudocode remains private.

A complete original-source decompile is technically unrecoverable: optimized machine code does not preserve the original source, identifiers, comments, types, or build structure. This project instead makes a specific function-level Ghidra analysis reproducible and reports bounded, verifiable metadata.

## Verified ground truth

- Exact private Ghidra 12.1.3 analysis: 19,809 functions; automated pseudocode for 19,807; instruction-exact private fallbacks at sorted indices 16,134 and 16,151.
- Reviewed RVAs: `xfast_syscall=0x1c0`, `copyout=0x2bd950`, `prison0=0x111fa18`, `rootvnode=0x2136e90`.
- Corrected `sysent` geometry: table `0x1102b70`, stride `0x30`, syscall 11 entry `0x1102d80`; provisional `0x110a760` is entry 661.
- The exact post-HEN capture matches 37 of 39 public FW 14.00 replacement fields. The two differences are syscall 11's argument-count and call fields; this does not establish clean stock bytes.

Machine-readable evidence lives in [`firmware/1400.json`](firmware/1400.json) and the pinned public-source replacement map in [`firmware/1400-kpatch.json`](firmware/1400-kpatch.json). Every fact is scoped to the exact hashes below; do not generalize the post-HEN observation to a clean retail image.

## Requirements

- Python 3.10+ (standard library only)
- Ghidra 12.1.3
- The owner-supplied capture: 44,040,192 bytes, SHA-256 `8b2fe4b1c1ef3504cbf871bea31b4fb6d36b83158fcabf58bd89fc2c872ca0a2`
- A private `kernel.meta.txt` compatibility record, either retained from the dumper payload or deterministically derived from the exact hash-gated capture

## Reproduce privately

Run from the repository root; keep every input/output under `C:\private\ps4-fw14`, outside this tree. The complete private work area—including captures, metadata, output parents, exporter directories, and tool-created staging children—MUST be trusted, owner-controlled, and quiescent for each command. No other process may create, replace, rename, hard-link, mutate, or delete any participating path or child while a command runs. The preparer and exporter reject linked/reparse paths, preflight same-volume hard-link support, and fail closed on observed identity drift, but cross-platform pathname link/unlink operations are not a sandbox against a writer that already controls the trusted directory. Run the public-tree audit only on a likewise quiescent checkout.

```powershell
python tools/hash_gate.py C:\private\ps4-fw14\kernel.elf --expect capture
python tools/prepare_kernel_elf.py C:\private\ps4-fw14\kernel.elf --write-metadata C:\private\ps4-fw14\kernel.meta.txt
python tools/prepare_kernel_elf.py C:\private\ps4-fw14\kernel.elf --metadata C:\private\ps4-fw14\kernel.meta.txt --output C:\private\ps4-fw14\kernel.analysis.elf --manifest C:\private\ps4-fw14\kernel.manifest.json
python tools/hash_gate.py C:\private\ps4-fw14\kernel.analysis.elf --expect analysis-elf
python tools/verify_kpatch.py C:\private\ps4-fw14\kernel.analysis.elf
```
`--write-metadata` records the load base already present in the exact capture's ELF headers. It is deterministic compatibility input, not independent evidence that a named dumper payload produced the capture.

Import `kernel.analysis.elf` into a new private Ghidra 12.1.3 project as x86:LE:64, accept analysis defaults, and let auto-analysis finish. Add `ghidra_scripts` as a Script Manager directory. The Program must retain Ghidra's exact executable SHA-256 metadata and exactly 19,809 discovered functions. Run `ExportPrivatePseudocode.java` repeatedly with four arguments: an external output directory, start index, count, and timeout seconds. The output directory must be a real, non-symlinked path outside both this repository and the Ghidra project:

```text
C:\private\ps4-fw14\exports 0 1000 600
C:\private\ps4-fw14\exports 1000 1000 600
```

Cover indices 0 through 19,808 (use a final count of 809). Use the canonical 600-second per-function timeout shown above; shorter values can add timeout-only failures and will not match the validated status vector. Then aggregate **inside the private area**:

```powershell
python tools/aggregate_private.py C:\private\ps4-fw14\exports --output C:\private\ps4-fw14\coverage.json
python tools/validate_facts.py
python tools/audit_public_tree.py .
```

The aggregate contains counts, coverage gaps, statuses, hashes, and provenance only. Review [the methodology](docs/METHODOLOGY.md) and [publication boundary](docs/PUBLICATION_BOUNDARY.md) before publishing any result.

## License and source attribution

Original tooling and prose are MIT-licensed. Public SDK constants and patch facts are attributed to their pinned upstream revisions in [the methodology](docs/METHODOLOGY.md); no upstream implementation code or proprietary firmware material is relicensed here.
