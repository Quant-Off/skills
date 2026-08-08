# binary-crypto-verify

Binary-level verification skill for Claude Code.

Confirms in compiled machine code that security logic survived the compiler:
that secret zeroization was not removed by **dead-store elimination**, and that
constant-time logic did not regain **secret-dependent branches**. Ships a
working Ghidra headless script that inventories the instructions that matter.

## Install

```
/plugin marketplace add Quant-Off/skills
/plugin install binary-crypto-verify@quant-security
```

## Use

Point Claude at a compiled artifact (binary, `.so`/`.a`/`.o`, firmware image),
or invoke directly:

```
/binary-crypto-verify
```

Requires Ghidra (`$GHIDRA_HOME`) and/or `objdump`/`radare2` on the host. The
skill detects what is available and adapts.

## What it does

- Scopes to a target function list rather than the whole binary.
- Runs `scripts/ct_zeroize_report.py` under Ghidra headless to classify every
  instruction into zero-stores, wipe calls, conditional branches, conditional
  moves, variable-latency ops, and register-indexed loads.
- Treats that inventory as a **worklist, not a verdict**: each item must be
  traced to a named secret or recorded as dismissed.
- Requires a configuration sweep (optimization level, LTO, arch, compiler)
  before anything is reported as verified.
- Backs important findings with a differential build, a debugger memory dump,
  ctgrind, or dudect.

## Structure

```
skills/binary-crypto-verify/
├── SKILL.md
├── references/
│   ├── zeroization-survival.md    # per-arch wipe shapes, coverage, differential method
│   ├── constant-time-codegen.md   # branch triage, cmov/csel, secret-indexed loads
│   ├── ghidra-headless.md         # invocations, objdump/r2 equivalents, stripped binaries
│   └── dynamic-validation.md      # dudect, ctgrind, memory dumps, perf counters
└── scripts/
    └── ct_zeroize_report.py       # Ghidra headless post-script (Jython 2.7)
```

## Related

Consumes findings from [`crypto-source-audit`](../crypto-source-audit): audit
the source first, then confirm each guarantee in the machine code here.

License: MIT
