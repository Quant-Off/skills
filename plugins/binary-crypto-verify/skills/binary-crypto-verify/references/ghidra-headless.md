# Ghidra Headless and Alternative Tooling

Exact invocations for producing the instruction inventory, plus the `objdump`
and `radare2` equivalents when Ghidra is unavailable.

## Locating Ghidra

```bash
# Common install locations
ls "$GHIDRA_HOME/support/analyzeHeadless" 2>/dev/null
ls /opt/ghidra/support/analyzeHeadless /usr/share/ghidra/support/analyzeHeadless 2>/dev/null
ls ~/ghidra_*/support/analyzeHeadless 2>/dev/null
command -v analyzeHeadless
```

Export `GHIDRA_HOME` before the commands below. The bundled script lives at
`scripts/ct_zeroize_report.py` inside this skill directory; reference it by
absolute path.

## First run: import and analyze

```bash
"$GHIDRA_HOME/support/analyzeHeadless" \
  /tmp/ghidra-proj cryptoverify \
  -import ./target \
  -scriptPath "${SKILL_DIR}/scripts" \
  -postScript ct_zeroize_report.py \
      --functions crypto_verify,aead_decrypt,derive_key \
      --json /tmp/ct-report.json \
  -deleteProject
```

- `/tmp/ghidra-proj` is the project directory, `cryptoverify` the project name.
- `-deleteProject` discards it afterward. Drop that flag to keep the analysis
  for re-runs.
- Auto-analysis runs before the post-script. On a large binary this dominates
  the wall-clock time; expect minutes, not seconds.

## Re-running without re-importing

Analysis is the expensive step. Keep the project and use `-process`:

```bash
"$GHIDRA_HOME/support/analyzeHeadless" \
  /tmp/ghidra-proj cryptoverify \
  -process target \
  -noanalysis \
  -scriptPath "${SKILL_DIR}/scripts" \
  -postScript ct_zeroize_report.py --all --json /tmp/ct-all.json
```

## Script options

| Option | Effect |
| --- | --- |
| `--functions a,b,c` | Analyze only functions whose names contain these substrings. |
| `--all` | Analyze every function. Overrides `--functions`. |
| `--json <path>` | Write the machine-readable inventory. Use this; the console output truncates long lists at 25 entries per bucket. |
| `--decompile` | Include Ghidra's pseudo-C per function. Slow and verbose, but useful for the initial read. |
| `--max-funcs N` | Safety cap, default 40. The script prints a warning when it truncates. |

With no `--functions` and no `--all`, the script falls back to a name heuristic
matching crypto-sounding identifiers. That heuristic **will miss** functions with
opaque names; prefer an explicit list from the `crypto-source-audit` handoff.

## Reading the output

The script emits six buckets per function:

| Bucket | Meaning | Typical action |
| --- | --- | --- |
| `zero_stores` | Stores that plausibly write zero to memory | Sum the widths against the buffer size |
| `wipe_calls` | Calls to `memset`, `explicit_bzero`, `OPENSSL_cleanse`, and similar | Verify dest, value, and length registers at the call site |
| `branches` | Conditional control flow | Trace each flag-setting operand; most are false positives |
| `cond_moves` | `cmov`, `csel`, and friends | Usually the *desired* lowering. Not findings. |
| `variable_latency` | Division, square root, and similar | Trace the operand; report scoped to the target microarchitecture |
| `indexed_loads` | Memory operands with a register index | Check whether the index derives from a secret |

The "no wipe evidence in this function" note fires when a function has neither
zero-stores nor wipe calls. If the source wipes a secret there, that note is the
lead; confirm it with the differential build described in
`zeroization-survival.md`.

## Stripped binaries

Without symbols, locate targets before running the script.

```bash
# Crypto constants often identify the primitive
rg -a --byte-offset -o $'\x67\xe6\x09\x6a' ./target        # SHA-256 IV, little-endian h0
rg -a --byte-offset -o 'expand 32-byte k' ./target          # ChaCha20 sigma

# Strings and their xrefs are a route into the surrounding code
strings -t x ./target | rg -i 'key|verify|decrypt|handshake'
```

In Ghidra, find the address of a constant or string, take its cross-references,
and note the containing function's entry point. Then pass entry addresses via
`--functions` after Ghidra assigns default names (`FUN_00401140`), or use `--all`
with a raised `--max-funcs` and filter the JSON.

Record in the report that targets were located heuristically. Every finding from
a stripped binary starts at `needs_review` unless a second signal confirms it.

## objdump equivalents

```bash
# Disassemble one function, Intel syntax, no raw bytes
objdump -d -M intel --no-show-raw-insn ./target \
  | awk '/<derive_key>:/{f=1} f{print} f&&/\tret/{exit}'

# Zero-store and wipe-call evidence
objdump -d -M intel ./target | rg -n 'xzr|, *0x0$|bzero|memset|cleanse'

# Conditional branches (worklist, not verdict)
objdump -d -M intel ./target | rg -n '\b(je|jne|jz|jnz|jb|jbe|ja|jae|jl|jle|jg|jge|js|jns)\b'

# Conditional moves (desired shape)
objdump -d -M intel ./target | rg -n '\bcmov|csel|cset'

# Variable-latency instructions
objdump -d -M intel ./target | rg -n '\b(i?div|udiv|sdiv|divss|divsd|sqrt)'
```

For aarch64 the same commands work with the mnemonics `b.eq`, `b.ne`, `cbz`,
`cbnz`, `tbz`, `tbnz` for branches and `csel`, `csinc`, `cset`, `csetm` for
selects.

## radare2 equivalents

```bash
# Analyze, seek to a function, print its disassembly
r2 -q -c 'aaa; s sym.derive_key; pdf' ./target

# List functions matching a pattern
r2 -q -c 'aaa; afl~key' ./target

# Zero-store search across the binary
r2 -q -c 'aaa; /c mov qword [rbp - 0x28], 0' ./target

# Graph a function to inspect exit paths
r2 -q -c 'aaa; s sym.derive_key; agf' ./target
```

## Comparing two builds

The differential is the strongest evidence available. Produce both listings and
diff them directly.

```bash
for opt in O0 O2; do
  cc "-$opt" -c crypto.c -o "/tmp/crypto-$opt.o"
  objdump -d -M intel --no-show-raw-insn "/tmp/crypto-$opt.o" \
    | awk '/<derive_key>:/{f=1} f{print} f&&/\tret/{exit}' > "/tmp/$opt.txt"
done
diff -u /tmp/O0.txt /tmp/O2.txt
rg -c 'mov.*, 0x0|bzero|memset' /tmp/O0.txt /tmp/O2.txt
```

Repeat with `-flto` on the final link rather than the object file, since LTO
eliminates across translation units at link time.

## Configuration sweep template

Record this matrix in every report. A single row is not a verification.

| Compiler | Opt | LTO | Arch | Wipe present | Branches on secret | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| gcc 13 | -O0 | no | x86-64 | yes (4 stores) | none | baseline |
| gcc 13 | -O2 | no | x86-64 | ... | ... | ... |
| gcc 13 | -O2 | yes | x86-64 | ... | ... | ... |
| clang 17 | -O2 | no | x86-64 | ... | ... | ... |
| clang 17 | -O2 | no | aarch64 | ... | ... | ... |

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `NO FUNCTIONS MATCHED` | The name heuristic found nothing. Pass `--functions` or `--all`. |
| Script not found | `-scriptPath` must be the directory, and the `-postScript` argument the bare filename. |
| Zero instructions in a known function | Auto-analysis did not run. Remove `-noanalysis`, or import fresh. |
| Function missing entirely | Inlined into its caller, or a tail-call target. Analyze the caller. |
| Jython syntax errors | Ghidra's Python is Jython 2.7. No f-strings, no `pathlib`. |
| Analysis never finishes | Large or packed binary. Raise the timeout, or scope with `-import` on a single extracted object. |
