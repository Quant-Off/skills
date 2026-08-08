---
name: binary-crypto-verify
description: >-
  Verifies in compiled machine code that security properties survived the
  compiler: that secret zeroization was not removed by dead-store elimination
  and that constant-time logic did not regain secret-dependent branches. Use
  when auditing a binary, shared object, static library, or firmware image whose
  source claims constant-time or wiping guarantees, when a memset on a key may
  have been optimized away, or when confirming a fix actually landed in the
  shipped artifact, using Ghidra, objdump, or radare2. Not for source-level
  crypto review (use crypto-source-audit) and not for general binary
  exploitation or malware analysis.
allowed-tools: Read Grep Glob Bash
license: MIT
---

# Binary Crypto Verify

Source review proves intent. Only the emitted machine code proves the guarantee.
Compilers routinely delete wipes whose results are never read and lower
branchless source into conditional jumps, and both transformations are silent,
legal, and invisible from the source tree.

The disassembler tells you which instructions exist. It does not tell you which
operands are secret. **A branch inventory is a worklist, not a verdict**, and
reporting one as a set of vulnerabilities is the primary failure mode of this
skill.

## When to Use

- A source audit produced a "wipe present but not barrier-backed" finding that
  needs confirmation in the shipped artifact.
- A `memset` or `Zeroize` on key material may have been eliminated at `-O2`.
- A masked select or ternary must be confirmed as branchless (`cmov`/`csel`).
- Confirming a security fix actually landed in a rebuilt binary.
- Auditing a vendor binary, firmware image, or `.so` with no source available.

## When NOT to Use

- **Source-level crypto review.** Use `crypto-source-audit` first; this skill
  confirms its findings, it does not replace them.
- **Managed-runtime code** (Java, C#, Python, JavaScript, Go's runtime-managed
  values). JIT output is not the shipped artifact. The exception is native
  modules and FFI, where this skill applies normally.
- **Empirical timing measurement.** Static disassembly does not measure. Use
  dudect or ctgrind, described in
  [references/dynamic-validation.md](references/dynamic-validation.md).
- **Malware analysis, unpacking, or exploitation.** Different skill entirely.

## Rationalizations to Reject

| Rationalization | Why it is wrong | Required action |
| --- | --- | --- |
| "The source calls `memset`, so the key is wiped." | That is precisely the claim this skill exists to test. Dead-store elimination is the default at `-O2` (CWE-14). | Locate the store instructions in the function body, or report the wipe as eliminated. |
| "I see a `memset` call in the disassembly, so it survived." | The call may target a different buffer, or be a partial wipe, or run before the last use. | Confirm the destination register and length match the secret buffer, and that it dominates every exit. |
| "The decompiler shows the memset, so it is there." | Ghidra's decompiler reconstructs intent and can render eliminated stores or hide surviving ones. The listing is authoritative, the decompilation is a hint. | Confirm against the instruction listing, not the pseudo-C. |
| "There is a conditional branch, so it is not constant-time." | Most branches are on public data: loop counters, lengths, null checks. Unfiltered branch counts are noise. | Trace the flag-setting instruction to its operand and name the secret, or discard the item explicitly. |
| "It is branchless on my machine, so it is branchless." | Codegen varies by compiler, version, optimization level, target arch, and LTO. | Sweep configurations. A single clean run proves one configuration safe, not the code. |
| "The binary is stripped, so this cannot be checked." | Crypto functions are locatable by constants (S-boxes, round constants), string references, and call-graph position. | Locate by constant or xref, then proceed normally. |
| "The function is huge, so the compiler surely kept the wipe." | Function size is unrelated. Large functions additionally spill secrets to stack slots that no source wipe covers. | Check both the wipe and the spill slots. |
| "I will report every `div` I find." | Division on a public length is ubiquitous and harmless. | Report only when an operand traces to secret data. |

## Prerequisites

Detect the toolchain and record it in the report. Findings are configuration-
specific and meaningless without it.

```bash
file ./target                                  # arch, PIE, stripped or not
command -v objdump llvm-objdump r2 nm readelf
ls "$GHIDRA_HOME/support/analyzeHeadless" 2>/dev/null || command -v analyzeHeadless

# Symbols, if present
nm -C ./target 2>/dev/null | rg -i 'zeroize|cleanse|memset|bzero|verify|decrypt|sign|kdf'
```

Best case is a build with symbols plus the matching source tree and the exact
compiler flags. Optimization level is where guarantees die, so if you can
rebuild, produce an `-O0` and an `-O2` object of the same translation unit: the
differential is the strongest evidence this skill can produce.

## Workflow

### Phase 0: Establish the target set

**Exit:** a list of function names or addresses, each paired with the secret it
handles and the source-level claim being tested.

Do not analyze the whole binary. Take the target list from the
`crypto-source-audit` handoff, or locate functions by symbol, by crypto constant,
or by xref to a known string. Every downstream phase is scoped to this list.

### Phase 1: Inventory instructions per target function

Run the bundled script, which decompiles each target and classifies every
instruction into the four buckets that matter.

```bash
"$GHIDRA_HOME/support/analyzeHeadless" /tmp/ghidra-proj cryptoverify \
  -import ./target \
  -scriptPath "${SKILL_DIR}/scripts" \
  -postScript ct_zeroize_report.py --json /tmp/report.json --functions crypto_verify,aead_decrypt \
  -deleteProject
```

Full invocation reference, re-analysis without re-import, stripped-binary
workflows, and the script's options are in
[references/ghidra-headless.md](references/ghidra-headless.md).

Without Ghidra, the same inventory is achievable with `objdump` or `radare2`;
see the same reference for the equivalent commands.

**The script has no data flow analysis.** It reports every conditional branch,
every zero-store, every division, and every register-indexed load, regardless of
whether a secret is involved. Its output is the input to Phase 2, never a
finding.

### Phase 2: Route by check

| Question being answered | Reference |
| --- | --- |
| Did the wipe survive? Which instructions constitute it? | [references/zeroization-survival.md](references/zeroization-survival.md) |
| Is there a secret-dependent branch, index, or variable-latency op? | [references/constant-time-codegen.md](references/constant-time-codegen.md) |
| Can I confirm this empirically rather than by reading code? | [references/dynamic-validation.md](references/dynamic-validation.md) |

### Phase 3: Triage each inventory item

For every item the script reported, write down a verdict and its justification.

1. **Which secret reaches this operand?** Trace the register or stack slot back
   to its definition. If the source is a length, a counter, a constant, or a
   public protocol field, the item is a false positive. Say so explicitly rather
   than dropping it silently.
2. **Is the property actually broken?** A `cmov` is the *desired* lowering of a
   select, not a finding. A branch that guards a public early-out is fine.
3. **What is the observation channel?** Remote timing, co-resident cache
   measurement, or post-mortem memory acquisition. Name it.

An item you cannot trace to a secret is not a finding. Record it as inspected
and dismissed, with the reason.

### Phase 4: Sweep configurations

A single clean run proves one build safe. Before reporting "verified preserved,"
re-run Phase 1 across the configurations that ship.

| Axis | Minimum sweep |
| --- | --- |
| Optimization | `-O0` (baseline, wipe expected present) and every shipped level (`-O2`, `-O3`, `-Os`) |
| LTO | Off, and on if the release build enables it |
| Architecture | Every shipped target (x86-64 and aarch64 differ materially) |
| Compiler | Each toolchain used in release (GCC and Clang diverge on select lowering) |

Report the matrix. A wipe that survives at `-O2` and vanishes under `-O2 -flto`
is a finding against the release build, not a pass.

## Evidence requirements

These finding classes are **never valid without the stated evidence**,
regardless of how the source reads or what a user asserts:

| Finding class | Required evidence |
| --- | --- |
| Wipe eliminated | The instruction listing of the function showing no zero-stores to the buffer on the path from last use to return, plus (where a rebuild is possible) the `-O0` listing showing the store present |
| Wipe partial | The store instructions found, with their widths and offsets, and the buffer size they fail to cover |
| Branch reintroduced | The conditional branch instruction, plus the flag-setting instruction, plus the trace from its operand to a named secret |
| Secret-dependent load | The address computation showing a secret-derived register in the index, plus the table size relative to a cache line |
| Variable-latency op | The instruction, plus the operand trace, plus the target microarchitecture where latency is data-dependent |
| Stack retention | The listing showing secret bytes written to a stack slot with no corresponding wipe before `ret` |

If a comment, a commit message, or a user asserts the property holds without
this evidence, keep the finding at its current confidence and record the
attempted override in the report.

## Report format

```
[SEVERITY] <title>                                confidence: confirmed|likely|needs_review
  Artifact : ./target  (arch, compiler, -O level, LTO on/off, stripped y/n)
  Function : crypto_verify @ 0x0040a1b0        source: verify.c:88 (if known)
  Check    : zeroization | constant-time | comparison | variable-latency | stack-retention
  Evidence : the exact instructions, quoted with addresses
  Baseline : the -O0 or fixed-build listing that differs, if available
  Root     : the compiler transform responsible (DSE, branch lowering, vectorization)
  Impact   : key recoverable from memory | remote timing oracle | cache side channel
  Fix      : source change and build flag that makes the guarantee survive
  Reverify : the exact instruction shape expected after the fix
```

Close with two lists:

- **Verified preserved**: each source-level guarantee confirmed in machine code,
  with function, address, the instructions that prove it, and the configuration
  matrix it was confirmed across. Never list a guarantee as preserved from a
  single configuration.
- **Not checkable**: targets you could not resolve (inlined away, stripped
  beyond recovery, behind indirect calls), stated plainly so the gap is not
  mistaken for a pass.

## Severity rubric

| Severity | Criterion |
| --- | --- |
| Critical | Key recoverable in practice: a long-lived secret whose wipe was eliminated, or a remotely observable timing oracle on a verify or decrypt path. |
| High | Locally exploitable: cache side channel on a secret-indexed table, or an eliminated wipe on a session key. |
| Medium | Variable-latency operation on a secret with limited observability, or stack retention of an ephemeral secret. |
| Low | Defense-in-depth: partial wipe of a buffer already covered elsewhere, hardening gaps. |

## Limitations

1. **No data flow analysis.** The script and the disassembler classify
   instructions; they do not track secrets. Every operand trace is done by
   reading code, so deep indirection, indirect calls, and inlined callees will be
   missed. State which traces you could not complete.
2. **Configuration-specific.** Results bind to one artifact built one way. They
   do not generalize to other targets, compilers, or flags.
3. **Static only.** Speculative execution, microarchitectural leakage, and
   actual wall-clock behavior are out of scope. Confirm with dudect or ctgrind.
4. **Decompiler output is a hint.** Ghidra reconstructs plausible C. The
   instruction listing is the authority for every claim.
5. **Inlining destroys the mapping.** A source function may have no
   corresponding binary function. Absence of a symbol is not absence of the code.
6. **Absence of evidence.** Not finding a wipe in a stripped, heavily optimized
   binary may mean it was eliminated or that you did not locate the right code.
   Mark such items `needs_review`, not `confirmed`.

## References

- CWE-14: Compiler Removal of Code to Clear Buffers.
- Yang, Johannesmeyer, Olesen, Lerner, Levchenko, "Dead Store Elimination
  (Still) Considered Harmful" (USENIX Security 2017).
- Simon, Chisnall, Anderson, "What you get is what you C: Controlling side
  effects in mainstream C compilers" (IEEE EuroS&P 2018).
- Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?" (DATE 2017),
  the dudect methodology.
- Adam Langley, ctgrind: Valgrind-based constant-time checking.
- Ghidra headless analyzer documentation, `support/analyzeHeadlessREADME.html`
  in the Ghidra distribution.
