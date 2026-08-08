# Constant-Time Code Generation

Confirming that branchless source stayed branchless, and that no secret reaches
a branch, an address computation, or a variable-latency instruction.

## The desired shapes

A constant-time select should appear as a conditional move or a masked
arithmetic sequence, with **no conditional jump** between the compare and the
result.

### x86-64, good

```
  cmp   rsi, rdx
  cmovne rax, rcx          ; branchless select
```

```
  neg   rax                ; mask construction
  sbb   rax, rax           ; rax = 0 or -1
  and   rcx, rax
  not   rax
  and   rdx, rax
  or    rcx, rdx           ; masked select, no branch
```

### aarch64, good

```
  cmp   x1, x2
  csel  x0, x3, x4, ne     ; branchless select
```

```
  cmp   x1, x2
  cset  x0, eq             ; 0 or 1 without a branch
  csetm x0, eq             ; 0 or -1 (mask), without a branch
```

### The regression to look for

```
  cmp   al, byte ptr [rsi]
  jne   .Lmismatch          ; <- branch on a secret-derived comparison
```

A `jcc` whose flags were set by an operation on a secret is the finding. The
`cmov` and `csel` forms above are the fix, not the problem, so **do not report
conditional moves as violations**.

## Triage procedure for each branch

The script's branch inventory is unfiltered. For every entry:

1. **Find the flag-setting instruction.** Walk backward from the `jcc`/`b.cond`
   to the nearest `cmp`, `test`, `sub`, `and`, `subs`, or `tst`.
2. **Trace both operands.** Follow each register to its definition. Stop when
   you reach a function argument, a load from a known buffer, a constant, or a
   call return.
3. **Classify the operand source.**

| Operand source | Verdict |
| --- | --- |
| Loop counter, buffer length, capacity, array size | False positive |
| Constant, immediate, compile-time value | False positive |
| Null check on a pointer | False positive |
| Protocol version, message type, public header field | False positive |
| Return code of a prior public operation | False positive |
| Byte loaded from a key, tag, MAC, plaintext, or nonce buffer | **True positive** |
| Bit extracted from a scalar or exponent | **True positive** |
| Result of an arithmetic op on any of the above | **True positive** |
| Cannot determine (indirect, inlined, register reused) | `needs_review`, report as untraced |

Record the verdict and the trace for every item. Silently dropping the
false positives is how real findings get lost in the noise.

## Secret-dependent memory addressing

A load or store whose *address* depends on a secret leaks through the cache,
even when every instruction has fixed latency.

```
  movzx eax, byte ptr [rdi + rcx]   ; rcx from a key byte -> cache side channel
  mov   eax, dword ptr [r8 + rax*4] ; classic AES T-table lookup
```

Triage:

1. Is the index register derived from secret data? Same tracing procedure as
   above.
2. How large is the table? A table spanning many cache lines (64 bytes each) is
   exploitable with Prime+Probe or Flush+Reload. A 16-byte table that always
   occupies one line is far weaker; note it rather than reporting it as High.
3. Is this in a loop over secret data? Repeated access amplifies the signal.

RIP-relative and PC-relative addressing (`[rip + 0x...]`, `adrp`/`add`) computes a
constant address and is a false positive.

## Variable-latency instructions

| Instruction | Architecture | Risk |
| --- | --- | --- |
| `div`, `idiv` | x86-64 | Latency depends on operand magnitude. High when the dividend or divisor is secret. This is the KyberSlash class. |
| `udiv`, `sdiv` | aarch64 | Early-terminating on many cores. Same risk. |
| `divss`, `divsd`, `sqrtsd` | x86-64 SSE | Data-dependent, plus denormal penalties. Secrets must never be in floating point. |
| `mul`, `imul`, `mul`/`umulh` | x86-64, aarch64 | Constant on modern cores; data-dependent on Cortex-M3 and some older or embedded targets. Report scoped to the target. |
| Variable shifts (`shl cl`) | x86-64 | Constant on modern cores. Historically variable. |
| `popcnt`, `lzcnt`, `clz` | Both | Constant on cores that implement them natively. A software fallback loop is not. |

Report format for these must name the affected microarchitecture rather than
asserting a universal leak.

## Comparison routines

Locate the function that compares MACs, tags, or secrets and confirm its shape.

**Correct**: a loop that accumulates with `or`/`xor` and branches exactly once,
after the loop.

```
.Lloop:
  movzx eax, byte ptr [rdi + rcx]
  xor   eax, dword ptr [rsi + rcx]
  or    edx, eax                    ; accumulate, no branch
  inc   rcx
  cmp   rcx, r8
  jb    .Lloop                      ; loop bound is the length: public, fine
  test  edx, edx
  setne al                          ; single branchless verdict
```

**Broken**: a `jne` inside the loop body exits early and leaks the first
mismatch position. That is a Critical finding on any tag-verification path.

Note that the loop-bound branch (`jb .Lloop`) is on the public length and is a
false positive. Only the in-body comparison branch matters.

## Vectorization hazards

Auto-vectorized loops can introduce data-dependent behavior the source never
had:

- Vector compare plus `pmovmskb` plus a branch on the mask is an early-exit that
  the compiler synthesized. Check `memcmp`-shaped loops carefully.
- Scalar prologue and epilogue loops around a vectorized body may have different
  branch structure than the main body.
- Gather instructions (`vpgatherdd`) with secret indices are secret-dependent
  addressing with extra amplification.

## When the property cannot be confirmed

Mark `needs_review` and say so explicitly when:

- The function was inlined and has no distinct body to analyze.
- The relevant register is reused so heavily that the trace is ambiguous.
- An indirect call obscures the callee.
- The binary is stripped and the target could only be located heuristically.

A `needs_review` item is a reported gap, not a pass. The "verified preserved"
list must not contain anything that reached this state.
