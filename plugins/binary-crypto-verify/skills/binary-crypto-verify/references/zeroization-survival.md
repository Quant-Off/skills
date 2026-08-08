# Zeroization Survival

Confirming that a secret wipe exists in the emitted code, covers the whole
buffer, and dominates every exit path.

## What a surviving wipe looks like

The wipe appears as either inline zero-stores or a call to a barrier-backed
helper. Recognize both per architecture.

### x86-64

| Form | Instructions | Notes |
| --- | --- | --- |
| Immediate store | `mov qword ptr [rbp-0x28], 0` | The clearest evidence. Count them against the buffer size. |
| Vector store | `pxor xmm0, xmm0` then `movups xmmword ptr [rbp-0x40], xmm0` | 16 bytes per store. The zeroing `pxor`/`xorps` must precede it. |
| Register store | `xor eax, eax` then `mov [rdi], rax` | Requires tracing that the register really holds zero. |
| Bulk | `mov rcx, 32` ; `xor eax, eax` ; `rep stosb` | Check `rcx` equals the buffer length and `rdi` points at the buffer. |
| Helper call | `call explicit_bzero` / `call OPENSSL_cleanse` / `call memset@plt` | Confirm `rdi` (dest), `rsi` (value, must be 0), `rdx` (length) at the call site. |

### aarch64

| Form | Instructions | Notes |
| --- | --- | --- |
| Zero register store | `str xzr, [sp, #0x18]` | 8 bytes. `wzr` is the 32-bit form. |
| Paired store | `stp xzr, xzr, [sp, #0x20]` | 16 bytes per instruction; the common inline-wipe shape. |
| Vector store | `movi v0.16b, #0` then `str q0, [sp, #0x30]` | 16 bytes. |
| Helper call | `bl explicit_bzero` | Confirm `x0` (dest), `x1` (value), `x2` (length). |

## Procedure

### Step 1: Count coverage, not presence

One `stp xzr, xzr` wipes 16 bytes. A 32-byte key needs two, or one vector store,
or a helper call with length 32. A single store on a 32-byte secret is a
**partial wipe finding**, not a pass.

Sum the widths of the zero-stores in the function and compare against the secret
buffer size. Record the arithmetic in the report.

### Step 2: Confirm the destination

A zero-store to *some* stack slot is not a wipe of *your* buffer. Establish the
buffer's stack offset (or heap pointer register) from the code that writes the
secret into it, then require the zero-stores to target the same offsets.

```
0x401140  lea  rdi, [rbp-0x40]        ; buffer address
0x401144  call kdf                     ; secret written to [rbp-0x40 .. rbp-0x21]
...
0x401180  mov  qword ptr [rbp-0x40], 0 ; covers bytes 0-7    <- same slot, good
0x401188  mov  qword ptr [rbp-0x38], 0 ; covers bytes 8-15
0x401190  mov  qword ptr [rbp-0x30], 0 ; covers bytes 16-23
0x401198  mov  qword ptr [rbp-0x28], 0 ; covers bytes 24-31  <- full 32 bytes
```

### Step 3: Confirm domination of every exit

The wipe must execute on all paths, including error returns. Walk the control
flow graph from the last read of the secret to every `ret`. A `ret` reachable
without passing through the wipe is a finding scoped to that path.

In Ghidra, the function graph view makes this direct. From the listing, find
every `ret` and check backward reachability.

### Step 4: Check for stack retention beyond the named buffer

Even a correct wipe leaves copies the source never knew about:

- **Register spills.** A large function spills secret-holding registers to stack
  slots the source cannot name. Look for stores of secret-carrying registers to
  slots that are never zeroed.
- **Callee frames.** A helper that received the secret by value has its own
  frame, unwiped after return.
- **Return slots.** A struct returned by value transits a caller-provided buffer
  or registers.
- **Vector registers.** `xmm`/`v` registers holding key material are not cleared
  by a memory wipe. On x86-64, look for a `vzeroall` or explicit clearing; its
  absence is a Medium finding.

## The differential method (strongest evidence)

When you can rebuild, this is definitive and should be preferred over reading a
single listing.

```bash
# Same translation unit, two optimization levels
cc -O0 -c crypto.c -o /tmp/crypto-O0.o
cc -O2 -c crypto.c -o /tmp/crypto-O2.o

# Extract the target function from each and compare wipe evidence
objdump -d --no-show-raw-insn /tmp/crypto-O0.o | sed -n '/<derive_key>:/,/ret/p' > /tmp/O0.txt
objdump -d --no-show-raw-insn /tmp/crypto-O2.o | sed -n '/<derive_key>:/,/ret/p' > /tmp/O2.txt

rg -c 'xzr|, 0x0|bzero|memset' /tmp/O0.txt /tmp/O2.txt
diff /tmp/O0.txt /tmp/O2.txt
```

Wipe instructions present at `-O0` and absent at `-O2` is dead-store elimination,
confirmed. That pair of listings is the evidence to quote in the report.

Repeat with `-flto` enabled, because link-time optimization can eliminate a wipe
that survived per-object compilation. Build the full link and disassemble the
final artifact, not the object file.

## Interpreting a helper call

A `call memset@plt` that survived is **not** automatically safe:

- The compiler may still remove it in a later build, since plain `memset` carries
  no barrier. Recommend `explicit_bzero` regardless.
- Verify the length argument. A `memset(key, 0, sizeof(key))` where `key` decayed
  to a pointer wipes 8 bytes, not the buffer. This is a real and common bug and
  shows up in the listing as a length register holding 8.
- Verify the value argument is zero and not something else.

Conversely, a call to `explicit_bzero`, `OPENSSL_cleanse`, or `sodium_memzero`
that is present with correct arguments is strong evidence of survival. It counts
as one of the two signals required for `confirmed`.

## Common false positives

Do not report these:

- Zero-stores that are struct initialization at function entry rather than a
  wipe at exit. Check the position relative to the secret's live range.
- Frame-pointer or canary setup writing zeros.
- A missing wipe in a function that never held the secret in the first place,
  because it was inlined into the caller. Check the caller before concluding.
- Absent wipe instructions in a function that tail-calls a wiping helper.

## Verdict rules

| Observation | Verdict |
| --- | --- |
| Zero-stores covering the full buffer, dominating all exits | Preserved (one signal) |
| Barrier-backed helper call with correct dest, value, and length | Preserved (one signal) |
| Both of the above, or either plus a clean `-O0`/`-O2` differential | Preserved, `confirmed` |
| Wipe present at `-O0`, absent at the shipped level | Eliminated, `confirmed` finding |
| No wipe evidence, no baseline build available | `needs_review`, never `confirmed` |
| Wipe covers part of the buffer | Partial wipe finding, quote the byte arithmetic |
