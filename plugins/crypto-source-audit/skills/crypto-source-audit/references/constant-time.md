# Constant-Time Execution

A secret must never change *what the machine does* in a way an attacker can
observe. Four classes of violation, each with a triage question and a fix.

## Class 1: Secret-dependent branches

The condition of a branch derives from a secret, so the taken path (and its
timing, and its footprint in the branch predictor and instruction cache) leaks.

```c
// VIOLATION: early exit reveals the index of the first differing byte
for (i = 0; i < n; i++)
    if (mac[i] != expected[i]) return -1;

// VIOLATION: the secret decides how much work happens
if (scalar_bit) point_add(&r, &p);
```

**Triage question:** can the branch condition be computed from public data
alone? A branch on a buffer length, a protocol version, or a loop counter is
fine. A branch on a key byte, a tag byte, a scalar bit, or decrypted plaintext
is a finding.

**Fix:** replace with arithmetic masking or a vetted constant-time select. Both
sides must be evaluated and one result selected without control flow.

```c
// mask is 0x00.. or 0xFF.. computed from the condition without a branch
uint64_t mask = ct_mask_from_bit(scalar_bit);
r.x = (r.x & ~mask) | (candidate.x & mask);
```

Note the ternary trap: `cond ? a : b` is *not* a guarantee of branchless code.
The compiler may emit `cmov`/`csel`, or it may emit a jump. Flag it as
unverified and hand it to `binary-crypto-verify`.

## Class 2: Secret-dependent memory access

The *address* of a load or store derives from a secret. Cache line residency is
observable by a co-resident attacker (Prime+Probe, Flush+Reload), so the secret
leaks even though the timing of any single instruction is fixed.

```c
// VIOLATION: classic AES T-table lookup, key byte selects the cache line
t = Te0[state[0] >> 24];

// VIOLATION: secret-indexed window in scalar multiplication
p = precomputed[window_value];
```

**Triage question:** is the index derived from a secret, and is the table larger
than one cache line (typically 64 bytes)? A lookup into a 16-byte table that
always occupies one line is far weaker, but still note it.

**Fix:** bit-slice the operation, use vector shuffles over a register-resident
table, or scan the whole table and select with a mask. AES-NI or equivalent
hardware instructions remove the problem entirely.

**Reference:** Bernstein, "Cache-timing attacks on AES" (2005);
Osvik, Shamir, Tromer (2006).

## Class 3: Variable-latency instructions

The instruction itself takes a data-dependent number of cycles.

| Operation | Risk | Notes |
| --- | --- | --- |
| `/` and `%` on a secret | High | Integer division latency depends on operand magnitude on most x86 and ARM cores. This is the KyberSlash class. |
| Multiplication on a secret | Medium | Constant on modern x86-64 and aarch64; data-dependent on Cortex-M3, some PowerPC, and older cores. Depends on the target. |
| Variable shift by a secret amount | Medium | Historically variable on some cores; check the target's optimization manual. |
| Floating point on secrets | High | Denormal handling is data-dependent and can be orders of magnitude slower. Never place secrets in floating point. |

**Triage question:** what is the deployment target? A finding here is
microarchitecture-specific. Name the affected cores in the report rather than
asserting a universal leak.

**Fix:** replace division by a constant with a Barrett or Montgomery reduction;
replace `%` with masking when the modulus is a power of two; keep secrets in
integer registers.

## Class 4: Secret-dependent loop bounds and early termination

```c
// VIOLATION: iteration count leaks the bit length of the secret exponent
while (exponent > 0) { ... exponent >>= 1; }
```

The number of iterations leaks the magnitude or bit length of the secret. This
is the Minerva class of ECDSA attack, where nonce bit-length leakage over many
signatures recovers the private key by lattice reduction.

**Fix:** iterate a fixed number of times determined by the type width or the
curve parameters, performing dummy work when the real work is not needed, with
the result selected by mask.

## Big-integer and field arithmetic

Multi-precision routines carry all four classes at once. Check specifically:

- Normalization loops that strip leading zero limbs (leaks magnitude).
- Conditional subtraction after a modular add (must be a masked select).
- Early exit in comparison routines used for range checks on secrets.
- `if (a > b) swap(a, b)` in a GCD or inversion routine.

Prefer a vetted field-arithmetic library over reviewing a hand-rolled one. If it
is hand-rolled, that fact is itself worth reporting.

## What is *not* a violation

Do not report these; noting them as cleared is correct.

- Branches on buffer lengths, message counts, protocol versions, or any value
  the attacker already knows from the wire format.
- Table lookups indexed by public constants or by a loop counter.
- Branches on the *result* of a constant-time comparison, when that result is
  the intended public output (for example, returning "auth failed" after the
  full-length compare has completed).
- Error handling that occurs identically for all failure causes.

## Handoff

Every conclusion in this file is about source intent. Route constant-time
findings, and every ternary or masked select you could not confirm, to the
`binary-crypto-verify` skill for confirmation in the emitted machine code.
