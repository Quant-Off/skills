# Dynamic Validation

Static disassembly finds most regressions and proves none of them empirically.
Back the important findings with a measurement. Dynamic results are the second
signal that promotes a finding from `likely` to `confirmed`.

## Choosing a method

| Question | Method |
| --- | --- |
| Is execution time independent of the secret? | dudect (statistical) |
| Does any branch or memory index depend on a secret? | ctgrind or Valgrind with tainting |
| Is the key actually gone from memory after the wipe? | Debugger memory dump |
| Does the property hold under the real workload? | Perf counters on the deployed path |

## dudect: statistical timing test

Tests the null hypothesis that timing distributions are identical for two input
classes (fixed secret versus random secret). It requires no source annotation
and works on any callable, which makes it the right first choice.

The harness measures one function under two input classes and applies Welch's
t-test to the timing distributions:

```c
#include "dudect.h"

// Class 0: fixed secret. Class 1: random secret. Same public inputs.
static void prepare_inputs(dudect_config_t *c, uint8_t *input_data,
                           uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0)
            memset(input_data + i * c->chunk_size, 0x00, c->chunk_size);
        else
            randombytes(input_data + i * c->chunk_size, c->chunk_size);
    }
}

static uint8_t do_one_computation(uint8_t *data) {
    return crypto_verify(data, expected_tag);   // the function under test
}
```

Interpretation:

- `t < 10`: no leakage detected at this sample count. This is **not** proof of
  constant-time behavior; it is failure to detect leakage.
- `t > 10`: leakage detected. Treat as a confirmed timing dependence.
- Let it run. A weak leak may need tens of millions of measurements to cross the
  threshold.

Run it pinned to one core, with frequency scaling and turbo disabled, otherwise
the noise floor swamps the signal:

```bash
sudo cpupower frequency-set -g performance
taskset -c 2 ./dudect-harness
```

**Reference:** Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?"
(DATE 2017).

## ctgrind: taint-based checking

Marks secret buffers as uninitialized in Valgrind's memcheck, which then reports
any branch or memory index that depends on them. This finds the *cause* rather
than the symptom, so it pairs well with dudect's black-box result.

```c
#include <valgrind/memcheck.h>

VALGRIND_MAKE_MEM_UNDEFINED(key, sizeof key);   // mark as secret
crypto_operation(key, msg, out);
VALGRIND_MAKE_MEM_DEFINED(out, out_len);        // the intended public output
```

```bash
valgrind --tool=memcheck --track-origins=yes ./harness
```

Every "Conditional jump or move depends on uninitialised value" report is a
secret-dependent branch, with a stack trace pointing at the source line. Every
"Use of uninitialised value of size N" in an address computation is
secret-dependent addressing.

Caveats: this instruments the compiled binary, so it tests the shipped codegen,
but Valgrind's synthetic CPU does not model real cache behavior. It detects the
dependence, not the exploitability.

## Confirming a wipe actually cleared memory

The definitive test for zeroization. Break after the wipe, dump the region, and
check it is zero.

```bash
gdb ./target
(gdb) break derive_key
(gdb) run
(gdb) print &key                  # note the address, e.g. 0x7fffffffe240
(gdb) finish                      # run to the end of the function, past the wipe
(gdb) x/32xb 0x7fffffffe240       # dump the buffer's former location
```

All-zero bytes means the wipe reached memory. Residual key bytes means it did
not, and the dump is the evidence to quote.

For heap secrets, break after `free` and inspect the freed chunk. For a
whole-process view, dump core and search it:

```bash
gcore $(pgrep target)
rg -a --byte-offset -o "$(python3 -c 'print("\\x41"*32)')" core.*   # known test key
```

Use a known test key pattern rather than a real one, and treat the core file as
sensitive material: wipe it after the test.

## Cache side-channel confirmation

For a suspected secret-indexed table lookup, measure rather than argue. A
Flush+Reload harness on the specific table is the standard approach, but the
cheaper first check is a perf counter comparison across input classes:

```bash
perf stat -e cache-misses,L1-dcache-load-misses -r 100 ./harness fixed-key
perf stat -e cache-misses,L1-dcache-load-misses -r 100 ./harness random-key
```

A consistent difference in miss counts between classes supports the finding.
Absence of a difference does not refute it; the measurement is coarse.

## What dynamic testing cannot settle

State these limits alongside any dynamic result:

- A passing dudect run proves nothing about untested inputs, other
  microarchitectures, or other optimization levels.
- Valgrind does not model speculative execution, so Spectre-class leakage is out
  of scope for all of these methods.
- Memory dumps observe one point in time. A secret already copied elsewhere by
  the allocator or the GC will not appear at the address you checked.
- A clean run on the test host says nothing about the production target when the
  architecture differs.

## Promoting confidence

| Evidence combination | Confidence |
| --- | --- |
| Static inventory only, operand traced to a named secret | `likely` |
| Static trace plus a differential build showing the transform | `confirmed` |
| Static trace plus ctgrind reporting the same line | `confirmed` |
| Static trace plus dudect `t > 10` on the same function | `confirmed` |
| Memory dump showing residual key bytes after the wipe | `confirmed` |
| Static inventory with an untraceable operand | `needs_review` |
