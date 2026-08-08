# Secret Zeroization

A secret that outlives its use is recoverable from a core dump, a swap page, a
heap-spray read, a hibernation image, or a VM snapshot. The audit has two
independent questions: **is there a wipe at all**, and **will the wipe survive
the compiler**.

## Why a plain `memset` is not a wipe

After the last read of a buffer, a store to that buffer has no observable effect
under the C abstract machine, so the optimizer is entitled to delete it. This is
dead-store elimination, and it is the documented behavior of GCC and Clang at
`-O2`, not a bug. CWE-14 is exactly this.

```c
void derive(const uint8_t *pw, size_t n) {
    uint8_t key[32];
    kdf(pw, n, key);
    use_key(key);
    memset(key, 0, sizeof key);   // DELETED at -O2: key is never read after
}
```

**Reference:** Yang, Johannesmeyer, Olesen, Lerner, Levchenko, "Dead Store
Elimination (Still) Considered Harmful" (USENIX Security 2017), which measured
this across real crypto libraries.

## Accepted wipe primitives

Only these count as barrier-backed. Anything else is a finding.

| Platform | Primitive | Notes |
| --- | --- | --- |
| POSIX / glibc 2.25+, BSD | `explicit_bzero(p, n)` | Compiler is forbidden from eliding it. |
| C11 Annex K | `memset_s(p, len, 0, n)` | Optional annex; confirm the toolchain provides it. |
| Windows | `SecureZeroMemory(p, n)` | Macro over a volatile-write loop. |
| OpenSSL | `OPENSSL_cleanse(p, n)` | Portable; also present in LibreSSL and BoringSSL. |
| libsodium | `sodium_memzero(p, n)` | Portable. |
| Rust | `zeroize` crate: `Zeroize`, `ZeroizeOnDrop`, `Zeroizing<T>` | Uses volatile writes plus a compiler fence. |
| Go | No language guarantee | See the managed-language reference; the GC may have copied the value already. |
| Portable fallback | `memset` followed by `asm volatile("" ::: "memory")` | Acceptable, but confirm the barrier is actually present. |

A `volatile` *pointer cast* (`*(volatile uint8_t *)p = 0` in a loop) is
generally effective but implementation-defined. Accept it with a note; prefer a
named primitive.

## Audit procedure

### Step 1: Find declared wipes and unprotected wipes

```bash
# Barrier-backed wipes present in the tree
rg -n "explicit_bzero|memset_s|SecureZeroMemory|OPENSSL_cleanse|sodium_memzero|Zeroizing|ZeroizeOnDrop|zeroize\(" -tcode

# Bare memset/bzero: candidates for elimination
rg -n "memset\s*\([^,]+,\s*0[^)]*\)|bzero\s*\(" -tcode
```

### Step 2: For each secret in the inventory, walk the live range

Answer for every secret buffer:

1. Where is the **last read**? The wipe must follow it on every path.
2. Do **all error and early-return paths** reach the wipe? A `goto cleanup` or
   RAII guard is the usual correct pattern; an early `return -1` between
   allocation and wipe is a finding.
3. Does the wipe cover the **full length** of the secret, including any padding
   or the capacity beyond the current length?
4. Is the buffer **freed before it is wiped**? Freeing first returns the bytes to
   the allocator intact.

### Step 3: Hunt for copies the wipe does not cover

This is the step most audits skip, and it is where real leaks hide.

| Copy source | What to check |
| --- | --- |
| Growable containers (`std::vector`, `String`, `Vec`, `StringBuilder`) | Reallocation leaves the old buffer unwiped. Reserve capacity up front, or use a fixed array. |
| Pass-by-value structs and `clone()` | Every copy is a separate buffer needing its own wipe. |
| Move semantics | Confirm the moved-from source is wiped, not merely marked invalid. |
| Serialization and encoding scratch | Base64, hex, JSON, and protobuf buffers hold the secret in cleartext. |
| Logging, `Debug`, `toString`, panic and assert messages | The formatter allocates its own buffer. Also a direct disclosure finding. |
| Stack spills and temporaries | Large functions spill registers. Not visible in source; note it and route to `binary-crypto-verify`. |
| Compiler-inserted copies (return slots, inlining) | Same: source-invisible, binary-confirmable. |

### Step 4: Check the memory policy around the secret

- **Swap:** for long-lived key stores, is the page locked (`mlock`,
  `VirtualLock`)? Absence is a Low finding unless the threat model includes disk
  forensics, in which case it is Medium.
- **Core dumps:** does the process disable dumps (`setrlimit(RLIMIT_CORE, 0)`,
  `PR_SET_DUMPABLE`) when holding long-lived keys?
- **Fork:** a child inherits the parent's secret pages. Check that keys are
  wiped before `fork` in daemons that fork per connection.

## Severity guidance

| Situation | Severity |
| --- | --- |
| Long-lived private key never wiped | High |
| Session key or KDF output never wiped | High |
| Wipe present but eliminable (bare `memset`) on a long-lived secret | High, pending binary confirmation |
| Wipe missing only on an error path | Medium |
| Uncovered copy in a serialization buffer | Medium |
| Ephemeral scratch buffer unwiped | Low |
| No `mlock` on a key store | Low |

## Handoff

Source review can prove a wipe is *absent*. It cannot prove a present wipe
*survived*. Every "wipe present but not barrier-backed" finding must be routed
to `binary-crypto-verify`, which compares the emitted stores across optimization
levels. State the function name in the handoff.
