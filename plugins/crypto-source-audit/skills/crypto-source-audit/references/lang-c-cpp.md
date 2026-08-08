# C and C++ Crypto Audit Notes

C and C++ give the compiler the most freedom and the programmer the fewest
guarantees, so both the constant-time and the zeroization checks are at their
weakest here. Assume nothing survives without a barrier.

## Language-specific hazards

### The abstract machine gives you no timing guarantees

The standard says nothing about execution time. Every constant-time property is
a property of the *generated code* for a *specific target and optimization
level*, never of the source. Two consequences for the audit:

- A masked select written correctly in C can still compile to a branch. Report
  it as unverified and route to `binary-crypto-verify`.
- A "fix" verified at `-O0` proves nothing about the shipped `-O2` build.
  Findings must name the build configuration.

### `volatile` is a partial tool

`volatile` on a pointer used for wiping prevents elision of those specific
stores, and is the mechanism behind most portable implementations. It does not
make surrounding code constant-time and does not prevent the compiler from
having spilled the secret elsewhere first.

### Undefined behavior interacts badly with crypto

Signed integer overflow, out-of-bounds reads, and strict-aliasing violations let
the optimizer delete or reorder checks. A UB bug inside a crypto routine is both
a memory-safety finding and a potential correctness break of the constant-time
property. Compile the target with `-fsanitize=undefined,address` if a build is
available.

## Zeroization

Preferred primitives, in order:

1. `explicit_bzero(p, n)` (glibc 2.25+, OpenBSD, FreeBSD).
2. `OPENSSL_cleanse(p, n)` if OpenSSL is already a dependency.
3. `sodium_memzero(p, n)` if libsodium is already a dependency.
4. `SecureZeroMemory(p, n)` on Windows.
5. `memset_s(p, len, 0, n)` where C11 Annex K is genuinely available (check
   `__STDC_LIB_EXT1__`; it is absent on glibc).
6. `memset` plus `asm volatile("" ::: "memory")` as a last resort.

C++ specifics:

- A destructor is the right place for the wipe. Verify it is actually called:
  a secret in a `std::vector` that is `std::move`d, or an object destroyed after
  `std::terminate`, does not run cleanup.
- `std::string` and `std::vector` reallocate. Their old buffers are unwiped and
  unreachable. Use a fixed `std::array` or a custom allocator that wipes on
  deallocate.
- Small-string optimization keeps short secrets inline in the object, so
  wiping the heap pointer is not enough.
- `std::optional`, `std::variant`, and copy elision create copies that no
  destructor you wrote will wipe.

```cpp
// Acceptable pattern: fixed storage, wipe in the destructor, non-copyable
class SecretKey {
    std::array<uint8_t, 32> k_{};
public:
    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    ~SecretKey() { OPENSSL_cleanse(k_.data(), k_.size()); }
};
```

## Constant-time idioms

```c
// Mask from a condition, without a branch. Both operands evaluated.
static inline uint64_t ct_mask(uint64_t cond_nonzero) {
    return (uint64_t)0 - (uint64_t)((cond_nonzero | (0 - cond_nonzero)) >> 63);
}

// Constant-time select: returns a if mask is all-ones, b if all-zeros
static inline uint64_t ct_select(uint64_t mask, uint64_t a, uint64_t b) {
    return b ^ (mask & (a ^ b));
}
```

Prefer an existing implementation over a hand-rolled one: BearSSL's
`br_*` inner functions, `crypto_int32`/`crypto_uint32` from the SUPERCOP
conventions, or the primitives shipped with the library already in use.

## Grep starters

```bash
# Unprotected wipes
rg -n "memset\s*\([^,]+,\s*0|bzero\s*\(" --type c --type cpp

# Non-constant-time comparison on likely-secret data
rg -n "memcmp|strcmp|strncmp" --type c --type cpp | rg -i "key|tag|mac|sig|token|hash|secret"

# Weak randomness
rg -n "\brand\s*\(|\bsrand\s*\(|\brandom\s*\(|time\s*\(\s*NULL" --type c --type cpp

# Division and modulo (check whether the operand is secret)
rg -n "[^/]/[^/=]|%[^=]" --type c --type cpp | rg -i "key|secret|priv|coef|scalar|nonce"

# Secret-indexed table lookups
rg -n "\w+\s*\[\s*\w*(key|secret|state|scalar|nonce)\w*\s*[\]\[]" --type c --type cpp
```

## Build-configuration checks

Record these in the report; they change what the findings mean.

```bash
rg -n "\-O[0-3s]|\-flto|\-fno-builtin|\-ffast-math" --glob '!*.md' \
   --glob 'Makefile*' --glob '*.mk' --glob 'CMakeLists.txt' --glob '*.cmake'
```

- `-flto` extends the optimizer's view across translation units, so a wipe that
  survived in one object file can be eliminated at link time. Any zeroization
  finding must state whether LTO is on.
- `-ffast-math` is a red flag near any code handling secrets in floating point.
- The absence of `-fstack-protector`, `-D_FORTIFY_SOURCE=2`, or RELRO/PIE is a
  hardening note, not a crypto finding.

## Handoff

C and C++ findings have the highest binary-confirmation requirement of any
language. Route to `binary-crypto-verify`: every bare `memset` wipe, every
masked select, every ternary on a secret, and every function large enough to
spill secrets to the stack.
