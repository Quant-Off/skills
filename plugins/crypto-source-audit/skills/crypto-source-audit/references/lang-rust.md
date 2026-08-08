# Rust Crypto Audit Notes

Rust removes the memory-safety class of bug but changes none of the timing or
zeroization guarantees: LLVM applies the same dead-store elimination and the
same branch reintroduction. The audit shifts toward type discipline, move
semantics, and the `unsafe` boundary.

## Zeroization

The ecosystem answer is the `zeroize` crate, which uses volatile writes plus a
compiler fence and is therefore barrier-backed.

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
struct SessionKey {
    bytes: [u8; 32],
}
// Zeroizing<T> wraps an existing type and wipes on drop
let buf = zeroize::Zeroizing::new(vec![0u8; 32]);
```

Audit points specific to Rust:

| Issue | What to check |
| --- | --- |
| `Clone` on a secret type | Every clone is a separate allocation needing its own drop-wipe. Prefer removing the derive. |
| `Copy` on a secret type | Copies are implicit and untrackable. A secret type must never be `Copy`. |
| `Debug` on a secret type | `{:?}` prints key material into logs and panic messages. Implement `Debug` manually to redact, or omit it. |
| `Vec<u8>` / `String` secrets | Growth reallocates and leaves the old buffer unwiped. Reserve capacity up front or use a fixed array. |
| Moves | A move leaves the source memory intact and merely marks it dead. `ZeroizeOnDrop` on the moved-to value covers the new location, not the old bytes. |
| `mem::forget`, `ManuallyDrop`, leaks | Drop never runs, so the wipe never runs. |
| Panics during drop | A panic in a prior drop can abort unwinding and skip later destructors. |
| `serde` derive on a secret | `Serialize` writes the secret into a formatter buffer that is not wiped. |

**Detection:**

```bash
rg -n "#\[derive\([^)]*\b(Debug|Clone|Copy|Serialize)\b" -tsrust -A2 \
  | rg -i "key|secret|priv|seed|nonce|token|passw"
rg -n "mem::forget|ManuallyDrop|Box::leak" -trust
```

## Constant-time

Use the `subtle` crate rather than raw operators. Its `Choice` type is a
newtype over `u8` with a black-box barrier, and `ConditionallySelectable`
provides masked selection.

```rust
use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

// Comparison: returns Choice, not bool, so it cannot be branched on accidentally
let ok: Choice = computed_tag.ct_eq(&received_tag);

// Selection without a branch
let v = u32::conditional_select(&a, &b, ok);

// Only convert at the very end, when the result is intended to be public
if bool::from(ok) { /* ... */ }
```

Audit points:

| Issue | What to check |
| --- | --- |
| `==` or `PartialEq` on secrets | Derived `PartialEq` short-circuits per field and per byte. A secret type must not derive `PartialEq`; implement `ConstantTimeEq`. |
| `if` on a value derived from a secret | Same finding class as C. Look for `bool::from(choice)` used too early. |
| Indexing with a secret | `slice[secret_idx]` also carries a bounds check whose branch is secret-dependent. |
| `unwrap`, `expect`, `panic!` on secret-parsing paths | The panic message may embed secret content, and the panic itself is an observable event. |
| Iterator adapters | `.position()`, `.find()`, `.any()`, `.all()` all short-circuit. Use `.fold()` with an accumulating OR. |
| `unsafe` blocks | Audit each for its stated invariant, and note that FFI hands the secret to code outside Rust's guarantees. |

**Detection:**

```bash
rg -n "\.ct_eq\(|subtle::|Choice" -trust                      # good signs
rg -n "\.position\(|\.find\(|\.any\(|\.all\(|\.iter\(\)\.eq\(" -trust
rg -n "unwrap\(\)|expect\(" -trust | rg -i "key|secret|decrypt|verify|sign"
rg -n "unsafe\s*\{" -trust
```

## Randomness

Use `OsRng` from `rand::rngs`, or the `getrandom` crate directly. Both draw from
the OS CSPRNG.

Findings:

- `rand::thread_rng()` is a userspace ChaCha-based generator seeded from the OS.
  It is acceptable for key material in most threat models, but note it where an
  air-gapped or FIPS posture requires a direct OS draw.
- `StdRng::seed_from_u64` and any explicitly seeded generator producing key
  material is a Critical finding.
- `rand::random()` for a nonce or token is a finding when the RNG is not the OS
  RNG.

```bash
rg -n "seed_from_u64|SmallRng|StdRng::from_seed|thread_rng\(\)" -trust
```

## Build configuration

Record the profile. `[profile.release]` with `lto = true` or `opt-level = 3`
widens the optimizer's view and increases the chance a wipe is eliminated across
crate boundaries.

```bash
rg -n "opt-level|lto|codegen-units|panic\s*=" Cargo.toml
```

`panic = "abort"` means destructors do not run on unwind, so `ZeroizeOnDrop`
will not fire on a panic path. Note this whenever the crate holds long-lived
secrets.

## Vetted crates

Treat calls into these as safe and record them in the cleared list:
`subtle`, `zeroize`, `secrecy`, `getrandom`, `aes-gcm`, `chacha20poly1305`,
`ring`, `dalek` family (`curve25519-dalek`, `ed25519-dalek`), `rustls`.

A hand-rolled implementation of anything these provide is a Medium finding on
its own.

## Handoff

Route to `binary-crypto-verify`: any `ZeroizeOnDrop` type whose drop is
inlined away, any `conditional_select` you want confirmed as branchless, and
any crate built with `lto = true` where a zeroization finding is in play.
