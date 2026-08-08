# Managed Languages: Go, Java, C#, Python, JavaScript

In garbage-collected runtimes, **zeroization is best-effort and frequently
impossible**. A moving or copying collector may have relocated the secret before
your wipe runs, leaving an unreachable copy that you cannot address. State this
limitation explicitly rather than reporting a wipe as fully effective.

The audit therefore reweights: comparison and randomness findings are as sharp
as in C, zeroization findings become "reduce exposure" rather than "erase," and
JIT compilation makes constant-time claims unverifiable at the source level.

## Cross-cutting: why constant-time is hard here

- The JIT recompiles hot paths with speculative optimizations, including branch
  specialization on observed values. Source-level branchless code gives no
  guarantee.
- Boxed integers, bounds checks, and interface dispatch add data-dependent work.
- Only the runtime's own vetted primitives should be trusted for constant-time
  behavior. Do not accept hand-rolled masking in these languages; recommend the
  platform primitive instead.

## Go

| Check | Guidance |
| --- | --- |
| Comparison | `crypto/subtle.ConstantTimeCompare`. Flag `bytes.Equal`, `==`, and `reflect.DeepEqual` on secrets. |
| Randomness | `crypto/rand` only. `math/rand` for key material is Critical. Note that Go 1.20+ auto-seeds `math/rand`, which makes the bug quieter, not safer. |
| Zeroization | No guarantee. A `[]byte` can be wiped in place with a loop, and that is worth doing, but the GC may have copied it. Strings are immutable and cannot be wiped at all: never store a secret in a `string`. |
| Slices | `append` reallocates and abandons the old array. Preallocate with `make([]byte, n)`. |
| Defer | Wipe in a `defer` so error paths are covered. Confirm the function does not `os.Exit` or panic past it. |

```bash
rg -n "bytes\.Equal|reflect\.DeepEqual|math/rand" -tgo
rg -n "subtle\.ConstantTimeCompare|crypto/rand" -tgo   # good signs
```

## Java and Kotlin

| Check | Guidance |
| --- | --- |
| Comparison | `MessageDigest.isEqual` (constant-time since 6u17). Flag `Arrays.equals`, `String.equals`, `.equals()` on secret-bearing objects. |
| Randomness | `SecureRandom`. `java.util.Random` and `Math.random()` for key material are Critical. Avoid `SecureRandom.setSeed` on a fresh instance in a way that replaces OS entropy. |
| Zeroization | Use `char[]` or `byte[]`, never `String`. Strings are immutable, interned, and may persist in the constant pool for the process lifetime. `Arrays.fill(buf, (byte)0)` is the best available wipe. |
| Key material | Prefer `javax.crypto.spec.SecretKeySpec` with a `byte[]` you control, and call `destroy()` where the provider implements it (many do not; check for `DestroyFailedException`). |
| Logging | `toString` on a config or key object leaks. Check Lombok `@Data` and `@ToString`, which generate leaking implementations silently. |

```bash
rg -n "Arrays\.equals|new Random\(|Math\.random|String .*(password|secret|key)" -tjava
rg -n "@Data|@ToString|@Value" -tjava
```

## C# and .NET

| Check | Guidance |
| --- | --- |
| Comparison | `CryptographicOperations.FixedTimeEquals`. Flag `SequenceEqual`, `==`, `Array.Equals`. |
| Zeroization | `CryptographicOperations.ZeroMemory(span)` is the supported wipe. `SecureString` is deprecated and is not a solution. |
| Randomness | `RandomNumberGenerator.GetBytes`. `System.Random` for key material is Critical. |
| Strings | Same immutability problem as Java. Use `byte[]` or `Span<byte>`. |

```bash
rg -n "SequenceEqual|new Random\(|SecureString" -tcs
```

## Python

| Check | Guidance |
| --- | --- |
| Comparison | `hmac.compare_digest`. Flag `==` on tokens, tags, and password hashes. |
| Randomness | `secrets` or `os.urandom`. The `random` module for tokens is Critical (it is a Mersenne Twister; observing 624 outputs recovers the full state). |
| Zeroization | Effectively impossible for `bytes` and `str`, which are immutable. Use `bytearray` and overwrite in place, and accept that interpreter-internal copies remain. |
| Exposure | Tracebacks include local variables in many frameworks. A secret in a local is a disclosure risk on any exception. |
| Serialization | `pickle` of a secret-bearing object writes cleartext to disk. |

```bash
rg -n "import random|random\.(random|randint|choice|sample)|==\s*(token|sig|mac|digest)" -tpy
rg -n "hmac\.compare_digest|secrets\.|os\.urandom" -tpy   # good signs
```

## JavaScript and TypeScript

| Check | Guidance |
| --- | --- |
| Comparison | `crypto.timingSafeEqual` (Node). Flag `===` and `==` on tokens and tags. Requires equal-length buffers; it throws otherwise. |
| Randomness | `crypto.randomBytes` (Node) or `crypto.getRandomValues` (browser). `Math.random()` for tokens is Critical. |
| Zeroization | `Buffer.fill(0)` on a Node `Buffer` works in place. Strings cannot be wiped. V8 may have copied either. |
| Browser context | Anything in client-side JavaScript is public. A "secret" shipped to the browser is a disclosure finding regardless of how it is handled. |

```bash
rg -n "Math\.random|===\s*(token|sig|mac|hash)" -tjs -tts
rg -n "timingSafeEqual|randomBytes|getRandomValues" -tjs -tts   # good signs
```

## Reporting adjustment for managed languages

When reporting a zeroization finding here, phrase the fix as exposure reduction
and state the residual risk:

> Fix: store the key in a `byte[]` rather than a `String` and call
> `Arrays.fill(key, (byte) 0)` after use.
> Residual: the JVM may have relocated the array during GC; unreachable copies
> may persist until process exit. Full erasure is not achievable in this
> runtime. For long-lived keys, move the material into an HSM, a KMS, or a
> native module.

Do not mark a managed-language secret as "cleared: wiped." The correct cleared
entry is "cleared: exposure minimized, residual GC copies documented."

## Handoff

`binary-crypto-verify` operates on native artifacts and is generally **not
applicable** to these runtimes. The exception is native modules and FFI (JNI,
cgo, Node native addons, Python C extensions), where the secret crosses into
compiled code and the full binary audit applies.
