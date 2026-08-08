# Comparison, Randomness, and Primitive Usage

Three checks that share one property: the correct answer is almost always "call
the vetted primitive," so the audit is mostly about spotting the hand-rolled or
default-but-wrong version.

## Part 1: Constant-time comparison

Any equality test where one side derives from a secret must accumulate
differences across the full length and branch exactly once, at the end.

```c
// VIOLATION: returns as soon as a byte differs, leaking the match prefix length
if (memcmp(tag, expected, 16) != 0) return AUTH_FAIL;

// CORRECT: full-length accumulate, single branch on the folded result
uint8_t diff = 0;
for (size_t i = 0; i < 16; i++) diff |= tag[i] ^ expected[i];
if (diff != 0) return AUTH_FAIL;
```

The attack is a forgery oracle: an attacker submits candidate tags and uses the
response time to learn the correct value one byte at a time, reducing a 2^128
search to roughly 128 * 256 queries. Lucky Thirteen (CVE-2013-0169) is the
production instance of this against TLS CBC.

### Vetted primitives

| Language / library | Primitive |
| --- | --- |
| OpenSSL, BoringSSL | `CRYPTO_memcmp` |
| libsodium | `sodium_memcmp`, `crypto_verify_{16,32,64}` |
| Rust | `subtle::ConstantTimeEq`, `constant_time_eq` crate |
| Go | `crypto/subtle.ConstantTimeCompare` |
| Python | `hmac.compare_digest` |
| Java | `MessageDigest.isEqual` (constant-time since Java 6u17) |
| .NET | `CryptographicOperations.FixedTimeEquals` |
| Node.js | `crypto.timingSafeEqual` |

### Detection

```bash
rg -n "memcmp|strcmp|strncmp|bytes\.Equal|Arrays\.equals|\.equals\(|==" -tcode \
  | rg -i "tag|mac|hmac|sig|digest|token|secret|key|passw|hash"
```

**Triage:** the hit is a finding only if one operand derives from a secret or
from a value the attacker is trying to guess. A `memcmp` on two public protocol
identifiers is a false positive. Note also that the vetted primitives require
**equal lengths**; comparing lengths first is fine and necessary, since length
is public.

## Part 2: Randomness

### Requirements

Keys, nonces, IVs, salts, and blinding factors must come from a CSPRNG.

| Platform | Acceptable source |
| --- | --- |
| Linux, modern | `getrandom(2)`, `/dev/urandom` |
| POSIX | `getentropy(3)` |
| Windows | `BCryptGenRandom` |
| OpenSSL | `RAND_bytes` (check the return value) |
| libsodium | `randombytes_buf` |
| Rust | `rand::rngs::OsRng`, `getrandom` crate |
| Go | `crypto/rand` (never `math/rand`) |
| Python | `secrets`, `os.urandom` (never `random`) |
| Java | `SecureRandom` (never `Random`) |
| Node.js | `crypto.randomBytes` (never `Math.random`) |

### Detection

```bash
rg -n "\brand\(\)|\brandom\(\)|Math\.random|mt19937|srand\(|new Random\(|math/rand|time\(NULL\)" -tcode
```

**Triage:** a weak PRNG used for a retry jitter, a test fixture, or a
non-security shuffle is a false positive. It is a finding when the output
becomes key material, a nonce, a session identifier, a password-reset token, or
a CSRF token. Also check that `RAND_bytes`-style return codes are checked; a
silently failing RNG that returns zeroed buffers is a Critical finding.

### Nonce and IV discipline

Nonce reuse is often more damaging than a weak cipher. Verify per algorithm:

| Algorithm | Consequence of reuse under a fixed key |
| --- | --- |
| AES-GCM | Authentication key recovery, full forgery capability. Catastrophic. |
| ChaCha20-Poly1305 | Same: keystream reuse plus Poly1305 key recovery. |
| CTR, OFB, CFB | Keystream reuse; XOR of two plaintexts. |
| ECDSA, DSA (the `k` value) | Immediate private key recovery from two signatures. |
| CBC | IV must be unpredictable, not merely unique, or chosen-plaintext attacks apply (BEAST). |

Check the counter width against the expected message volume: a 32-bit random
nonce collides at roughly 2^16 messages by the birthday bound. For AES-GCM with
random 96-bit nonces, the accepted limit is about 2^32 messages per key.

Also confirm the nonce is not reset when a connection resumes, a process
restarts, or a VM is restored from snapshot. Counter state that lives only in
memory is a reuse bug on rollback.

## Part 3: Primitive and mode usage

### Deprecated primitives

| Primitive | Status | Migration target |
| --- | --- | --- |
| MD5, SHA-1 | Broken for collision resistance | SHA-256, SHA-3, BLAKE2 |
| SHA-1 in signatures or certificates | Broken (SHAttered, 2017) | SHA-256 or better |
| DES, 3DES | 64-bit block, Sweet32 (CVE-2016-2183) | AES |
| RC4 | Biased keystream | AES-GCM, ChaCha20-Poly1305 |
| ECB mode | Leaks plaintext structure | An AEAD mode |
| PKCS#1 v1.5 encryption | Bleichenbacher padding oracles | OAEP, or better, a KEM |
| Raw RSA, textbook RSA | Malleable | OAEP for encryption, PSS for signatures |
| Unsalted or fast password hashes | Trivially cracked | Argon2id, scrypt, bcrypt |

### Composition rules

- Prefer AEAD (AES-GCM, ChaCha20-Poly1305, AES-OCB) over building your own.
- If composing manually, encrypt-then-MAC only. MAC-then-encrypt and
  encrypt-and-MAC both have known padding-oracle failures.
- The MAC must cover the IV, the associated data, and the ciphertext.
- Verify the MAC **before** decrypting or parsing anything.
- Never reuse one key for two purposes. Derive per-purpose subkeys with HKDF.

### Hand-rolled crypto

Any implementation of a standard primitive inside application code, rather than
a call into a vetted library, is worth reporting on its own. Note it as a
Medium finding with the rationale that the maintenance burden and audit surface
are unjustified, then audit it against the rest of this skill anyway.

## What is *not* a finding

- MD5 or SHA-1 used as a non-security checksum (cache key, ETag, dedup hash),
  provided no attacker controls the input in a way that matters.
- `math/rand` in tests, benchmarks, or jitter.
- `memcmp` on public values.
- A "custom" wrapper that only forwards arguments to a vetted primitive.
