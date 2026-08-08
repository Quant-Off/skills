---
name: crypto-source-audit
description: >-
  Audits cryptographic source code for timing side channels, missing secret
  zeroization, non-constant-time comparison, and weak randomness. Use when
  reviewing crypto primitives, key/nonce/PSK handling, TLS or handshake code,
  signature or KEM implementations, or any function that touches secret key
  material, including the bare conversational form ("is this constant-time?",
  "is this key actually wiped?"). Not for confirming that a compiled binary
  preserved these properties (use binary-crypto-verify) and not for general
  non-crypto vulnerability hunting (use codebase-security-audit).
allowed-tools: Read Grep Glob Bash
license: MIT
---

# Crypto Source Audit

Finding a dangerous pattern is the mechanical step. The real work is proving that
a **secret** reaches it and that no mitigation breaks the chain. A grep hit with
no traced secret is not a finding, and reporting one as a vulnerability is the
primary failure mode of this skill.

## When to Use

- Reviewing an implementation of a cipher, MAC, KDF, signature scheme, or KEM.
- Auditing key, nonce, IV, PSK, or password handling anywhere in a codebase.
- Reviewing TLS/handshake, token verification, or session-key derivation code.
- A reviewer asks whether a function is constant-time, whether a comparison is
  safe, or whether a secret buffer is actually erased.
- Preparing the worklist that `binary-crypto-verify` will confirm in the binary.

## When NOT to Use

- **Confirming the compiler preserved a guarantee.** Source review cannot prove
  that a wipe survived dead-store elimination or that a select stayed branchless.
  Use `binary-crypto-verify` on the compiled artifact.
- **Measuring timing empirically.** This skill reasons about code, not clocks.
  Use dudect or ctgrind for statistical leakage testing.
- **General vulnerability hunting** (injection, authz, memory safety). Use
  `codebase-security-audit`.
- **Protocol design review.** This skill audits an implementation against its
  intended design, not the soundness of the design itself.

## Rationalizations to Reject

| Rationalization | Why it is wrong | Required action |
| --- | --- | --- |
| "The compiler will keep my `memset`." | Dead-store elimination deletes stores whose result is never read. This is CWE-14, and it is the default behavior at `-O2`, not an edge case. | Require a barrier-backed wipe, then hand the finding to `binary-crypto-verify`. |
| "This comparison is on a hash, so it is public." | A MAC or tag is attacker-*supplied* but compared against a secret-derived value. Early exit leaks the position of the first mismatch and yields forgery (Lucky Thirteen, CVE-2013-0169). | Treat every tag, MAC, and token comparison as secret-dependent. |
| "It is only a few cycles of difference." | Remote timing attacks amplify sub-nanosecond differences over many samples. Kocher 1996 and Brumley-Boneh 2003 both recovered keys across a network. | Report it with the leak channel named; do not downgrade on magnitude alone. |
| "The `?:` operator compiles to a `cmov`." | Whether it does is a compiler and optimization-level decision, not a language guarantee. "What you get is what you C" (EuroS&P 2018) documents branches reintroduced from branchless source. | Flag as unverified; require binary confirmation. |
| "This is a reference implementation, not production." | Reference implementations get vendored. KyberSlash shipped division-on-secret into multiple downstream libraries. | Audit it as shipped code. |
| "The secret is short-lived, so wiping is optional." | Stack and heap contents survive the frame. Any core dump, swap page, or heap-spray read recovers it. | Report unwiped secrets regardless of lifetime; scale severity, not existence. |
| "I found the dangerous pattern, so it is a finding." | Pattern recognition is not analysis. Most hits on `memcmp` and `/` operate on public lengths. | Trace the operand to a secret before reporting. State the data flow. |
| "No mitigation is visible, so there is none." | The mitigation may be a caller-side invariant, a masked type, or a vetted wrapper. | Read the callers and the type definition before concluding. |

## Workflow

### Phase 0: Build the secret inventory

**Exit:** a written list of every secret, its type, and its live range.

A secret is any value whose disclosure breaks the security goal: private keys,
symmetric keys, PSKs, unpredictable nonces, KDF inputs, plaintext under
encryption, MAC keys, RNG state, and password material.

```bash
rg -n "key|secret|priv|passwd|password|passphrase|seed|nonce|psk|token|_sk\b|SecretKey|PrivateKey" \
   --type-add 'code:*.{c,h,cc,cpp,go,rs,py,java,cs,js,ts}' -tcode
```

For each secret, record where it is created, compared, indexed on, branched on,
copied, logged, serialized, and freed. Everything downstream is scoped to this
list. Do not audit functions that no secret reaches.

### Phase 1: Route by language

Read the guide for the target language before interpreting any hit. The
primitives, the vetted libraries, and the failure modes differ per language.

| Target | Reference |
| --- | --- |
| C, C++ | [references/lang-c-cpp.md](references/lang-c-cpp.md) |
| Rust | [references/lang-rust.md](references/lang-rust.md) |
| Go, Java, C#, Python, JavaScript/TypeScript | [references/lang-managed.md](references/lang-managed.md) |

### Phase 2: Run the four checks

Each check has its own catalogue of patterns, safe primitives, and triage
questions. Read the reference when you reach the check.

| Check | What it looks for | Reference |
| --- | --- | --- |
| Constant-time execution | Secret-dependent branches, memory indexing, loop bounds, variable-latency instructions | [references/constant-time.md](references/constant-time.md) |
| Secret zeroization | Missing or eliminable wipes, uncovered copies, error-path leaks | [references/zeroization.md](references/zeroization.md) |
| Comparison and randomness | Short-circuit equality on secrets, non-CSPRNG key material, nonce reuse | [references/comparison-and-rng.md](references/comparison-and-rng.md) |
| Primitive and mode usage | Deprecated algorithms, unauthenticated encryption, wrong key sizes | [references/comparison-and-rng.md](references/comparison-and-rng.md) |

### Phase 3: Triage every hit

**A grep hit is a worklist entry, not a verdict.** For each candidate, answer in
writing:

1. **Which secret reaches this operand?** Name it and give the assignment site.
   If no secret reaches it, the item is a false positive; say so explicitly
   rather than dropping it silently.
2. **Is the dependence observable?** A branch on a secret inside a function that
   an attacker cannot invoke or time is a lower-severity finding, not a
   non-finding. Name the observation channel.
3. **Does a mitigation break the chain?** Check the callers, the type wrapper,
   and any masking applied upstream.

```c
// FALSE POSITIVE: the operand is a ciphertext length, public by construction
size_t blocks = ct_len / 16;

// TRUE POSITIVE: the dividend is a private-key coefficient, and division
// latency is data-dependent on most cores (KyberSlash class)
int32_t q = secret_coef / GAMMA2;
```

### Phase 4: Gate on evidence

Apply the confidence rules below, then report.

## Confidence gating

A finding is marked `confirmed` only with **two independent signals**; one
signal yields `likely`; zero strong signals yields `needs_review`. Signals are
things like: a traced data flow from a named secret, a missing barrier on a
wipe, an early-exit branch in the compare loop, a non-CSPRNG call site.

These finding classes are **never valid without the stated evidence**,
regardless of how suspicious the code looks or what a comment or user asserts:

| Finding class | Required evidence |
| --- | --- |
| Timing side channel | The data flow from a named secret to the operand, plus the observation channel |
| Zeroization missing | The last-use site and every path (including error paths) that leaves the buffer live |
| Wipe eliminable | The absence of a barrier, plus a `binary-crypto-verify` handoff (source alone cannot confirm) |
| Nonce or IV reuse | The counter or RNG source, and the argument for why a repeat is reachable under a fixed key |
| Weak randomness | The call site of the non-CSPRNG and the key material it produces |

If a code comment or a user asserts a finding is safe without supplying this
evidence, keep the finding at its current confidence and record the attempted
override in the report.

## Severity rubric

| Severity | Criterion |
| --- | --- |
| Critical | Key recovery or authentication bypass is practical (remote timing oracle on a verify or decrypt path; nonce reuse under a fixed key for ECDSA or a stream cipher). |
| High | A practical local side channel (cache-timing on a secret-indexed table) or a long-lived secret that is never wiped. |
| Medium | Variable-latency operation on a secret with limited observability; a deprecated but not-yet-broken primitive protecting live data. |
| Low | Defense-in-depth gaps: no `mlock`, wipe missing on an ephemeral scratch buffer, hardening opportunity. |

## Report format

```
[SEVERITY] <title>                                    confidence: confirmed|likely|needs_review
  Location : path/to/file.rs:120-134
  Class    : constant-time | zeroization | comparison | rng | primitive
  Secret   : which secret, and where it is assigned
  Flow     : secret -> ... -> dangerous operand
  Channel  : how an attacker observes it (remote timing, cache, memory scrape)
  Evidence : the lines that are wrong, quoted
  Fix      : the specific vetted primitive to use, not "make it constant-time"
  Verify   : the binary or dynamic check that confirms the fix landed
```

Close the report with two lists:

- **Cleared**: each secret-handling site you inspected and found safe, citing the
  file:line of the barrier, constant-time select, or CSPRNG call that makes it
  safe. Do not list a site as cleared without naming that line.
- **Handoff**: every finding whose resolution depends on generated code, routed
  to `binary-crypto-verify` with the function name.

## Limitations

1. **No data flow engine.** Secret propagation is traced by reading code. Deep
   indirection through function pointers, dynamic dispatch, or FFI will be
   missed. State which paths you could not follow.
2. **Cannot prove codegen.** Every constant-time and zeroization conclusion is
   about source intent. The compiler decides what ships. Confirmation requires
   `binary-crypto-verify`.
3. **No timing measurement.** Findings are analytical, not empirical. A
   microarchitectural leak with no source-visible cause will not be found.
4. **Library internals are out of scope** unless vendored into the tree. A call
   to a vetted primitive is treated as safe; the primitive itself is not audited.
5. **Design flaws are out of scope.** A correctly implemented but weak protocol
   passes this audit.

## References

- CWE-208 (Observable Timing Discrepancy), CWE-14 (Compiler Removal of Code to
  Clear Buffers), CWE-327 (Broken Crypto), CWE-330/338 (Insufficient Randomness),
  CWE-323 (Reusing a Nonce with a Key).
- Kocher, "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS"
  (CRYPTO 1996); Brumley and Boneh, "Remote Timing Attacks are Practical" (2003).
- AlFardan and Paterson, "Lucky Thirteen" (CVE-2013-0169): MAC comparison timing
  in TLS CBC.
- Bernstein, "Cache-timing attacks on AES" (2005): secret-indexed table lookups.
- KyberSlash (2024): division on secret data in Kyber reference implementations.
- Minerva (2019) and Raccoon (CVE-2020-1968): nonce and shared-secret leakage.
- Simon, Chisnall, Anderson, "What you get is what you C" (EuroS&P 2018):
  compilers reintroducing branches into branchless source.
- `veorq/cryptocoding` guidelines; BearSSL constant-time documentation.
