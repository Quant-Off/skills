# crypto-source-audit

Source-level cryptographic audit skill for Claude Code.

Reviews code that touches secret key material for **timing side channels**,
**secret zeroization**, **constant-time comparison**, and **weak randomness**.
Every candidate is traced from a named secret to the dangerous operand before it
is reported, so grep hits with no traced secret are recorded as dismissed rather
than filed as findings.

## Install

```
/plugin marketplace add Quant-Off/skills
/plugin install crypto-source-audit@quant-security
```

## Use

Ask Claude to audit crypto source, or invoke directly:

```
/crypto-source-audit
```

## What it does

- Builds a secret inventory first, then scopes the entire audit to it.
- Routes by language to the relevant idioms and vetted primitives.
- Runs four checks: constant-time execution, zeroization, comparison and
  randomness, primitive and mode usage.
- Gates findings on confidence (two independent signals for `confirmed`) and on
  non-negotiable evidence requirements per finding class.
- Reports with a severity rubric, a cleared list citing the line that makes each
  site safe, and an explicit handoff list.

## Structure

```
skills/crypto-source-audit/
├── SKILL.md
└── references/
    ├── constant-time.md        # secret-dependent branches, indexing, latency
    ├── zeroization.md          # wipe primitives, DSE, uncovered copies
    ├── comparison-and-rng.md   # CT comparison, CSPRNG, nonce discipline, primitives
    ├── lang-c-cpp.md
    ├── lang-rust.md
    └── lang-managed.md         # Go, Java, C#, Python, JavaScript
```

## Related

Pairs with [`binary-crypto-verify`](../binary-crypto-verify) to confirm the
compiler preserved the source-level guarantees, and with
[`codebase-security-audit`](../codebase-security-audit) for non-crypto issues.

License: MIT
