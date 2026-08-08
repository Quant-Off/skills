# codebase-security-audit

Zero-trust security audit skill for Claude Code.

Reviews a codebase, module, or single file across injection, authorization,
secrets, memory safety, deserialization, SSRF, and dependency risk. Every
candidate passes **six validation gates** before it is reported, so the output is
an audit rather than a list of grep hits.

## Install

```
/plugin marketplace add Quant-Off/skills
/plugin install codebase-security-audit@quant-security
```

## Use

Ask Claude to security-audit a target, or invoke directly:

```
/codebase-security-audit
```

## What it does

- Maps the attack surface first: entry points, trust boundaries, privileged
  operations. Code that no untrusted input reaches is not audited.
- Sweeps by bug class with per-language sink catalogues.
- Writes an explicit source-to-sink flow for every candidate. No flow, no
  finding.
- Gates each candidate on: untrusted source, reachability, attacker control,
  absence of mitigation, real impact, and a devil's advocate refutation attempt.
- Reports with a CVSS-aligned severity rubric plus three closing lists: cleared,
  dismissed (with the gate that failed), and not covered.

## Structure

```
skills/codebase-security-audit/
├── SKILL.md
└── references/
    ├── validation-gates.md     # the six gates, verdict format, confidence rules
    ├── bug-classes.md          # injection, deserialization, SSRF, XSS, CSRF, XXE
    ├── authz-and-identity.md   # IDOR, JWT, sessions, OAuth, multi-tenancy, TOCTOU
    ├── secrets-and-memory.md   # secrets, memory safety, concurrency, dependencies
    └── language-sinks.md       # Python, JS/TS, Go, Rust, Java, C/C++, PHP, Ruby
```

## Related

Delegates deep cryptographic checks to
[`crypto-source-audit`](../crypto-source-audit) and compiled-artifact
verification to [`binary-crypto-verify`](../binary-crypto-verify).

License: MIT
