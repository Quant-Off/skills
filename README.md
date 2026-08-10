# Quant-Off Security Skills

<div align="center">

English | [한국어](README_KR.md)
</div>

A [Claude Code](https://docs.claude.com/en/docs/claude-code) **plugin marketplace** for security research. It provides the methodology Claude Code needs to verify cryptographic code, analyze binary artifacts with Ghidra, and audit codebases accurately and repeatably.

## Why

Security guarantees are easy to claim but hard to verify. Constant-time code can be turned into a timing attack by the compiler, a `memset` that wipes a key can be deleted by DSE (Dead-Store Elimination), and an audit that relies on memory alone easily misses the one unauthorized hole that actually matters. These skills codify a zero-trust, evidence-first workflow structure so that guarantees become proof rather than assumption.

## Available plugins

The skills currently included in this repository are listed in the table below.

| Plugin                                                       | Role                                                                                                                                                                                                        |
|--------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`crypto-source-audit`](plugins/crypto-source-audit)         | Source-level crypto audit checking constant-time execution, secret zeroization, constant-time comparison, CSPRNG usage, and side-channel resistance                                                         |
| [`binary-crypto-verify`](plugins/binary-crypto-verify)       | Uses reverse-engineering tools (Ghidra, objdump, radare2) to verify that constant-time logic and zeroization survived the compiler (no reintroduced branches, no dead-store-eliminated wipes)               |
| [`codebase-security-audit`](plugins/codebase-security-audit) | Zero-trust audit across injection, authentication and authorization, secrets, crypto misuse, memory safety, deserialization, SSRF, and dependency risk, producing severity-ranked, evidence-backed findings |

All plugins are designed to chain together. Audit the source with `crypto-source-audit`, confirm the compiler preserved those guarantees with `binary-crypto-verify`, and sweep everything else structurally with `codebase-security-audit`.

## How the skills work

Each skill follows the same shape, so the output is an audit rather than a pile of grep hits.

- **Explicit scope.** Every skill states when to use it and when to use a sibling instead, so the right methodology runs for the question asked.
- **Rationalizations to reject.** Each skill opens with the shortcuts that produce wrong or missed findings, and the action required instead of each one.
- **Worklist, not verdict.** Tool and grep output is treated as candidates. Each item must be traced to a named secret or a named untrusted source before it can be reported, and untraceable items are recorded as dismissed rather than dropped in silence.
- **Evidence gates.** Findings carry non-negotiable evidence requirements and a confidence level. An assertion in a comment or from a reviewer does not lower a finding's confidence on its own.
- **Stated blind spots.** Every skill enumerates its own limitations, so an empty report is not mistaken for a clean bill of health.
- **Progressive disclosure.** `SKILL.md` stays short and routes to `references/` for the detail the current phase needs. `binary-crypto-verify` also ships a working Ghidra headless script in `scripts/`.

## Install

Add the marketplace to your Claude Code environment with the commands below. You can then install any plugin you want.

```
/plugin marketplace add Quant-Off/skills
/plugin install crypto-source-audit@quant-security
/plugin install binary-crypto-verify@quant-security
/plugin install codebase-security-audit@quant-security
/plugin install ...
```

`quant-security` is the name of this marketplace (defined in `.claude-plugin/marketplace.json`). Each plugin lives under `plugins/<name>` in this repository. Manage your installs as follows.

```
/plugin list # list installed plugins
/plugin marketplace update # pull updates
/plugin disable <name>@quant-security
```

For development environments, you can also add a local checkout as a marketplace.

```
/plugin marketplace add ./path/to/this-repo
```

## Use

Once installed, a skill activates automatically when your request matches it (for example, "audit this crypto code for constant-time issues" or "check in the binary that this memset was not optimized away"). You can also invoke them directly.

```
/crypto-source-audit
/binary-crypto-verify
/codebase-security-audit
```

`binary-crypto-verify` requires Ghidra (`$GHIDRA_HOME`) or `objdump` or `radare2` on the host.

## Repository layout

```
root/
├── .claude-plugin/marketplace.json # marketplace manifest (repo root)
├── plugins/
│   └── <plugin-name>/
│       ├── .claude-plugin/plugin.json
│       ├── skills/<skill-name>/
│       │   ├── SKILL.md            # entry point, under 500 lines
│       │   ├── references/         # detail loaded on demand
│       │   └── scripts/            # optional executable helpers
│       └── README.md
├── CLAUDE.md # agent guide
├── CONTRIBUTING.md # contribution guide
└── README.md # English docs (this file)
```

## Contributing

For how to add a plugin, validation steps, and conventions, see [CONTRIBUTING.md](CONTRIBUTING.md). Claude Code operating in this repo follows the directives in [CLAUDE.md](CLAUDE.md). All skills must follow a zero-trust, air-gapped-ready posture by default. Work offline where possible, never exfiltrate code or secrets, and attach concrete evidence and a clear fix to every finding.

## License

[MIT](LICENSE)
