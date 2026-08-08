# CLAUDE.md

Directives for Claude Code when working in this repository. Follow these rules
whenever you create or modify files here. The human contribution workflow lives
in [CONTRIBUTING.md](CONTRIBUTING.md); this file is the operating manual for the
agent.

## Repository context

`Quant-Off/skills` is a **Claude Code plugin marketplace** for security research.
Each plugin bundles one or more skills that let Claude Code verify cryptographic
code, analyze binary artifacts with Ghidra, and audit codebases accurately and
repeatably.

## Structural rules (never violate)

- `.claude-plugin/marketplace.json` lives at the **repo root**, never inside a
  plugin.
- A plugin's `plugin.json` lives at `plugins/<name>/.claude-plugin/plugin.json`.
- Skills, commands, agents, and hooks live at the **plugin root**
  (`plugins/<name>/skills/...`), never inside `.claude-plugin/`.
- Skills auto-discover from the plugin's `skills/` directory; no extra
  declaration is needed unless a custom path is used.

Repository layout:

```
.
├── .claude-plugin/
│   └── marketplace.json          # Marketplace manifest (MUST stay at repo root)
├── plugins/                      # One directory per plugin
│   └── <plugin-name>/
│       ├── .claude-plugin/
│       │   └── plugin.json        # Plugin manifest
│       ├── skills/
│       │   └── <skill-name>/
│       │       ├── SKILL.md        # Entry point, under 500 lines
│       │       ├── references/     # Detail loaded on demand, one level deep
│       │       └── scripts/        # Optional executable helpers
│       └── README.md
├── CLAUDE.md                     # This file (Claude Code directives)
├── CONTRIBUTING.md               # Contribution guide (English)
├── CONTRIBUTING_KR.md            # Contribution guide (Korean)
├── README.md                     # English docs
├── README_KR.md                  # Korean translation
└── LICENSE
```

## Marketplace facts

- The marketplace `name` is `quant-security` (from `marketplace.json`).
- Each plugin's `source` is a repo-relative path (`./plugins/<name>`), so
  everything ships from this single repository.
- Install path for users: `/plugin marketplace add Quant-Off/skills` then
  `/plugin install <plugin-name>@quant-security`.

## When you write or change a skill

The skills this repo ships must embody a **zero-trust, air-gapped-ready**
posture. Enforce it in the content you author:

- Treat every input, boundary, and dependency as hostile until proven safe.
- A guarantee is not real until there is evidence for it: cite file:line, the
  exact instructions, or the measurement. No hand-waving.
- Prefer isolation and least privilege. Set `allowed-tools` on every skill, and
  keep audit skills read-only (`Read Grep Glob Bash`).
- Skills must not exfiltrate code or secrets to external services; they should
  work offline wherever possible.
- Findings must include a concrete attack path and a specific, actionable fix.

### Required SKILL.md shape

Every security skill in this repo follows the same template. Deviating from it
is a review failure.

1. **Frontmatter**: `name`, `description`, `allowed-tools`, `license`. The
   description is third person, names the trigger situation with a "Use when"
   clause, and states negative scope with a "Not for" clause pointing at the
   sibling skill that does cover it. Under 1,536 characters.
2. **Opening**: one or two sentences separating the mechanical step from the
   real work, and naming the skill's primary failure mode.
3. **`## When to Use`** and **`## When NOT to Use`**: concrete bullets. The
   negative section routes to the correct sibling skill.
4. **`## Rationalizations to Reject`**: a three-column table of the shortcuts
   that lead to missed or wrong findings, why each is wrong, and the required
   action. Mandatory.
5. **`## Workflow`**: numbered phases, each with an explicit exit condition, and
   a routing table pointing at the reference file for that phase.
6. **A triage phase** that treats tool and grep output as a worklist, not a
   verdict, and requires a written verdict per item. Items that cannot be traced
   are recorded as dismissed, never silently dropped.
7. **Evidence requirements**: a table of finding classes that are never valid
   without stated evidence, plus the rule that an unevidenced assertion from a
   comment or a user does not lower confidence.
8. **Severity rubric** and a fenced **report format** block.
9. **`## Limitations`**: numbered, enumerating the skill's own blind spots.
10. **`## References`**: real CWE identifiers, CVEs, and papers. No filler.

### Progressive disclosure

- Keep `SKILL.md` under 500 lines. Push detail into `references/`.
- References are **one level deep**: `SKILL.md` links to a reference file, and
  reference files do not chain to further reference files.
- Link references from a routing table so the reader loads only what the current
  phase needs.
- Ship executable helpers in `scripts/`, and have `SKILL.md` give the exact
  invocation with real flags.

## When you add or change a plugin

Follow the step list and validation in [CONTRIBUTING.md](CONTRIBUTING.md) before
finishing. Non-negotiable points:

- Bump the plugin `version` (semver) in **both** `plugin.json` and the
  marketplace entry when a skill's behavior changes.
- Update the plugin tables in **both** `README.md` and `README_KR.md` together.
- Skill and plugin names are **kebab-case** and stable (users type them).

## Editing conventions

- `CLAUDE.md` is English-only. `README.md`/`CONTRIBUTING.md` each have a Korean
  mirror (`README_KR.md`/`CONTRIBUTING_KR.md`); keep every pair in sync.
- Do not add code comments to skill helper scripts unless they state a
  non-obvious constraint.
