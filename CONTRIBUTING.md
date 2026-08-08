# Contributing

<div align="center">

English | [한국어](CONTRIBUTING_KR.md)
</div>

Thanks for helping improve the Quant-Off Security Skills marketplace. This guide covers how to add or change a plugin.

## Ground rules

- Every skill follows a zero-trust, air-gapped-ready posture: work offline where possible, never exfiltrate code or secrets, and back every finding with concrete evidence and a specific fix.
- Skill and plugin names are kebab-case and stable, since users type them.
- Keep each skill scoped to one clear job, and cross-reference sibling skills instead of duplicating them.

## Skill template

Security skills here share one structure. Copy an existing skill rather than starting from scratch, and keep these elements:

- A third-person `description` with a "Use when" trigger clause and a "Not for" clause routing to the sibling skill that covers the excluded case.
- `## When to Use` paired with `## When NOT to Use`.
- A `## Rationalizations to Reject` table listing the shortcuts that produce wrong or missed findings, why each is wrong, and the action it requires instead.
- Numbered workflow phases, each with an explicit exit condition.
- A triage phase that treats grep and tool output as a worklist rather than a verdict, and requires a written verdict per item. Items that cannot be traced are recorded as dismissed, never silently dropped.
- Evidence requirements, a severity rubric, and a fenced report format block.
- A numbered `## Limitations` section naming the skill's own blind spots.
- Real CWE, CVE, and paper citations under `## References`.

Keep `SKILL.md` under 500 lines and move detail into `references/`, linked from a routing table so the reader loads only what the current phase needs. References are one level deep: `SKILL.md` links to them, and they do not chain to each other. Executable helpers go in `scripts/`, with the exact invocation documented in `SKILL.md`.

## Add a new plugin

1. Create `plugins/<name>/.claude-plugin/plugin.json`. `name` is the only required field; also set `description`, `version`, `author`, `license`, and `keywords`.
2. Add the skill at `plugins/<name>/skills/<skill-name>/SKILL.md` following the template above. Set `allowed-tools`, and keep audit skills read-only (`Read Grep Glob Bash`). Keep `description` under the 1,536-character limit and make it trigger-friendly, saying when to use the skill.
3. Register the plugin in `.claude-plugin/marketplace.json` under `plugins` with `name`, `source: ./plugins/<name>`, `description`, `version`, `author`, `license`, `category`, and `keywords`.
4. Add a short `plugins/<name>/README.md`.
5. Update the plugin tables in both `README.md` and `README_KR.md`.

## Change an existing plugin

- When a skill's behavior changes, bump the `version` (semver) in both `plugin.json` and its marketplace entry.
- Keep the English and Korean docs in sync.

## Validate before opening a PR

```bash
# JSON validity
find . -name '*.json' -path '*.claude-plugin*' -print -exec python3 -m json.tool {} /dev/null \;

# SKILL.md frontmatter present
find plugins -name SKILL.md -exec head -n1 {} \;

# SKILL.md length budget (warn above 500 lines)
find plugins -name SKILL.md -exec wc -l {} \;

# Optional: install locally and smoke-test
/plugin marketplace add ./
/plugin install <plugin-name>@quant-security
```

## Submitting

Open a pull request against `main` with a short description of what the plugin or skill does and why. Confirm the validation above passes.
