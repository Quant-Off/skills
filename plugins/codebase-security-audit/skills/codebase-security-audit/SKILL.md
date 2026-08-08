---
name: codebase-security-audit
description: >-
  Audits a codebase, module, or single file for exploitable vulnerabilities
  across injection, authentication and authorization, secrets management, memory
  safety, deserialization, SSRF, and dependency risk, gating every candidate
  through reachability and impact review before reporting. Use when asked to
  security-audit, threat-model, or review code for vulnerabilities, when
  preparing a pre-release security pass, or when hardening a high-assurance or
  air-gapped target. Not for deep cryptographic review (use crypto-source-audit)
  and not for verifying compiled artifacts (use binary-crypto-verify).
allowed-tools: Read Grep Glob Bash
license: MIT
---

# Codebase Security Audit

Finding the dangerous sink is the mechanical step. The real work is proving an
attacker reaches it with data they control, and that no validator breaks the
chain. **A pattern match is a worklist entry, not a vulnerability**, and
reporting one as a finding is the primary failure mode of this skill.

Operate under zero trust: assume every external input is hostile and every trust
boundary is crossed. Then prove it, per finding, with a traced flow.

## When to Use

- A security audit of a repository, service, module, or single file.
- A pre-release or pre-merge security pass on a diff.
- Threat-modeling an application's attack surface.
- Triaging whether a suspected issue is real before filing it.
- Hardening review for a high-assurance, regulated, or air-gapped deployment.

## When NOT to Use

- **Cryptographic implementation review.** Constant-time behavior, zeroization,
  and primitive misuse need `crypto-source-audit`.
- **Compiled-artifact verification.** Use `binary-crypto-verify`.
- **Runtime testing.** This skill reads code. It does not fuzz, scan a live
  host, or execute exploits.
- **Pure code quality review.** Style, naming, and architecture are out of scope
  unless they create a security consequence.

## Rationalizations to Reject

| Rationalization | Why it is wrong | Required action |
| --- | --- | --- |
| "This pattern is dangerous, so it is a vulnerability." | Pattern recognition is not analysis. Most `exec` and `query` hits take trusted input. | Trace source to sink before concluding. No trace, no finding. |
| "I cannot find the sanitizer, so there is none." | Validation is often centralized in middleware, a framework hook, an ORM layer, or a base class. | Read the framework's request pipeline and the callers before reporting. |
| "This is clearly critical." | Models overrate severity and are biased toward seeing bugs. | Apply the severity rubric mechanically. Justify the rating against its criterion. |
| "The endpoint is internal, so it is safe." | Internal means undocumented, not unreachable. SSRF, a compromised pod, or a misrouted ingress reaches it. | State the required attacker position instead of dismissing the finding. |
| "There is authentication, so authorization is covered." | Authentication proves who; authorization proves whether. IDOR lives in exactly this gap. | Check ownership on every object accessed by a user-supplied identifier. |
| "It needs admin, so severity is Low." | Privilege is a precondition, not an exemption. Admin compromise is a normal step in a chain. | Rate on impact, note the precondition. |
| "The library handles that." | Libraries have unsafe defaults and unsafe modes. `yaml.load` and `pickle.loads` are library calls. | Confirm the specific call and its configuration. |
| "It is only exploitable in a weird config." | If the config ships, it is real. If it is the default, it is worse. | Check the shipped defaults and state which config is affected. |
| "I will report everything and let them filter." | An unvalidated list of grep hits destroys the credibility of the real findings. | Every reported item passes the gates below or is not reported. |
| "The tests pass, so it is fine." | Tests encode expected behavior. Attackers supply unexpected behavior. | Test coverage is not evidence of safety. |

## Workflow

### Phase 0: Map the attack surface

**Exit:** a written list of entry points, trust boundaries, and where secrets and
privileged operations live.

```bash
ast-outline digest .          # module map; or `ast-outline map <file>` for one file

# Entry points and untrusted input
rg -n "fn main|func main|def main|public static void main" -tcode
rg -n "app\.(get|post|put|patch|delete)|@(Get|Post|Put|Delete)Mapping|@app\.route|router\.(get|post)" -tcode
rg -n "argv|getenv|req\.(body|query|params|headers)|request\.(GET|POST|args|json)|Deserialize|read_to_string|recv\(" -tcode
```

Record: which inputs are authenticated, which are raw, which components cross a
privilege boundary, and where the sensitive data lives. Everything downstream is
scoped to this map. Do not audit code no untrusted input reaches.

### Phase 1: Sweep by bug class

Read the catalogue when you reach it. It carries the sink lists, the grep
patterns, and the class-specific triage questions.

| Area | Reference |
| --- | --- |
| Injection, deserialization, path traversal, SSRF, XSS, CSRF | [references/bug-classes.md](references/bug-classes.md) |
| Authentication, authorization, IDOR, session and token handling | [references/authz-and-identity.md](references/authz-and-identity.md) |
| Secrets, memory safety, concurrency, dependency and supply chain | [references/secrets-and-memory.md](references/secrets-and-memory.md) |
| Per-language sinks and idioms (Python, JS/TS, Go, Rust, Java, C/C++, PHP, Ruby) | [references/language-sinks.md](references/language-sinks.md) |

Crypto hits during this sweep (weak primitives, static IVs, `memcmp` on a MAC,
non-CSPRNG tokens) are handed to `crypto-source-audit` rather than analyzed here.

### Phase 2: Trace each candidate

For every hit, write the flow explicitly. This is the work.

```
source: POST /api/report body field `filename`   (untrusted, unauthenticated)
  -> ReportController.create():41   no validation
  -> ReportService.render():88      passed as `template_path`
  -> sink: fs.readFileSync(path.join(TEMPLATE_DIR, template_path))  render.js:88
mitigation searched: no canonicalization, no allowlist, no boundary check
```

If you cannot write the flow, you do not have a finding. Record the item as
inspected and dismissed with the reason.

### Phase 3: Gate before reporting

Every candidate passes all six gates or it is not reported. Full criteria and
worked examples are in
[references/validation-gates.md](references/validation-gates.md).

| # | Gate | Passes when |
| --- | --- | --- |
| 1 | Source is untrusted | The input crosses a trust boundary from an attacker-influenced origin |
| 2 | Reachability | A concrete request or invocation path reaches the sink |
| 3 | Attacker control | The attacker controls enough of the value to change behavior |
| 4 | No mitigation | No validator, encoder, parameterization, or authz check breaks the chain |
| 5 | Real impact | Exploitation yields RCE, privilege escalation, data disclosure, integrity loss, or denial of service |
| 6 | Devil's advocate | You attempted to refute the finding and failed |

Verdict line for each candidate: `CANDIDATE #N TRUE POSITIVE: <reason>` or
`CANDIDATE #N FALSE POSITIVE: <gate that failed>`.

### Phase 4: Report

Rank by severity, and state what you did not cover.

## Severity rubric

Rate on impact and precondition, not on how alarming the code looks. Align with
CVSS 3.1 intuition.

| Severity | Criterion |
| --- | --- |
| Critical | Unauthenticated RCE, authentication bypass, or mass exfiltration of sensitive data. No meaningful precondition. |
| High | Authenticated RCE, IDOR exposing other users' sensitive data, stored credential or key disclosure, privilege escalation to admin. |
| Medium | Stored or reflected XSS, SSRF with limited reach, CSRF on a state-changing action, weak crypto protecting live data, DoS reachable by a normal user. |
| Low | Information disclosure with no direct leverage, missing hardening header, verbose errors, defense-in-depth gaps. |
| Info | No security consequence. Hygiene only. |

Do not invent a severity between tiers. Pick the tier whose criterion the
finding meets and justify it in one sentence.

## Report format

Lead with a one-paragraph verdict on overall risk posture and a severity tally.
Then, most severe first:

```
[SEVERITY] <title>                                    confidence: confirmed|likely
  Location : path/to/file:line-line
  Class    : injection | authz | secrets | memory | deserialize | ssrf | deps | ...
  CWE      : CWE-xxx
  Flow     : untrusted source -> intermediate -> sink   (with file:line at each hop)
  Trigger  : the concrete input or request that exploits it
  Impact   : what the attacker gains, and the precondition required
  Evidence : the specific code that is wrong, quoted
  Gates    : 1-6 pass, with the one-line justification for gate 5 and gate 6
  Fix      : the specific remediation. Never "sanitize input" or "validate."
```

Close with three lists:

- **Cleared**: high-risk areas inspected and found sound, each citing the
  file:line of the control that makes it sound. No entry without that citation.
- **Dismissed**: candidates that failed a gate, with the gate number. This is
  what separates an audit from a grep dump.
- **Not covered**: out-of-scope areas, code paths you could not follow, and
  anything needing dynamic testing or credentials you did not have. State this
  plainly so the gap is not mistaken for a clean bill of health.

## Limitations

1. **Static reading only.** No execution, no fuzzing, no live testing. Findings
   are analytical and unproven at runtime.
2. **No interprocedural data flow engine.** Traces are done by reading code.
   Dynamic dispatch, reflection, function pointers, message queues, and RPC
   boundaries will break a trace. State where.
3. **Framework behavior is assumed, not verified.** Where a mitigation is claimed
   to live in framework middleware, that middleware is not audited.
4. **Dependencies are checked by version, not by review.** A clean advisory
   database says nothing about an unreported vulnerability.
5. **Configuration and deployment are usually out of tree.** Infrastructure,
   secrets management, and network policy shape real exploitability and are not
   visible here.
6. **Absence of findings is not absence of vulnerabilities.** Say so in the
   report.

## References

- CWE Top 25 Most Dangerous Software Weaknesses; OWASP Top 10 (web) and OWASP
  API Security Top 10.
- CVSS 3.1 specification for severity calibration.
- CWE-89 (SQLi), CWE-78 (OS command injection), CWE-79 (XSS), CWE-22 (path
  traversal), CWE-502 (unsafe deserialization), CWE-918 (SSRF), CWE-639 (IDOR),
  CWE-798 (hardcoded credentials), CWE-416 (use after free), CWE-190 (integer
  overflow), CWE-362 (race condition).
