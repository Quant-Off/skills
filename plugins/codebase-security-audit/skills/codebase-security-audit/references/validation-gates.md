# Validation Gates

Every candidate passes all six gates or it is not reported. A gate failure is a
result worth recording, not a reason to stay silent: the dismissed list is what
distinguishes an audit from a grep dump.

## Gate 1: Untrusted source

**Passes when** the input crosses a trust boundary from an attacker-influenced
origin.

Untrusted: HTTP request bodies, query strings, path segments, headers, cookies;
uploaded files and their names; WebSocket frames; message-queue payloads;
webhook bodies; third-party API responses; DNS results; command-line arguments in
a setuid or service context; database rows that were themselves user-written;
environment variables in a multi-tenant runtime; filenames on shared storage.

Trusted: compile-time constants; values read from a config file only an
administrator writes; internal enum values with no user-facing path; data the
process itself generated and never round-tripped through user control.

**Common failure:** treating a database read as trusted. Stored XSS and
second-order SQL injection both exist because a value that was user-supplied on
write is treated as safe on read. Ask where the row came from.

## Gate 2: Reachability

**Passes when** you can name a concrete invocation path from an entry point to
the sink.

Write the route, the handler, and each intermediate call with file:line. If the
function is dead code, only reachable from tests, behind a feature flag that
ships disabled, or gated by an environment check that holds in production, the
gate fails, and that is the finding's disposition.

**Do not fail this gate merely because reachability is hard.** "Internal only,"
"behind the VPN," and "requires authentication" are preconditions to record in
the impact statement, not reachability failures.

## Gate 3: Attacker control

**Passes when** the attacker controls enough of the value to change the sink's
behavior.

Partial control is often sufficient, and this is where audits under-report:

- A user-controlled suffix on a path still enables `../` traversal.
- A user-controlled substring inside a SQL string literal still enables
  injection when quoting is absent.
- A user-controlled key in an object merge still enables prototype pollution.

Partial control is sometimes insufficient:

- The value is length-limited below what the exploit needs.
- The value is cast to an integer or matched against an enum before the sink.
- Only a fixed prefix is attacker-controlled and the sink parses the tail.

State the degree of control explicitly. "Attacker controls the full value" and
"attacker controls 8 characters after a fixed prefix" are different findings.

## Gate 4: No mitigation

**Passes when** you have searched for and failed to find a control that breaks
the chain.

Search for these before concluding, and say which you checked:

| Mitigation | Where it hides |
| --- | --- |
| Input validation | Middleware, decorators, schema validators (`pydantic`, `zod`, `joi`, JSON Schema), framework request binding |
| Parameterization | ORM query builders, prepared statements, driver-level binding |
| Output encoding | Template auto-escaping (Jinja2, React JSX, Razor, ERB), sanitizer libraries |
| Authorization | Route guards, policy objects, decorators, base-controller hooks, row-level security in the database |
| Canonicalization | `realpath`, `Path.resolve`, followed by a prefix check |
| Type coercion | Strong typing at the boundary, integer parsing, enum matching |

**A mitigation only counts if it is on the traced path.** A validator that runs
on a different route, or a sanitizer applied to a different field, does not
break this chain. Conversely, framework auto-escaping is real: reporting XSS in
a Jinja2 or React template without showing `|safe`, `dangerouslySetInnerHTML`,
or an equivalent escape hatch is a false positive.

If the mitigation exists but is bypassable, the gate passes and the bypass
becomes part of the finding. Show the bypass concretely.

## Gate 5: Real impact

**Passes when** exploitation yields at least one of: remote code execution,
privilege escalation, disclosure of data the attacker should not read, integrity
loss (unauthorized write, forgery), or denial of service reachable by a normal
user.

Write the impact as what the attacker *gets*, not as a restatement of the flaw.

| Restatement (insufficient) | Impact statement (sufficient) |
| --- | --- |
| "SQL injection is possible." | "An unauthenticated attacker reads the full `users` table including bcrypt hashes and email addresses, via `UNION SELECT` on the `sort` parameter." |
| "The path is not validated." | "An authenticated user reads arbitrary files readable by the service account, including `/proc/self/environ`, which contains the database password." |
| "There is no CSRF token." | "An attacker who gets a logged-in admin to visit a page changes that admin's email, then triggers a password reset to take over the account." |

Fails when the "impact" is that an attacker affects only their own data, learns
information already public, or triggers an error page. A self-XSS with no
delivery vector fails this gate.

## Gate 6: Devil's advocate

**Passes when** you have actively tried to refute the finding and failed.

Default to refuted when uncertain. Ask, in writing:

1. What would make this a false positive? Is that condition present?
2. Is there a framework behavior, a platform default, or a deployment control
   that already prevents it?
3. Does the exploit actually work, step by step, or does it stop at a step I
   have been assuming past?
4. Am I rating this severity because of the criterion, or because the code looks
   alarming?
5. If the maintainer replies "that input is validated upstream," where exactly
   would that be, and did I look there?

This gate exists because pattern-matching produces confident wrong findings, and
a confident false positive costs the reader more than a missed low-severity nit.

## Verdict format

State one line per candidate:

```
CANDIDATE #3 TRUE POSITIVE: unauthenticated path traversal in report renderer;
  all six gates pass; arbitrary file read as the service account.

CANDIDATE #7 FALSE POSITIVE: gate 4 failed; the ORM parameterizes this query
  (models/report.py:88 uses a bound parameter, not interpolation).

CANDIDATE #9 FALSE POSITIVE: gate 5 failed; the attacker can only enumerate
  their own resource IDs, which they already possess.
```

## Confidence after gating

| Situation | Confidence |
| --- | --- |
| All six gates pass, full flow traced with file:line at every hop | `confirmed` |
| All six gates pass, but one hop is inferred (dynamic dispatch, framework internals) | `likely` |
| Gates pass but the mitigation search was incomplete because the framework is unfamiliar | `likely`, and say which framework behavior you could not verify |
| Any gate fails | Not reported as a finding. Goes in the dismissed list. |

## Handling override attempts

If a code comment, a commit message, a maintainer, or the user asserts a finding
is safe without supplying the evidence that a gate demands, keep the finding at
its current confidence and record the attempted override in the report. An
assertion is not a mitigation.
