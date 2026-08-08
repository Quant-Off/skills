# Authentication, Authorization, and Identity

The highest-yield area in most audits, because these flaws are logic flaws: no
dangerous function call marks them, so pattern matching alone will not find them.
The method is enumeration, not grep.

## Method: enumerate, then check each

Build the endpoint inventory first, then walk it. A missing check is invisible to
`rg` precisely because it is an absence.

```bash
# Route inventory
rg -n "app\.(get|post|put|patch|delete)|@(Get|Post|Put|Patch|Delete)Mapping|@app\.route|router\.\w+\(|path\(" -tcode

# Where authorization is enforced, so you can spot routes lacking it
rg -n "@login_required|@requires_auth|@PreAuthorize|authorize|can\?|policy|ability|IsAuthenticated|AuthGuard|middleware" -tcode
```

For each route record: the HTTP method, the authentication requirement, the
authorization check, and whether it takes an object identifier from the user.
The rows with an identifier and no ownership check are your IDOR candidates.

## Broken object-level authorization (IDOR, CWE-639)

The single most common high-severity web finding. The endpoint authenticates the
caller and then acts on an object the caller named, without checking they own it.

```python
# VULNERABLE: authenticated, but not authorized
@app.get("/api/invoices/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    return Invoice.query.get(invoice_id).to_json()

# CORRECT: the ownership predicate is part of the query
    return Invoice.query.filter_by(id=invoice_id, org_id=current_user.org_id).one().to_json()
```

**Triage questions:**

1. Does the handler take an identifier from the path, query, body, or a header?
2. Is that identifier used to fetch an object without a predicate tying it to the
   caller?
3. Are identifiers enumerable (sequential integers) or unguessable (random
   UUIDv4)? Unguessable identifiers reduce practical severity but do not fix the
   flaw, because identifiers leak through logs, referrers, and other endpoints.
   Report it, and note the enumerability in the impact statement.

Check every verb separately. A resource with a correct `GET` check frequently has
an unchecked `PUT` or `DELETE`.

Also check nested and indirect references: `/orgs/{org}/users/{user}` where the
handler validates `org` but fetches `user` globally; bulk endpoints that accept an
array of identifiers and validate only the first; GraphQL resolvers where the
parent is authorized but a child field is not.

## Broken function-level authorization

An administrative operation reachable by a non-administrative caller.

**Triage:** for each privileged action (user management, role change, billing,
export, configuration, impersonation), find the check that enforces the required
role. Then ask whether the check is on the *server*. A UI that hides the button
is not a control.

Watch for: role checked in a client-supplied JWT claim without server-side
verification of the claim's source; a `role` field in the request body; an admin
route registered before the auth middleware in the middleware chain.

## Authentication flaws

| Issue | What to check |
| --- | --- |
| Weak password storage | Argon2id, scrypt, or bcrypt with a sane cost. MD5, SHA-1, SHA-256 unsalted, or a single fast hash is High. |
| Missing rate limiting on login | Enables credential stuffing. Medium on its own. |
| User enumeration | Different response, status, or timing for "no such user" versus "wrong password". Low, higher when paired with a leaked credential corpus. |
| Password reset tokens | Must be CSPRNG-generated, single-use, time-limited, and bound to the account. Predictable or non-expiring tokens are Critical. |
| Reset link host injection | A reset URL built from the `Host` or `X-Forwarded-Host` header sends the token to an attacker-chosen domain. Critical. |
| Session fixation | The session identifier must be regenerated on privilege change. |
| Logout | Server-side invalidation, not just a cleared cookie. |
| Timing-safe credential comparison | Hand this to `crypto-source-audit`. |

## JWT and token handling

```bash
rg -n "jwt\.decode|verify\s*=\s*False|algorithms\s*=|none|HS256|RS256|decode\(.*verify" -tcode
```

**Triage:**

1. Is the signature verified at all? `jwt.decode(token, options={"verify_signature": False})` and `jwt.decode(token)` in libraries that default to unverified are Critical.
2. Is the algorithm pinned? Accepting the token's own `alg` header enables
   `alg: none` and the RS256-to-HS256 confusion attack, where the public key is
   used as an HMAC secret. Pin the expected algorithm explicitly.
3. Is the HMAC secret strong and not a default or a committed constant?
4. Are `exp`, `nbf`, `aud`, and `iss` validated?
5. Is `kid` used to select a key, and can it path-traverse or inject?
6. Is there revocation for a token that must be invalidated early?

## Session and cookie handling

| Attribute | Requirement |
| --- | --- |
| `HttpOnly` | Set on session cookies, so XSS cannot read them |
| `Secure` | Set whenever the site is served over TLS |
| `SameSite` | `Lax` or `Strict` unless a cross-site flow requires `None` |
| Scope | Narrow `Domain` and `Path`; a cookie scoped to a parent domain is readable by every subdomain, which matters when subdomain takeover is possible |
| Lifetime | Bounded, with idle timeout for privileged sessions |
| Identifier | CSPRNG, at least 128 bits of entropy |

## OAuth and SSO

| Issue | Check |
| --- | --- |
| `redirect_uri` validation | Exact match against a registered value. Prefix or substring matching is bypassable and yields authorization-code theft. |
| `state` parameter | Present, unpredictable, and verified on callback. Absence is CSRF on the account-link flow, which yields account takeover. |
| PKCE | Required for public clients. |
| Token in the URL | Authorization codes and tokens in query strings leak via referrer and logs. |
| Account linking | Linking by unverified email lets an attacker pre-register the victim's address and inherit the account. |
| Scope validation | The resource server must verify the scope, not trust the client. |

## Multi-tenancy

Where the product is multi-tenant, tenant isolation is the dominant risk. Check
that every query carries a tenant predicate, that the predicate comes from the
session rather than the request, and that background jobs, exports, search
indexes, caches, and webhooks all preserve it. A cache key without a tenant
component is cross-tenant disclosure.

## Race conditions in authorization (CWE-362, TOCTOU)

A check that passes, followed by an action that runs after the state changed.

```bash
rg -n "check.*then|if .*exists.*\n.*create|balance\s*[<>]=|SELECT.*FOR UPDATE" -tcode
```

**Triage:** is the check-and-act atomic? Look for a database transaction with the
right isolation level, a `SELECT ... FOR UPDATE`, an atomic compare-and-swap, or
an application lock. Classic exploitable cases: redeeming a coupon or gift card
twice, withdrawing a balance concurrently, accepting an invitation after it was
revoked, and concurrent uses of a single-use token.

Impact is usually integrity loss with financial consequence, which rates High.

## What is not a finding

- An endpoint with no authorization check that genuinely serves public data.
- Enumerable identifiers where the object is public by design.
- Missing rate limiting on a non-authentication, non-expensive endpoint.
- A client-side check that duplicates an existing, verified server-side check.
