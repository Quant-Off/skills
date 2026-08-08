# Secrets, Memory Safety, Concurrency, and Dependencies

## Secrets management (CWE-798, CWE-532)

### Detection

```bash
# Hardcoded credentials and keys
rg -n -i "(api[_-]?key|secret|passw(or)?d|token|credential)\s*[:=]\s*[\"'][^\"']{8,}" -tcode

# Private key material and known provider formats
rg -n "BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|xox[baprs]-" -a

# Committed environment and credential files
rg --files -g '.env*' -g '*.pem' -g '*.p12' -g '*.keystore' -g 'credentials*' -g 'id_rsa*'

# History, which the working tree does not show
git log --all --diff-filter=A --name-only --format="" | sort -u | rg -i 'env|pem|key|credential'
```

### Triage

A hit is a finding when the value is a live credential for a reachable system. It
is not a finding when it is an obvious placeholder (`changeme`, `xxx`,
`example`), a test fixture with no real backend, or a public key.

The decisive question is **whether it was ever committed**. A secret removed in a
later commit is still in the history and must be rotated, not merely deleted.
Report rotation as the fix; deletion alone is insufficient and saying otherwise
is a harmful recommendation.

### Secrets in output

```bash
rg -n "log\.|logger\.|console\.log|print\(|printf|fmt\.Print|System\.out" -tcode -A1 \
  | rg -i "passw|secret|token|key|authorization|cookie"
rg -n "@Data|@ToString|derive\(Debug|__repr__|toString\(\)" -tcode
```

Authorization headers, cookies, and request bodies logged at debug level are a
disclosure finding whenever logs cross a trust boundary, which they do in every
centralized logging setup. Rate Medium normally, High when the logs are broadly
readable.

Also check: verbose error pages and stack traces in production, `debug = True`,
exposed `/debug`, `/actuator`, `/metrics`, `/.git`, and source maps shipped to
production.

### Storage and transit

- Secrets should come from a secret manager or the environment, not the repo.
- Check that TLS verification is not disabled: `verify=False`,
  `rejectUnauthorized: false`, `InsecureSkipVerify: true`,
  `ServicePointManager.ServerCertificateValidationCallback` returning true. Each
  is a High finding on a path carrying credentials or sensitive data.

```bash
rg -n "verify\s*=\s*False|rejectUnauthorized|InsecureSkipVerify|NODE_TLS_REJECT_UNAUTHORIZED|trustAllCerts" -tcode
```

## Memory safety (C, C++, unsafe Rust, cgo, FFI)

| Class | CWE | What to look for |
| --- | --- | --- |
| Buffer overflow | CWE-787, CWE-125 | `strcpy`, `strcat`, `sprintf`, `gets`, `memcpy` with an unvalidated length, manual index arithmetic |
| Off-by-one | CWE-193 | `<=` in a bound check, `n` versus `n-1` for a null terminator, `strncpy` not null-terminating |
| Use after free | CWE-416 | Pointer used after `free`; double `free`; a freed object still in a list or cache |
| Integer overflow into allocation | CWE-190 | `malloc(n * size)` without an overflow check; `int` used for a size; signed/unsigned confusion |
| Format string | CWE-134 | `printf(user_input)` rather than `printf("%s", user_input)` |
| Uninitialized memory | CWE-457 | A struct partially filled then sent or written, leaking stack or heap contents |

```bash
rg -n "\b(strcpy|strcat|sprintf|vsprintf|gets|alloca)\s*\(" -tc -tcpp
rg -n "memcpy\s*\(|memmove\s*\(" -tc -tcpp
rg -n "malloc\s*\([^)]*\*|calloc\s*\(" -tc -tcpp
rg -n "printf\s*\(\s*[a-z_]+\s*\)" -tc -tcpp
```

**Triage:** is the length attacker-controlled and unvalidated on the path to the
call? A `memcpy` with a compile-time-constant length is not a finding. Build with
`-fsanitize=address,undefined` and run the test suite if a build is available;
that turns a suspicion into evidence.

Rust: audit each `unsafe` block against its stated invariant. Flag
`from_raw_parts`, `transmute`, `get_unchecked`, and every FFI boundary. Note that
`unwrap`/`expect` on attacker-controlled input is a denial-of-service finding,
not memory unsafety.

```bash
rg -n "unsafe\s*\{|from_raw_parts|transmute|get_unchecked" -trust
```

## Concurrency (CWE-362, CWE-367)

| Pattern | Risk |
| --- | --- |
| Check-then-act on shared state | TOCTOU; see the authorization reference for the exploitable cases |
| `access()` then `open()` | Classic file TOCTOU; use `openat` with the right flags instead |
| Predictable temporary file names | Symlink attack; use `mkstemp` |
| Non-atomic counters or balances | Lost update under concurrency |
| Shared mutable state without a lock | Data race; in C and C++ this is undefined behavior, not merely a wrong answer |
| Lock ordering | Deadlock, which is a denial-of-service finding when reachable by a request |

```bash
rg -n "access\s*\(|tmpnam|mktemp\s*\(|/tmp/" -tcode
rg -n "static mut|global |threading\.|go func|std::thread::spawn" -tcode
```

## Denial of service

Report these when a normal user can trigger them:

- Unbounded allocation from a user-supplied size or count.
- Regular expressions with nested quantifiers on user input (ReDoS). Check
  `(a+)+`, `(a|a)*`, and similar shapes.
- Decompression bombs: zip, gzip, and image formats expanded without a size cap.
- Unbounded recursion on user-supplied nesting (JSON, XML, protobuf).
- Missing pagination on an endpoint that can return the whole table.
- Expensive work before authentication (password hashing on an unauthenticated
  endpoint is a two-sided tradeoff worth noting).

```bash
rg -n "\(\w*\+\)\+|\(\w*\*\)\*|\(\.\*\)\+" -tcode        # ReDoS shapes
rg -n "ZipFile|GZIPInputStream|tarfile|Image\.open|decompress" -tcode
```

## Dependencies and supply chain

```bash
# Advisory databases, whichever the ecosystem provides
npm audit --audit-level=moderate 2>/dev/null
pip-audit 2>/dev/null || safety check 2>/dev/null
cargo audit 2>/dev/null
govulncheck ./... 2>/dev/null
osv-scanner --recursive . 2>/dev/null

# Lockfiles: their presence is itself a control
rg --files -g 'package-lock.json' -g 'yarn.lock' -g 'Cargo.lock' -g 'poetry.lock' -g 'go.sum' -g 'Gemfile.lock'
```

**Triage:** a reported advisory is a finding only if the vulnerable code path is
reachable from this application. `govulncheck` performs that reachability
analysis; the other tools do not, so verify before reporting a transitive
advisory as High.

Beyond advisories, check:

- Unpinned versions (`^`, `~`, `*`, or no lockfile) in a build that ships.
- Install-time script execution (`postinstall`, `setup.py` running code).
- Dependencies fetched from a non-default registry, a Git URL, or plain HTTP.
- Typosquat-shaped names on recently added dependencies.
- CI workflows using `pull_request_target` with a checkout of untrusted code, or
  actions pinned by mutable tag rather than commit SHA.

```bash
rg -n "pull_request_target|uses:\s*\S+@(main|master|v\d+)\s*$" .github/workflows/ 2>/dev/null
rg -n "postinstall|preinstall|prepare" package.json 2>/dev/null
```

## Handoff to the crypto skills

Route to `crypto-source-audit` rather than analyzing here: weak or deprecated
primitives, static IVs and nonce reuse, non-constant-time comparison of secrets,
non-CSPRNG token generation, and any question about whether key material is
properly erased. Route compiled-artifact questions to `binary-crypto-verify`.

Note the finding in your report with a one-line summary and the handoff, so the
reader sees the full surface even though the depth lives elsewhere.
