# Per-Language Sinks and Idioms

Language-specific dangerous calls, the framework behavior that usually mitigates
them, and the false positives each ecosystem generates. Read the section for the
target language before triaging its hits.

## Python

| Sink | Risk | Safe form |
| --- | --- | --- |
| `eval`, `exec`, `compile` | RCE | Do not pass user input |
| `pickle.loads`, `dill`, `shelve` | RCE | `json.loads` |
| `yaml.load(s)` | RCE | `yaml.safe_load(s)` |
| `subprocess(..., shell=True)`, `os.system` | Command injection | List argv, no shell |
| `os.path.join` with user input | Traversal | `Path.resolve` plus containment check |
| `.raw()`, `.extra()`, cursor `execute` with `%` | SQLi | Bound parameters |
| `render_template_string` | SSTI, RCE | `render_template` with a fixed file |
| `flask.send_file` with user path | Traversal | `send_from_directory` plus validation |
| `xml.etree`, `lxml` defaults | XXE | `defusedxml` |
| `assert` for a security check | Removed under `-O` | Explicit `if` plus raise |

```bash
rg -n "\beval\(|\bexec\(|pickle\.loads|yaml\.load\(|shell\s*=\s*True|render_template_string|\.extra\(|\.raw\(" -tpy
rg -n "^\s*assert " -tpy
```

**Mitigations that count:** Django ORM parameterization; Django template
auto-escaping; `pydantic` models at the boundary; `SafeLoader`.
**False positives:** `eval` in a REPL tool or a test; `subprocess` with a literal
command; f-strings in a query built entirely from constants.

## JavaScript and TypeScript (Node)

| Sink | Risk | Safe form |
| --- | --- | --- |
| `eval`, `new Function`, `vm.runInThisContext` | RCE | Do not pass user input |
| `child_process.exec`, `execSync` | Command injection | `execFile` with an argv array |
| `innerHTML`, `dangerouslySetInnerHTML`, `document.write` | XSS | Text nodes, or DOMPurify |
| `require(userInput)`, dynamic `import()` | RCE | Static allowlist |
| `JSON.parse` into `Object.assign` merge | Prototype pollution | `Object.create(null)`, or a schema |
| `res.sendFile`, `path.join` with user input | Traversal | `path.resolve` plus prefix check |
| Template literals in SQL | SQLi | Parameterized driver calls |
| `serialize-javascript`, `node-serialize` | RCE | `JSON.stringify` |

```bash
rg -n "\beval\(|new Function\(|child_process\.exec\(|innerHTML\s*=|dangerouslySetInnerHTML|__proto__|constructor\[.prototype.\]" -tjs -tts
```

**Prototype pollution** deserves its own pass: a recursive merge of user JSON
that copies `__proto__`, `constructor`, or `prototype` keys pollutes
`Object.prototype`, and the impact depends on the gadget it reaches (RCE in Node
when a polluted property feeds `child_process` options, XSS in a browser).
Check `lodash.merge` versions, hand-written deep merges, and query-string
parsers.

**False positives:** React and Vue auto-escape interpolated values; Express
`res.json` does not create XSS; `eval` inside a bundler or dev tooling path.

## Go

| Sink | Risk | Safe form |
| --- | --- | --- |
| `fmt.Sprintf` into a SQL string | SQLi | `db.Query` with placeholders |
| `exec.Command("sh", "-c", s)` | Command injection | `exec.Command(bin, args...)` |
| `text/template` for HTML | XSS | `html/template` |
| `filepath.Join` with user input | Traversal | `filepath.Clean` plus prefix check |
| `encoding/gob` on untrusted data | Type confusion, DoS | JSON with a schema |
| `math/rand` for tokens | Predictable secrets | `crypto/rand` |
| Unchecked error returns | Logic bypass | Handle every error |

```bash
rg -n "fmt\.Sprintf\(.*(SELECT|INSERT|UPDATE|DELETE)|exec\.Command\(\"(sh|bash)\"|text/template|math/rand" -tgo
rg -n "_\s*[,=]\s*\w+\.(Verify|Validate|Check|Auth)" -tgo   # discarded security errors
```

**Idiom-specific:** an ignored error from a verification function is a real
bypass and is easy to miss because it looks like normal Go. Also check that
`defer` cleanup cannot be skipped by `os.Exit`.

## Rust

| Sink | Risk | Notes |
| --- | --- | --- |
| `unsafe` blocks | Memory unsafety | Audit each against its invariant |
| `unwrap`, `expect`, indexing, `panic!` on user input | DoS | Reachable panic in a request handler |
| Integer arithmetic in release | Silent wraparound | `checked_*` or `saturating_*` |
| `Command::new` with a shell | Command injection | Pass args, not a shell string |
| `serde` with `deny_unknown_fields` absent | Mass assignment | Add the attribute |
| `format!` into SQL | SQLi | `sqlx` bound parameters |

```bash
rg -n "unsafe\s*\{|\.unwrap\(\)|\.expect\(|from_raw_parts|transmute" -trust
```

**False positives:** `unwrap` on a value the type system guarantees (a literal
parse, a lock in single-threaded code). Read the surrounding context before
reporting; a blanket `unwrap` report is noise.

## Java and Kotlin

| Sink | Risk | Safe form |
| --- | --- | --- |
| `ObjectInputStream.readObject` | RCE | JSON with a schema |
| `Runtime.exec`, `ProcessBuilder` with a shell | Command injection | argv array |
| String-built JPQL, HQL, or JDBC SQL | SQLi | `PreparedStatement`, named parameters |
| `DocumentBuilderFactory` defaults | XXE | Disable DTDs and external entities |
| `Class.forName`, reflection on user input | RCE | Allowlist |
| Spring EL, SpEL from user input | RCE | Do not evaluate user expressions |
| `new File(userPath)` | Traversal | Canonicalize plus prefix check |
| `@CrossOrigin("*")` with credentials | CORS bypass | Explicit origins |

```bash
rg -n "readObject\(|Runtime\.getRuntime\(\)\.exec|createQuery\(.*\+|DocumentBuilderFactory|Class\.forName\(|SpelExpressionParser" -tjava
rg -n "@CrossOrigin|@PreAuthorize|@Secured|permitAll" -tjava
```

**Mitigations that count:** Spring Security method-level annotations that are
actually enabled; JPA parameter binding; Thymeleaf and JSP escaping in the
default context.

## C and C++

Covered in depth by the memory-safety section of the secrets and memory
reference. Priority sinks:

```bash
rg -n "\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|alloca|system|popen)\s*\(" -tc -tcpp
rg -n "memcpy|memmove|strncpy|snprintf" -tc -tcpp     # check the length argument
```

**Build hardening worth reporting when absent:** `-fstack-protector-strong`,
`-D_FORTIFY_SOURCE=2`, `-Wformat-security`, RELRO, PIE, and NX. Their absence is
Low on its own and raises the severity of an adjacent memory finding.

## PHP

| Sink | Risk |
| --- | --- |
| `unserialize` on user input | RCE via POP chain |
| `eval`, `assert` with a string, `preg_replace` with `/e` | RCE |
| `include`, `require` with user input | Local and remote file inclusion |
| `system`, `exec`, `shell_exec`, backticks | Command injection |
| `extract($_REQUEST)` | Variable overwrite |
| `==` on hashes | Type juggling; `"0e123" == "0e456"` is true |
| `$_REQUEST` | Ambiguous source, parameter pollution |

```bash
rg -n "unserialize\(|eval\(|\binclude\s*\(|\brequire\s*\(|shell_exec|extract\(|\\\$_REQUEST" -tphp
rg -n "==\s*\\\$|strcmp\(.*\)\s*==" -tphp
```

Use `===` and `hash_equals` for any comparison involving a secret or a hash.

## Ruby

| Sink | Risk |
| --- | --- |
| `Marshal.load`, `YAML.load` (pre-3.1) | RCE |
| `eval`, `instance_eval`, `send` with user input | RCE |
| `system`, backticks, `%x{}` | Command injection |
| `where("... #{param}")`, `find_by_sql` | SQLi |
| `render inline:`, `render text:` with user input | SSTI, XSS |
| `permit!` or missing strong parameters | Mass assignment |
| `constantize`, `safe_constantize` on user input | RCE |

```bash
rg -n "Marshal\.load|YAML\.load\(|\beval\(|\.send\(|%x\{|find_by_sql|where\(\"[^\"]*#\{|permit!|constantize" -trb
```

Rails mitigations that count: strong parameters with an explicit permit list;
ERB auto-escaping (so report `html_safe` and `raw`, not the variable); ActiveRecord
parameterization.

## Framework mitigation reference

Before reporting, check whether the framework already handles it. Reporting a
mitigated issue is a gate-4 failure.

| Framework | Auto-escapes output | CSRF default | ORM parameterizes |
| --- | --- | --- | --- |
| Django | Yes | Enabled globally | Yes |
| Flask + Jinja2 | Yes | Only with Flask-WTF | Depends on the ORM |
| Rails | Yes | Enabled globally | Yes |
| Spring Boot + Thymeleaf | Yes | Enabled with Spring Security | Yes with JPA binding |
| Express | No | None by default | No |
| React | Yes for children | Not applicable | Not applicable |
| Laravel | Yes with `{{ }}` | Enabled via middleware | Yes with Eloquent |

Express and raw Node are the common cases where nothing is on by default, so
findings there are more often real.
