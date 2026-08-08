# Injection, Deserialization, and Request-Forgery Classes

Sink catalogues with detection patterns and the triage question that separates a
finding from noise.

## SQL and NoSQL injection (CWE-89, CWE-943)

**Sinks:** any query built by string concatenation, interpolation, or formatting.

```bash
rg -n "SELECT .*(\+|\|\|)|f\"SELECT|format!\(.*SELECT|\.raw\(|execute\(.*%|query\(.*\$\{" -tcode
rg -n "\.where\(.*\+|\.filter\(.*format|Sequel\.lit|literal\(" -tcode
```

**Triage:** is the interpolated value attacker-influenced, and is it inside a
string literal or an identifier position? Parameterization solves values; it does
not solve identifiers. A user-supplied `ORDER BY` column or table name cannot be
bound and must be checked against an allowlist. Report those separately.

NoSQL: operator injection is the analogue. A query built from a raw JSON body
lets an attacker submit `{"$ne": null}` or `{"$gt": ""}` where a scalar was
expected. Check that values are cast to the expected type before use.

**False positives:** ORM query builders that bind parameters; queries whose only
interpolation is a compile-time constant or an internal enum.

## OS command injection (CWE-78)

**Sinks:**

```bash
rg -n "system\(|popen\(|exec[lv]?p?\(|subprocess\..*shell\s*=\s*True|os\.system|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec|Command::new|`" -tcode
```

**Triage:** does the invocation go through a shell? `subprocess.run([...])` with a
list argument and no `shell=True` does not, and user input in `argv[1]` is
generally safe. `subprocess.run(f"convert {name}", shell=True)` does, and is a
finding. `child_process.execFile` is safe where `child_process.exec` is not.

Watch for argument injection even without a shell: a user-controlled value
beginning with `-` becomes a flag. `tar`, `curl`, `ffmpeg`, and `git` all have
flags that read or write arbitrary files. Terminate options with `--` or validate
the value does not start with a dash.

## Path traversal (CWE-22)

**Sinks:** file open, read, write, delete, and archive extraction where a
component of the path is user-supplied.

```bash
rg -n "open\(|readFile|read_to_string|File::open|new File\(|fs\.(read|write|unlink)|Path\.Combine|os\.path\.join" -tcode
```

**Triage:** is there canonicalization followed by a prefix check? The correct
pattern resolves symlinks and `..` first, then verifies containment:

```python
base = Path(TEMPLATE_DIR).resolve()
target = (base / user_input).resolve()
if not target.is_relative_to(base):
    raise Forbidden
```

`os.path.join(base, user)` alone is not a control: an absolute `user` value
discards `base` entirely in Python, and `..` traverses upward. Stripping `../`
once is bypassable with `....//`. Report both.

Archive extraction is the same class (zip slip): entry names inside a user-
supplied archive must be validated before joining.

## Unsafe deserialization (CWE-502)

**Sinks by language:**

| Language | Dangerous | Safe alternative |
| --- | --- | --- |
| Python | `pickle.loads`, `yaml.load` without `SafeLoader`, `jsonpickle`, `dill`, `shelve` | `json.loads`, `yaml.safe_load` |
| Java | `ObjectInputStream.readObject`, XStream default, SnakeYAML default constructor | JSON with an explicit schema |
| Ruby | `Marshal.load`, `YAML.load` (pre-3.1 default) | `JSON.parse`, `YAML.safe_load` |
| PHP | `unserialize` on user input | `json_decode` |
| .NET | `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter` | `System.Text.Json` |
| Node | `node-serialize`, `serialize-javascript` eval paths, `vm.runInNewContext` | `JSON.parse` |

```bash
rg -n "pickle\.loads|yaml\.load\(|Marshal\.load|unserialize\(|readObject\(|BinaryFormatter|node-serialize" -tcode
```

**Triage:** does attacker-controlled bytes reach the call? If yes this is
generally Critical (RCE) with no further qualification needed, because gadget
chains exist for all of the above in any nontrivial dependency tree. Confirm the
data path, then rate it Critical.

## Server-side request forgery (CWE-918)

**Sinks:** any outbound HTTP, DNS, or socket call whose destination is derived
from user input. Webhooks, URL previews, image fetchers, PDF renderers, and
"import from URL" features are the usual carriers.

```bash
rg -n "requests\.(get|post)|urllib|http\.Get|fetch\(|axios\.|HttpClient|curl_exec|Net::HTTP" -tcode
```

**Triage:** is there a destination allowlist? A denylist of `127.0.0.1` and
`localhost` is not one, and should be reported as insufficient. Bypasses to check
for: decimal and octal IP encodings, `0.0.0.0`, IPv6 loopback and mapped forms,
DNS rebinding, redirects to an internal host after an allowed first hop, and
alternate schemes (`file://`, `gopher://`, `dict://`).

Impact depends on what the internal network exposes. Cloud metadata endpoints
(`169.254.169.254`) turn SSRF into credential theft, which is Critical. Name the
reachable target in the impact statement rather than asserting SSRF generically.

## Cross-site scripting (CWE-79)

**Sinks:** user data reaching HTML, attribute, JavaScript, or URL contexts
without contextual encoding.

```bash
rg -n "dangerouslySetInnerHTML|innerHTML\s*=|v-html|\|safe\b|raw\(|html_safe|Html\.Raw|document\.write" -tcode
```

**Triage:** modern template engines auto-escape, so the finding almost always
requires an escape hatch. Report the escape hatch, not the variable. Then check
the context: HTML-escaping is insufficient inside a `<script>` block, inside an
event handler attribute, or in a `href="javascript:"` position.

DOM XSS is a separate trace: source is `location`, `document.referrer`,
`postMessage` data, or `window.name`; sink is `eval`, `innerHTML`,
`setTimeout(string)`, or `Function()`.

**False positives:** escaped output in a normal HTML text context; data rendered
into a JSON script block with correct encoding; content already passed through a
vetted sanitizer such as DOMPurify with a safe configuration.

## Cross-site request forgery (CWE-352)

**Triage:** does the state-changing endpoint require a token the attacker cannot
predict, or a `SameSite` cookie policy that prevents cross-origin submission?
Check the framework default: many enable CSRF protection globally and disable it
per-route, so search for the exemption.

```bash
rg -n "csrf_exempt|@CrossOrigin|csrf:\s*false|SameSite\s*=\s*None|skipCSRF" -tcode
```

A JSON-only API authenticated by a bearer token in a header is not CSRF-able. A
JSON API authenticated by a cookie usually is, if the endpoint accepts a content
type that a form can produce.

## XML external entities (CWE-611)

```bash
rg -n "DocumentBuilderFactory|SAXParser|XMLReader|etree\.parse|libxml|SimpleXML|XmlDocument" -tcode
```

**Triage:** is external entity resolution disabled? Defaults vary by parser and
version, and several ecosystems fixed their defaults in recent releases, so check
the version. Impact is file read and SSRF; with `xinclude` or parameter entities
it becomes out-of-band exfiltration.

## Template injection (CWE-1336)

User input reaching a template *compiler* rather than a template *variable*.

```bash
rg -n "Template\(|render_template_string|from_string|Twig.*createTemplate|Velocity|Freemarker|Handlebars\.compile" -tcode
```

**Triage:** the distinction is whether the user controls the template text or
only the data bound into it. The former is typically RCE in Jinja2, Twig, Velocity,
and Freemarker.

## Open redirect and header injection

```bash
rg -n "redirect\(|Location:|sendRedirect|res\.redirect|header\(" -tcode
```

**Triage:** is the redirect target validated against an allowlist of paths or
hosts? A relative-path-only check is a valid control; a "starts with our domain"
check is bypassable with `https://evil.com/?x=https://ours.com` or
`https://ours.com.evil.com`. Rate Low on its own, but note it as a chain
component: open redirect on an OAuth `redirect_uri` is authorization-code theft
and rates High or Critical in that context.

Header injection: a newline in a user value reaching a response header splits the
response. Most modern frameworks reject this; confirm the version.

## Mass assignment (CWE-915)

An object built directly from a request body lets the attacker set fields the
form never exposed: `is_admin`, `role`, `verified`, `balance`, `owner_id`.

```bash
rg -n "Object\.assign\(|\.\.\.req\.body|update\(\*\*|new Model\(req\.body|ModelMapper|BeanUtils\.copyProperties" -tcode
```

**Triage:** is there an explicit allowlist of assignable fields (`fillable`,
`permit`, a DTO, a schema)? A denylist is bypassable as soon as a new sensitive
field is added.
