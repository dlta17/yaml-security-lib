# Usage Guide — yaml-security-lib

Practical recipes for the safe YAML parser, the streaming engine, schema
validation, the linter / CLI, and troubleshooting. For the full API reference
see the [README](../README.md); for how the library is built internally see
[ARCHITECTURE.md](ARCHITECTURE.md).

> Every rejection message quoted in this guide was captured from a real run;
> the numbers depend on the active limits.

---

## 1. Install & import

```bash
npm install yaml-security-lib
```

No runtime dependencies. Node.js ≥ 16 (CI-tested on 16, 18, 20, 22, 24), all modern
browsers.

| Style | Example |
|-------|---------|
| ESM | `import { YamlSecurity } from 'yaml-security-lib'` |
| CommonJS | `const { YamlSecurity } = require('yaml-security-lib')` |
| Lean subpaths | `import { YamlSecurity } from 'yaml-security-lib/core'` |
| Validator only | `import { s, validate } from 'yaml-security-lib/validate'` |
| Linter only | `import { lint } from 'yaml-security-lib/lint'` |
| Browser `<script>` | `dist/yaml-security.min.js` → global `YamlSecurity` |
| Browser ESM | `dist/yaml-security.mjs` |

`core` / `validate` / `lint` are standalone bundles that skip the parts you do
not use (see README § Lean builds for sizes). TypeScript declarations ship for
the main entry and every subpath.

---

## 2. Two API styles — pick the safe one

| API | Behavior | Use it when |
|-----|----------|-------------|
| `new YamlSecurity().parse(yaml)` | **Never throws.** Returns `{ ok, result }` or `{ ok, error }` | Any input you did not write yourself |
| `validateYaml(yaml, spec)` | Never throws. Returns `{ ok, value, errors }` | Parse + structured schema error report |
| `parse(yaml)` (low-level) | **Throws** `YAMLException` on bad input | You are sure the YAML is valid, or you want `try/catch` |
| `lint(yaml)` | Never throws for content. Returns `{ valid, issues, errors, warnings }` | Inspect a string for style/security issues without needing the value |

Rule of thumb: **for untrusted input, always use the `YamlSecurity` class.**

---

## 3. Recipes

### 3.1 Parse untrusted config safely

```js
import { YamlSecurity } from 'yaml-security-lib'

const parser = new YamlSecurity()
const result = parser.parse(userSuppliedYaml)

if (!result.ok) {
  console.error('Rejected:', result.error)   // human-readable, with line/column
} else {
  const config = result.result
}
```

`result.error` is a string like `YAML at line 3, column 5: …` — safe to log.
Security limits are on by default, so a bomb document never reaches your code.
See § 5 for what each message means.

### 3.2 One-line hardened profile (`strict: true`)

```js
const parser = new YamlSecurity({ strict: true })   // tighter defaults, same semantics
```

Or globally:

```js
YamlSecurity.setLimits({ strict: true })   // all current and future instances
YamlSecurity.setLimits({})                 // reset to standard defaults
```

Explicit keys override a `strict` profile: `new YamlSecurity({ strict: true, maxStringLength: 0 })`.

### 3.3 Per-instance vs global limits

```js
const strict = new YamlSecurity({ maxAliasDepth: 2 })      // this instance only
YamlSecurity.setLimits({ maxNodes: 5000 })                 // every instance
```

Constructor options only affect that instance; `setLimits` affects everything,
including instances created later. A `strict` instance is never loosened by a
global `setLimits`, so one hardened instance stays hardened.

### 3.4 Drop-in replacement for js-yaml

```js
// Before:  const data = require('js-yaml').load(str)
import { YamlSecurity } from 'yaml-security-lib'
const parser = new YamlSecurity()
const { ok, result, error } = parser.parse(str)
if (!ok) throw new Error(error)
const data = result
```

`parser.dump(obj)` (and the low-level `dump(value)`) serialize back to YAML.

### 3.5 Multi-document streams

```js
const parser = new YamlSecurity()
const r = parser.parseAll('a: 1\n---\nb: 2')
// → { ok: true, result: [ { a: 1 }, { b: 2 } ] }
```

The low-level throwing variant returns the array directly and throws on error:
`parseAll(yaml, { types: [...] })`.

### 3.6 Streaming — push chunks, reject early

```js
import { createStream } from 'yaml-security-lib'

const stream = createStream({ maxNodes: 10000 })
stream.on('key',    ev => console.log('key  ', ev.value))
stream.on('scalar', ev => console.log('value', ev.value))
stream.on('document', doc => console.log('doc  ', doc))  // full document for convenience
stream.on('error', err => console.error('rejected mid-stream:', err.message))
stream.on('end', () => console.log('done'))

stream.write('a: 1\n')
stream.write('b: [2, 3]\n')
stream.end()
```

- All security limits are enforced **during** parsing (e.g. `maxInputBytes` on
  every `write()`), so a bomb is rejected before the whole input is consumed.
- Aliases need memory: `anchors: 'disable'` gives true zero-buffering and
  rejects any `&`/`*` immediately.
- For just the documents, use `parseStream(input)` — an async generator that
  yields each completed document (`for await (const doc of parseStream(chunks()))`).
- `StreamParser` is also async-iterable (`for await (const ev of stream)`).

### 3.7 Schema validation

```js
import { YamlSecurity, s } from 'yaml-security-lib'

const spec = s.object({
  name: s.string(),
  age: s.int({ min: 0 }),
  roles: s.array(s.string()),
})

const r = new YamlSecurity().validateYaml('name: أحمد\nage: 30\nroles: [admin]', spec)
// → { ok: true, value: { name: 'أحمد', age: 30, roles: ['admin'] } }
```

- `validate(value, spec)` validates a plain JS value already in memory.
- Stream and validate incrementally: `createStream({ validate: spec })` emits
  `violation` events as soon as the offending node completes —
  `parser.on('violation', v => console.log(v.path, v.message))` gives
  `$.age must be >= 0`-style reports per node.
- To abort early on the first problem, `createStream({ validate: spec, abortOnError: true })`
  rejects by **throwing** `YAMLException` from the offending `write()`/`end()`
  call, so wrap the feed in `try/catch` (it stops before the rest of the input
  is consumed).
- `parseStream(input, { validate: spec })` yields `{ value, errors }` per document.
- `fromJSONSchema(schema)` / `toJSONSchema(spec)` bridge JSON Schema.
- `createStreamValidator(spec)` is exported standalone for custom event-driven
  consumers (it plugs into the parser's event hooks).

### 3.8 Custom schema / tags

```js
import { YamlSecurity, YamlType, Schema } from 'yaml-security-lib'

const schema = new Schema().addType(
  new YamlType('!upper', { construct: (v) => String(v).toUpperCase() }),
)

const parser = new YamlSecurity()
parser.setSchema(schema)
parser.parse('x: !upper hello')   // → { ok: true, result: { x: 'HELLO' } }
```

`%TAG` directives resolve custom handles against the active schema.

### 3.9 Linting

```js
import { lint } from 'yaml-security-lib'

const result = lint('a: 1\nb: true\nb: 2\n')
// { valid: false, issues: [ { rule: 'duplicate-key', severity: 'error', line: 3, ... }, ... ] }
```

- 4 error rules: `syntax-error`, `duplicate-key`, `anchor-bomb`, `prototype-pollution`.
- 10 warning rules: `unsafe-tag`, `hidden-character`, `merge-key`,
  `inconsistent-eol`, `trailing-spaces`, `line-length`, `missing-newline-at-eof`,
  `space-after-colon`, `space-after-dash`, `truthy-yes-no`. (Full table in README § Linter.)
- Toggle rules: `lint(yaml, { rules: { 'line-length': 'off' } })` or enable only a
  list: `{ rules: ['syntax-error', 'duplicate-key'] }`. Unknown rule names throw.

### 3.10 CLI

```bash
npx yaml-lint config.yaml                 # human output, exit code 0/1
npx yaml-lint --json config.yaml          # machine-readable JSON
npx yaml-lint --max-line-length 100 **/*.yaml
cat config.yaml | npx yaml-lint           # stdin when no files given
```

- Exit codes: `0` clean, `1` at least one error-severity issue, `2` argument or
  IO problem (unknown option, unreadable file).
- The summary line always prints; unreadable files are listed as `(N could not
  be read)`. `--json` reports them as `{ file, error }` entries with a top-level
  `unreadable` count.
- Works from a fresh checkout, CI, and the installed package — no build step.

### 3.11 Browser

```html
<script src="https://unpkg.com/yaml-security-lib/dist/yaml-security.min.js"></script>
<script>
  const p = new YamlSecurity.YamlSecurity()
  console.log(p.parse('hello: world'))
</script>
```

Lean bundles: `dist/core.min.js` (global `YamlSecurityCore`),
`dist/validate.min.js` (global `YamlSecurityValidate`),
`dist/lint.min.js` (global `YamlSecurityLint`); ESM versions ship as
`dist/*.mjs`.

### 3.12 Canonicalization — `tree()` / `parseTree()`

```js
import { tree, parseTree } from 'yaml-security-lib'

tree('a: 1\nb: [x, y]\n')          // libyaml-style event string: +STR +DOC +MAP =VAL :a …
const [doc] = parseTree('a: 1\nb: [x, y]\n')   // nested AST, one node per document
```

Useful for diffing, debugging, and canonical form checks without constructing
the JS object tree. Passes 262/262 tree cases of the YAML Test Suite.

---

## 4. Limits reference

Default limits (standard → `strict`), every key also settable per instance or
globally via `setLimits`:

| Limit | Standard | Strict | Purpose |
|-------|----------|--------|---------|
| `maxNodes` | `10000` | `5000` | Total nodes in a document (bomb gate) |
| `maxAlias` | `100` | `20` | Distinct anchored values remembered |
| `maxAliasDepth` | `10` | `5` | Alias reference depth (circular-alias gate) |
| `maxExpansion` | `100000` | `10000` | Alias expansion weight (Billion Laughs gate) |
| `maxInputBytes` | `1048576` (1 MB) | same | Total input size |
| `maxStringLength` | `0` (unlimited) | `1048576` | Single scalar length |
| `maxKeys` | `0` (unlimited) | `10000` | Keys in one mapping |
| `maxDepth` | `50` | `30` | Nesting depth |

Use `getBaseConfig()` to read the active defaults (reflects `setLimits`, incl. strict).

---

## 5. Troubleshooting

The message on the right is exactly what `{ ok: false, error }` contains; the
numbers depend on your active limits.

| If you see… | Cause | Fix |
|-------------|-------|-----|
| `…nodes limit exceeded (possible bomb) — reached N` | Document built more than `maxNodes` nodes | Genuinely hostile input → keep default; legit large file → raise via constructor/`setLimits` (watch `maxInputBytes`) |
| `…mapping keys limit exceeded (N)` | One mapping has more than `maxKeys` keys | Raise `maxKeys` (default unlimited) or split the map |
| `…expansion limit exceeded (possible bomb) — reached N` | Aliases expanded past `maxExpansion` (Billion Laughs) | Keep default for untrusted input |
| `…string length exceeds limit (N)` | A scalar longer than `maxStringLength` | Raise `maxStringLength` / `{ strict: true, maxStringLength: 0 }` |
| `YAML: input too large (>1MB)` | Input exceeded `maxInputBytes` | Raise `maxInputMB` / `maxInputBytes` |
| `YAML: alias depth exceeds limit (N)` | Alias reference chain deeper than `maxAliasDepth` | Default is fine for trusted docs; raise if your schema aliases deeply |
| `YAML: circular alias detected — "name"` | `&a … *a` self/cycle reference | Rewrite the YAML; this is always invalid |
| `YAML at line N, column N: Duplicate key: "k"` | Duplicate mapping key | Fix the document; duplicates are invalid by design (`duplicate-key` lint rule too) |
| `Security: cannot set key "__proto__" — prototype pollution blocked` | A `__proto__` / `constructor` / `prototype` path in the input | By design — the key is blocked, nothing is polluted |
| `YAML: unexpected end of the stream within a flow mapping` (etc.) | Syntax error | Check the reported line/column; run the `yaml-lint` CLI for a full report |

Semantics to know:

- **Implicit timestamps stay strings.** `2023-01-15` → `"2023-01-15"` (YAML 1.2
  core). Use an explicit `!!timestamp` tag to get a `Date`.
- **`__proto__` on a null-prototype object** is an own plain key, never a
  prototype write — the parse result uses a null-prototype object, so nothing
  can pollute.
- **`parse()` does not throw.** Rejections come back as `{ ok: false, error }`.
  The only throwing entry points are the low-level `parse` / `parseAll` /
  `dump` (they raise `YAMLException`, exported for `instanceof` checks).
- **Missing trailing newline** is only a linter warning
  (`missing-newline-at-eof`), never a parse error.

---

## 6. FAQ

- **Is it really zero-dependency?** Yes — the runtime bundle has no imports
  (dev tooling differs).
- **Which Node versions?** ≥ 16; CI matrix runs 16, 18, 20, 22, 24.
- **Are there TypeScript types?** Yes — `.d.ts` for the main entry and each
  subpath (`core`/`validate`/`lint`).
- **Which CDN files do I link?** `dist/yaml-security.min.js` (everything) or the
  lean `dist/core.min.js`, `dist/validate.min.js`, `dist/lint.min.js` (+ `.mjs`
  ESM variants). Filenames are stable across releases.
- **How was performance validated?** `npm run bench` runs an honest 3-way
  benchmark (this library vs `js-yaml` vs eemeli `yaml`, including two adversary
  shapes); results are machine-dependent and regenerable.
- **Can I re-run the tests myself?** `npm test` runs the full suite
  (unit + fuzz + streaming + schema + linter + CLI regression). The YAML Test
  Suite conformance runs 406 cases and the tree suite 262/262.
- **Where are the big docs?** README (API reference, comparison, threat model,
  security model), this guide, [ARCHITECTURE.md](ARCHITECTURE.md) (internals),
  [SECURITY.md](../SECURITY.md), [CHANGELOG.md](../CHANGELOG.md).