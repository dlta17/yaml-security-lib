# YAML Security Lib

[![npm version](https://img.shields.io/npm/v/yaml-security-lib)](https://www.npmjs.com/package/yaml-security-lib)
[![CI](https://github.com/dlta17/yaml-security-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/dlta17/yaml-security-lib/actions)
[![Downloads](https://img.shields.io/npm/dw/yaml-security-lib)](https://www.npmjs.com/package/yaml-security-lib)
[![Bundle Size](https://img.shields.io/bundlephobia/min/yaml-security-lib)](https://bundlephobia.com/package/yaml-security-lib)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue)](https://www.npmjs.com/package/yaml-security-lib)
[![Snyk Advisor](https://img.shields.io/badge/Snyk%20Advisor-Recommended-brightgreen)](https://snyk.io/advisor/npm-package/yaml-security-lib)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21684897.svg)](https://doi.org/10.5281/zenodo.21684897)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0008--4915--4787-a6ce39)](https://orcid.org/0009-0008-4915-4787)

**Secure YAML parser for JavaScript.** Protects against:
- **Duplicate keys** — Privilege escalation (K8s, GitLab, Ansible)
- **Anchor bombs** — Alias depth + circular alias tracking (prevents OOM/exhaustion)
- **Prototype pollution** — `__proto__` / `constructor` / `prototype` blocked
- **Billion Laughs** — Expansion limit detection
- **Runaway strings/keys** — `maxStringLength` / `maxKeys` limits (opt-in)
- **CPU-exhaustion via quadratic parsing** — flow collections (multi-line gathering and single-line item slicing) are linear-time in both the batch and streaming engines, so deep `a: [\n  x,\n …` inputs and huge single-line `[1,2,3,…]` sequences can't stall the parser

Zero dependencies. Works in Node.js ≥16 and all modern browsers.

> **For contributors / maintainers:** see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a
> deep dive into the two parsing engines (batch + streaming), the security model, and a
> code map of the single-file core (`src/index.js`).

## Install

```bash
npm install yaml-security-lib
```

## Usage

```js
import { YamlSecurity } from 'yaml-security-lib'
// or: const { YamlSecurity } = require('yaml-security-lib')

const parser = new YamlSecurity()

// Parse safely — always returns { ok, result } or { ok, error }
parser.parse("name: أحمد\nage: 30")
// → { ok: true, result: { name: 'أحمد', age: 30 } }

// Duplicate key → caught safely
parser.parse("x: 1\nx: 2")
// → { ok: false, error: 'YAML at line 2: Duplicate key: "x"' }

// Anchor bomb → caught safely
parser.parse("&a *a")  // self-reference (circular alias)
// → { ok: false, error: 'YAML: circular alias detected — "a"' }

parser.parse("&a 1\n&b *a\n&c *b\n&d *c\n&e *d\n&f *e\n&g *f\n&h *g\n&i *h\n&j *i\n&k *j\n&l *k\nkey: *l")  // 11-deep chain
// → { ok: false, error: 'YAML: alias depth exceeds limit (10)' }
```

## API

### `new YamlSecurity(opts?)`

| Option | Default | Description |
|--------|---------|-------------|
| `maxAliasDepth` | `10` | Max anchor indirection depth |
| `maxAlias` | `100` | Max total alias expansions |
| `maxDepth` | `50` | Max nesting depth of block collections (mappings + sequences). Flow `[...]`/`{...}` don't count; `0` disables. See "How `maxDepth` is counted" below |
| `maxNodes` | `10000` | Max parsed nodes before abort |
| `maxExpansion` | `100000` | Max expansion factor (Billion Laughs) |
| `maxStringLength` | `0` (unlimited) | Max string length in parsed output. Set to e.g. `10000` to prevent overly long strings. |
| `maxKeys` | `0` (unlimited) | Max keys per mapping (block + inline). Set to e.g. `1000` to prevent mapping bombs. |
| `maxInputBytes` | `1048576` (1MB) | Max input size in bytes (set via `maxInputMB` too) |
| `maxInputMB` | `1` | Max input size in MiB (maps onto `maxInputBytes`) |

> **Note on limits**: all limits use strict `>` semantics — a value equal to the limit is allowed, anything larger is blocked. E.g. `maxStringLength: 1000000` allows a 1,000,000-char string but blocks 1,000,001+. To block a specific size, set the limit one lower. Constructor options are validated with the same rules as `setLimits` (unknown keys are ignored, invalid values throw).

#### How `maxDepth` is counted

The counter starts at `0` for the document's top-level block collection and increases by `1` for every *nested block collection* (block mapping or block sequence) you open. Flow collections (`[ ... ]`, `{ ... }`) are **not** counted, and `maxDepth: 0` disables the guard. Because the rule is strict `>` (depth equal to the limit is allowed), `maxDepth: 3` accepts `a.b.c.d` — three nested maps reach depth `3` — but rejects `a.b.c.d.e`, whose fourth nested map reaches depth `4 > 3`:

```yaml
a:         # block mapping, depth 0
  b:       # block mapping, depth 1
    c:     # block mapping, depth 2
      d: 1 # block mapping, depth 3 → allowed with maxDepth: 3
```

```yaml
a:            # depth 0
  b:          # depth 1
    c:        # depth 2
      d:      # depth 3
        e: 1  # depth 4 > 3 → blocked
```

Sequences count too, and their items do **not** reset the counter — the block inside a sequence item is the sequence's depth `+ 1`:

```yaml
a:        # depth 0
  - b:    # sequence depth 1; the item map `b` is depth 2
      c: 1 # block mapping, depth 3 → blocked with maxDepth: 2
```

### `parse(str)` → `{ ok, result } | { ok, error }`

Parses a YAML string. Always returns an object — never throws.

### `parseAll(str)` → `{ ok, result } | { ok, error }`

Parses multi-document YAML (`---` or `...` separated). Returns an array.

### `dump(obj, opts?)` → `{ ok, result } | { ok, error }`

Serializes a JavaScript value to YAML. Options: `indent` (default `2`), `flowLevel` (default `6`).

### `parseAll(str, opts?)` on instance

When called on a `YamlSecurity` instance, `parseAll` accepts an optional second argument with per-call schema overrides:

```js
const parser = new YamlSecurity()
parser.parseAll('x: !upper hello\n---\ny: world', {
  schema: mySchema,
})
// or with types array (extends instance schema):
parser.parseAll('x: !upper hello', { types: [upperType] })
```

### `parseToJSON(str)` → `{ ok, result } | { ok, error }`

Parses YAML and returns pretty-printed JSON string.

```js
const p = new YamlSecurity()
p.parseToJSON('name: أحمد\nage: 30')
// → { ok: true, result: '{\n  "name": "أحمد",\n  "age": 30\n}' }
```

### `YamlSecurity.setLimits(opts)`

Globally adjust limits for all parsers (affects existing and new instances). Call with no arguments (or `{}`) to reset to defaults.

```js
import { YamlSecurity } from 'yaml-security-lib'

// Tighten limits globally
YamlSecurity.setLimits({
  maxNodes: 5000,
  maxDepth: 20,
  maxExpansion: 10000,
  maxStringLength: 50000,
  maxKeys: 500,
  maxAliasDepth: 5,
  maxInputMB: 0.5,
})

const p = new YamlSecurity()
p.parse('x: ' + 'a'.repeat(60000))
// → { ok: false, error: 'YAML: string length exceeds limit (50000)' }
```

### `YamlSecurity.setSchema(schema)`

Set a custom Schema on an instance (affects parsing only for that instance).

```js
import { YamlSecurity, YamlType, Schema } from 'yaml-security-lib'

const schema = new Schema()
  .addType(new YamlType('!upper', {
    construct: (v) => String(v).toUpperCase(),
  }))

const parser = new YamlSecurity()
parser.setSchema(schema)
parser.parse('x: !upper hello')
// → { ok: true, result: { x: 'HELLO' } }
```

### `YAMLException`

All internal errors use the `YAMLException` class (extends `Error`). Available as an export for `instanceof` checks:

```js
import { YAMLException } from 'yaml-security-lib'
try { /* ... */ } catch (e) {
  if (e instanceof YAMLException) console.log('YAML error:', e.message)
}
```

## Streaming API

In addition to `parse`/`parseAll`, the library provides a zero-dependency, SAX-style **streaming parser**. It feeds YAML in chunks, emits events, and **enforces every security limit while streaming** — so a malicious document is rejected before the whole input is consumed.

### `createStream(opts?)` → `StreamParser`

Push-based incremental parser.

```js
import { createStream } from 'yaml-security-lib'

const stream = createStream({ maxNodes: 10000, maxDepth: 50 })

stream.on('key',      ev => console.log('key  ', ev.value))
stream.on('scalar',   ev => console.log('value', ev.value))
stream.on('document', doc => console.log('doc  ', doc))   // convenience: full document
stream.on('end', () => console.log('done'))

// feed in chunks (works for single- and multi-doc streams)
stream.write('a: 1\n')
stream.write('b: [2, 3]\n')
stream.end()
```

`StreamParser` is also **async-iterable**:

```js
const stream = createStream()
const consumer = (async () => {
  for await (const ev of stream) console.log(ev.type, ev.value)
})()
stream.write('a: 1\n')
stream.end()
await consumer
```

Events: `documentStart`, `mappingStart`, `sequenceStart`, `key`, `scalar`, `mappingEnd`, `sequenceEnd`, `documentEnd`, `end` (plus `error`). Each `key`/`scalar` event carries `{ value, raw }`.

### Streaming semantics

- **Multi-line scalars fold**: plain, double-quoted, and single-quoted scalars that span lines fold line breaks to a single space (`a: "line1\n  line2"` → `"line1 line2"`), matching reference parsers.
- **Implicit timestamps are strings**: a plain `2023-01-15` resolves to the string `"2023-01-15"` (YAML 1.2 core behavior). Use an explicit `!!timestamp` tag to get a `Date`.
- **Retroactive retraction**: for pathological `- - 2:` indentation the parser may emit a scalar and later retract it. The parser's `retractions` counter tells consumers when events cannot be replayed verbatim into the final tree.
- **Merge keys (`<<`)** are resolved during buffering; the merge is applied after the mapped events are emitted, so a pure event-replay consumer should apply `<<` merges as post-processing.

### `parseStream(input, opts?)` → `AsyncGenerator`

Yields each parsed document as it completes. Accepts a string or any (async) iterable of chunks.

```js
import { parseStream } from 'yaml-security-lib'

for await (const doc of parseStream('a: 1\n---\nb: 2')) {
  console.log(doc) // { a: 1 } then { b: 2 }
}

// streaming from an async source, document-by-document
async function* chunks() {
  yield 'name: أحمد\n'
  yield '---\n'
  yield 'count: 3\n'
}
for await (const doc of parseStream(chunks())) { /* ... */ }
```

### Security in streaming mode

All limits (`maxNodes`, `maxDepth`, `maxKeys`, `maxExpansion`, `maxStringLength`, `maxAlias`, `maxAliasDepth`, `maxInputBytes`) are enforced **during** parsing. For example, `maxInputBytes` is checked on every `write()`, and `maxNodes`/`maxKeys` on every node/key seen. `maxDepth` is counted exactly as in the batch parser — see "How `maxDepth` is counted" above; both engines enforce the same limit on the same documents. Alias bombs are bounded by `maxExpansion`/`maxNodes` just like the batch parser: every `*alias` reference charges the full weight of the anchored subtree, so `createStream({ maxExpansion, maxNodes })` stops a bomb even when `maxAlias` is raised. Multi-line flow collections are gathered with an incremental balance tracker, so the stream parser stays linear-time on `a: [\n  x,\n …` inputs (no per-line re-scan of the accumulated flow).

### Anchors: `buffered` vs `disable`

Aliases require remembering the anchored node, which conflicts with true constant-memory streaming:

- `anchors: 'buffer'` (default) — anchors/aliases are supported; anchored values are buffered in memory until resolved.
- `anchors: 'disable'` — any `&`/`*` is rejected immediately for **true zero-buffering** (fully constant-memory streaming for anchor-free documents).

### `YamlSecurity.createStream()` / `YamlSecurity.parseStream()`

Instances expose the same streaming API, bound to the instance's schema and limits:

```js
const ys = new YamlSecurity({ maxDepth: 20 })
const s = ys.createStream()
s.on('document', doc => console.log(doc))
s.write('a: 1\n'); s.end()

for await (const doc of ys.parseStream('x: 1\n---\nx: 2')) { /* ... */ }
```

### Constructor vs `setLimits`

Constructor options only affect that specific instance. `setLimits` affects all instances globally.

```js
const strict = new YamlSecurity({ maxAliasDepth: 2 })
strict.parse("&a 1\n&b *a\n&c *b\n&d *c\nkey: *d")
// → { ok: false, error: '...alias depth exceeds limit (2)' }

const normal = new YamlSecurity()
normal.parse("&a 1\n&b *a\n&c *b\n&d *c\nkey: *d")
// → { ok: true, result: { key: 1 } }  ← unaffected by strict config
```

## Schema Validation

Validate parsed YAML (or plain JS values) against a schema spec. Works standalone (`validate`, `validateYaml`) and **inside the streaming API** — the validator consumes the SAX events incrementally, so a bad document can be rejected before the rest of the input is consumed.

### Fluent builder

```js
import { s, validate, validateYaml } from 'yaml-security-lib'

const user = s.object({
  name: s.string({ min: 1 }),
  age: s.int({ min: 0 }),
  tags: s.array(s.string()),
  role: s.optional(s.enum(['admin', 'user'])),  // absent OK, present must match
})

validate({ name: 'ned', age: 30, tags: ['a'] }, user)
// → { ok: true, errors: [] }

validateYaml('name: ned\nage: -5\n', user)
// → { ok: false, value: {...}, errors: [{ path: '$.age', message: 'must be >= 0', ... }] }
```

Errors carry a JSON-pointer-like `path` (`$.a.b[0]`), a `message`, and the offending `value`.

| Builder | Description |
|---------|-------------|
| `s.string({ min, max, pattern, enum })` | String with length/pattern/choice constraints |
| `s.int({ min, max, exclusiveMin, exclusiveMax, multipleOf })` | Integer |
| `s.number()` / `s.float({...})` | Any finite number |
| `s.bool()` / `s.null()` / `s.any()` / `s.never()` | Boolean / null / anything / nothing |
| `s.timestamp()` | `Date` or ISO 8601 string |
| `s.enum([...])` | One of the listed values (deep equality) |
| `s.array(items, { minItems, maxItems, uniqueItems })` | Array of `items` |
| `s.tuple([a, b])` | Fixed-length array, per-index types |
| `s.object(shape, { required, allowExtra, additionalProperties, patternProperties, minProps, maxProps })` | Object with per-key specs |
| `s.record(spec)` | Map of any string keys → `spec` |
| `s.optional(spec)` / `s.nullable(spec)` | Present-optional / accepts `null` |
| `s.oneOf([...])` / `s.anyOf([...])` / `s.allOf([...])` / `s.not(spec)` | Combinators |
| `s.custom(fn)` | Custom validator: return `true`/`undefined` to pass, `false` or a string to fail |

Keys in an `s.object(shape)` are **required by default**; wrap with `s.optional()` to relax. Unknown keys are **rejected by default**; set `allowExtra: true` or provide `additionalProperties`.

### JSON Schema bridge

`fromJSONSchema(js)` converts a JSON Schema (draft-07 subset: `type`, `enum`, `const`, `$ref` to local `#/$defs`, `pattern`, `min/maxLength`, `minimum/maximum`, `multipleOf`, `items`, `prefixItems`→tuple, `properties`, `required`, `additionalProperties`, `patternProperties`, `min/maxItems`, `min/maxProperties`, `uniqueItems`, `oneOf`/`anyOf`/`allOf`/`not`, boolean schemas) into a fluent spec. `toJSONSchema(spec)` converts back:

```js
import { s, validate, fromJSONSchema } from 'yaml-security-lib'

const spec = s.fromJSONSchema({           // or fromJSONSchema(js)
  type: 'object',
  properties: { n: { type: 'integer', minimum: 1 } },
  required: ['n'],
  additionalProperties: false,
})
```

### Validation in the streaming API

Pass `validate` to `createStream`/`parseStream`. Violations are emitted as `violation` events **incrementally** — as soon as the offending node completes:

```js
import { createStream, s } from 'yaml-security-lib'

const spec = s.object({ age: s.int({ min: 0 }) })
const parser = createStream({ validate: spec, abortOnError: true })

parser.on('violation', (v) => console.log(v.path, v.message)) // $.age must be >= 0
parser.on('error', (e) => console.error('aborted:', e.error.message))
parser.on('document', (doc) => { /* validated doc */ })

parser.write('age: -5\n')
parser.end()
```

- `violation` event: `{ type: 'violation', path, message, value }`.
- `abortOnError: true` throws on the **first** violation → the stream aborts with an `error` event before consuming the rest of the input.
- `parseStream(input, { validate: spec })` yields `{ value, errors }` per document (`errors` is the authoritative per-doc list).
- Structure-level checks (object/array/record/tuple/scalar/ranges) are exact and incremental. `oneOf`/`anyOf`/`allOf`/`not`/`custom` and deep `uniqueItems` are authoritatively resolved at document end from the buffered root (default mode); in `anchors: 'disable'` (zero-buffering) mode they are best-effort via kind-matched branches.
- `createStreamValidator(spec)` is exported standalone for custom event-driven consumers.

## Comparison vs Alternatives

| Feature | yaml-security-lib | js-yaml | yaml (Eemeli) |
|---------|:-:|:-:|:-:|
| Zero dependencies | ✅ | ❌ (5 deps) | ❌ (10+ deps) |
| Error-safe API (never throws) | ✅ | ❌ | ❌ |
| Duplicate key detection | ✅ (blocked) | ✅ (warn) | ❌ |
| Prototype pollution guard | ✅ | ❌ | ❌ |
| Circular alias detection | ✅ | ❌ | ❌ |
| Alias depth limit | ✅ | ❌ | ❌ |
| Node/expansion limits | ✅ | ❌ | ❌ |
| `maxStringLength` / `maxKeys` | ✅ | ❌ | ❌ |
| Input size limit (1MB default) | ✅ | ❌ | ❌ |
| YAML Test Suite score | **406/406** (100%) | ~95% | ~95% |
| Browser bundle | ✅ (14KB gzip) | ✅ (17KB) | ✅ (26KB) |
| Dual license (AGPL + Commercial) | ✅ | ❌ (MIT) | ❌ (MIT) |
| Schema system | ✅ | ✅ | ✅ |
| Multi-document support | ✅ | ✅ | ✅ |
| **Streaming parser** (SAX events + async iterator) | ✅ | ❌ | ✅ |
| Zero dependencies (fully self-owned) | ✅ | ❌ | ❌ |

## YAML Test Suite

yaml-security-lib passes **all 406** official [YAML Test Suite](https://github.com/yaml/yaml-test-suite) test cases (100%, 351 files) — including every SHOULD-FAIL security-relevant case — while enforcing its security protections (duplicate keys, alias bombs, prototype pollution, expansion limits). The [`tree()`](#-treeyamlstr-opts--string) event stream matches **262/262** conformance cases (the 82 SHOULD-FAIL cases throw as expected).

Plain-scalar `:` handling matches **js-yaml** in both the batch and streaming parsers (the streaming fuzz oracle is js-yaml v5):

- Flow collections require commas between entries: `{a: 1 b: 2}` and `[a: 1 b: 2]` throw `missed comma between flow collection entries`.
- Block plain scalars reject `: ` key separators: `key: a: b` and `key: a\n  b: c` throw `bad indentation of a mapping entry`, while attached colons stay literal (`key: a:b`, `key: http://x`, `key: 10:30:00`).
- Continuation lines fold into the plain scalar in both parsers, whatever their leading indicator (`key: a\n  - b` → `"a - b"`, `key: a\n  "b"`, `key: a\n  &x b`, `key: a\n  ? b`, `key: a\n  [1, 2]`, `key: a\n  |\n  text`, `key: a\n  ...`). A column-0 `...`/`---` still ends/starts a document, and multi-document streams match `js-yaml`'s `loadAll`.
- Compact quoted-key mappings are accepted PyYAML-style: `"a":b` → `{a: 'b'}` (js-yaml rejects the attached value with "a whitespace character is expected after the key-value separator"). The keys flow through the duplicate/prototype-pollution checks — `"__proto__":x` is blocked, `"a":b\n"a":c` is a duplicate key, `- "a":b` and `x:\n  "a":b` nest correctly.

## Schema System

Built-in YAML types (`!!str`, `!!int`, `!!float`, `!!bool`, `!!null`, `!!timestamp`, `!!binary`) are resolved automatically. You can extend or replace them with custom types.

### `YamlType`

```js
import { YamlType } from 'yaml-security-lib'

const upperType = new YamlType('!upper', {
  kind: 'scalar',           // 'scalar' | 'mapping' | 'sequence'
  construct: (v) => String(v).toUpperCase(),  // transform parsed value
  resolve: () => false,     // implicit detection (true to auto-resolve)
})
```

| Option | Default | Description |
|--------|---------|-------------|
| `kind` | `'scalar'` | Type kind (only `scalar` is used currently) |
| `construct` | identity | Transforms the raw string into the result value |
| `resolve` | `() => false` | Returns truthy if the value should be implicitly resolved by this type (checked in order of registration) |
| `instance` | `undefined` | Reserved for future use (mapping/sequence instances) |

### `Schema`

```js
import { Schema } from 'yaml-security-lib'

const schema = new Schema()
  .addType(upperType)
  .addType(reverseType)

schema.tagFor('hello') // → 'tag:yaml.org,2002:str'
```

- **`addType(type)`** — Registers a type. Returns the Schema (chainable).
- **`removeType(tag)`** — Removes a type by tag. Returns `true` if found and removed.
- **`hasType(tag)`** — Returns `true` if a type with that tag is registered.
- **`tagFor(val)`** — Returns the YAML tag that would be used for a JS value.

### Standalone `parse` / `parseAll` with options

```js
import { parse, parseAll } from 'yaml-security-lib'

// Custom schema
parse('x: !upper hello', { schema: mySchema })

// Extend default schema with custom types
parse('x: !upper hello', { types: [upperType] })

parseAll('---\nx: !upper hello\n---\ny: 2', { schema: mySchema })
```

### `tree(yamlStr, opts?)` → `string`

Renders a normalized YAML event stream (libyaml-style `+MAP` / `-MAP` / `+SEQ` / `-SEQ` / `=VAL` / `=ALI` events with resolved anchors, tags, and style prefixes) without constructing the object tree. Useful for debugging, canonicalization, and diffing YAML documents.

```js
import { tree } from 'yaml-security-lib'

tree('a: 1\nb: [x, y]\n')  // +STR +DOC +MAP =VAL :a =VAL :1 …
```

| Option | Default | Description |
|--------|---------|-------------|
| `schema` | `DEFAULT_SCHEMA` | Schema used to resolve tags |
| `types` | `[]` | Extra custom types (like `parse`) |
| `keepRaw` | `false` | Emit raw scalar text instead of normalized values |

Passes **262/262** tree conformance cases from the official YAML Test Suite (the remaining 82 are the SHOULD-FAIL cases, which all throw as expected).

### `parseTree(yamlStr, opts?)` → `Array<Node>`

Like `tree()`, but returns a nested AST instead of a string — one node per document:

```js
import { parseTree } from 'yaml-security-lib'

const [doc] = parseTree('a: 1\nb: [x, y]\n')
// doc.type === 'document'
// doc.node = { type: 'mapping', flow: false, items: [
//   { key: { type: 'scalar', style: 'plain', value: 'a' }, value: { type: 'scalar', style: 'plain', value: '1' } },
// ] }
```

| Node field | Description |
|------------|-------------|
| `type` | `'document'` / `'mapping'` / `'sequence'` / `'scalar'` / `'alias'` |
| `items` | Children for `mapping` (array of `{ key, value }`) and `sequence` |
| `flow` | `true` if the collection used flow style `{}` / `[]` |
| `anchor` / `tag` | Anchor name / resolved tag (if any) |
| `value` | Scalar content (or alias target name for `'alias'`) |
| `style` | `'plain'` / `'single'` / `'double'` / `'literal'` / `'folded'` |

### `renderTree(events)` → `string`

Renders a flat event stream (the `{ t, k, s, a, g, c, n, e }` objects produced during parsing) into the libyaml-style `+STR`/`+DOC`/`+MAP`/`=VAL`/`-STR` text that `tree()` returns. Useful if you drive the parser yourself:

```js
import { renderTree } from 'yaml-security-lib'

renderTree([{ t: 'doc' }, { t: 'c', k: 'map' }, { t: 'v', c: 'a', s: 1 }, { t: 'x', k: 'map' }, { t: 'docEnd' }])
// +STR +DOC +MAP =VAL :a -MAP -DOC -STR
```

### `assembleAST(events)` → `Array<Node>`

The inverse of `renderTree`: builds the nested document AST (same node shape as `parseTree`) from a flat event stream. `parseTree` is exactly `assembleAST` applied to the events of an internal parse.

### Utility helpers

```js
import { getBaseConfig, unescapeYaml, byteLength } from 'yaml-security-lib'
```

- `getBaseConfig()` → copy of the current default limits: `{ maxNodes: 10000, maxAlias: 100, maxAliasDepth: 10, maxExpansion: 100000, maxInputMB: 1, maxInputBytes: 1048576, maxStringLength: 0, maxKeys: 0, maxDepth: 50 }` (reflects `setLimits`).
- `unescapeYaml(str)` → decode YAML double-quoted escapes (`\n`, `\t`, `\xNN`, `\uNNNN`, `\UNNNNNNNN`, …) into a JS string. Throws `YAMLException` on an unknown escape.
- `byteLength(str)` → UTF-8 byte length (works in Node and browsers via `Buffer` or `TextEncoder`).

### `%TAG` directives

Custom tag handles via `%TAG` directives are expanded and resolved against the active Schema:

```js
parse('%TAG !e! tag:example.com:\n---\nx: !e!upper hello', {
  schema: tagSchema,  // schema with type for 'tag:example.com:upper'
})
```

### DEFAULT_SCHEMA

The default schema automatically resolves:

| Tag | Implicitly resolves |
|-----|-------------------|
| `!!str` | Any unmatched value |
| `!!null` | `null`, `~` |
| `!!bool` | `true`, `false` |
| `!!int` | Decimal, hex (`0x`), octal (`0o`), binary (`0b`). Leading zeros (`0123`) are strings. |
| `!!float` | Decimal numbers, scientific notation, `.inf` / `-.inf` / `.nan` |
| `!!timestamp` | ISO 8601 dates (`2024-01-01`, `2024-01-01T12:00:00Z`) |
| `!!binary` | Base64 (explicit only) |

## Linter

`lint(yaml, opts?)` validates a YAML string for **syntax errors**, **security
concerns**, and basic **style** issues. It never throws for YAML content;
issues are returned with line/column positions and a severity.

```js
import { lint } from 'yaml-security-lib';

const result = lint('a: 1\nb: yes\nb: 2\n', {});
// {
//   valid: false,
//   issues: [
//     { rule: 'duplicate-key', severity: 'error',   line: 3, column: 2, ... },
//     { rule: 'truthy-yes-no', severity: 'warning', line: 2, column: 3, ... }
//   ],
//   errors: 1,
//   warnings: 1
// }
```

`valid` is `true` only when there are **no error-severity** issues.

### Rules

| Rule | Severity | Detects |
|------|----------|---------|
| `syntax-error` | error | Unparseable YAML (incl. tabs for indentation) |
| `duplicate-key` | error | Duplicate mapping keys |
| `anchor-bomb` | error | Circular aliases / excessive alias expansion |
| `prototype-pollution` | error | Keys like `__proto__` / `constructor` |
| `trailing-spaces` | warning | Trailing whitespace at end of line |
| `line-length` | warning | Lines over `maxLineLength` (default 120) |
| `missing-newline-at-eof` | warning | File does not end with `\n` |
| `space-after-colon` | warning | `key:value` instead of `key: value` |
| `space-after-dash` | warning | `-item` instead of `- item` (numbers like `-5` skipped) |
| `truthy-yes-no` | warning | Unquoted `yes`/`no`/`on`/`off` (YAML 1.2 strings) |

### Options

```js
lint(yaml, {
  maxLineLength: 100,              // line-length threshold
  rules: ['syntax-error', 'duplicate-key'],       // enable only these rules (everything else off)
  rules: { 'truthy-yes-no': 'off', 'line-length': 'off' },  // toggle per rule
});
```

Rule values accept `false`/`0`/`'off'` (disable), `true`/`'error'`, or
`'warn'`/`'warning'`. Passing an unknown rule name throws a `TypeError`.

### CLI

A `yaml-lint` binary ships with the package:

```bash
yaml-lint config.yaml
yaml-lint --json config.yaml          # machine-readable output
yaml-lint --max-line-length 100 **/*.yaml
cat config.yaml | yaml-lint           # stdin when no files are given
```

Issue output follows the classic `file:line:column` format, and the exit code
is `1` when any error-severity issue is found, `2` on IO/usage errors.

## Browser

Pre-built bundles available in `dist/`:

```html
<script src="https://unpkg.com/yaml-security-lib/dist/yaml-security.min.js"></script>
<script>
  const p = new YamlSecurity.YamlSecurity()
  console.log(p.parse('hello: world'))
</script>
```

Or with ES modules:

```html
<script type="module">
  import { YamlSecurity } from 'https://unpkg.com/yaml-security-lib/dist/yaml-security.mjs'
</script>
```

## License

**Dual License:**

| Use Case | License | Cost |
|----------|---------|------|
| Personal / Educational / Research | [AGPL-3.0](LICENSE) | Free |
| Academic publication | [AGPL-3.0](LICENSE) + citation | Free |
| Commercial product (closed-source) | [Commercial License](LICENSE.COMMERCIAL) | Paid |

See [LICENSE](LICENSE) (AGPL-3.0) and [LICENSE.COMMERCIAL](LICENSE.COMMERCIAL).

## Author

**Nedal Ibrahim** — salamanedal@gmail.com

## Development & Testing

```bash
npm install
npm test        # unit + fuzz + stream + stream-fuzz + YAML Test Suite + tree suite + validate + lint
```

- The YAML Test Suite + tree suite require the suite checkout; set `YAML_SUITE_DIR`
  (e.g. `/home/nedal/yaml-test-suite/src`). If the dir is missing they skip cleanly,
  and CI clones the suite automatically.
- Zero runtime dependencies; rollup (dev-only) rebuilds the bundles.
- Bundles are gitignored, but `npm pack`/`npm publish` runs `prepack` which
  rebuilds them automatically — published tarballs always ship fresh builds.
- Implicit timestamps resolve to **strings** (YAML 1.2 core); only explicit
  `!!timestamp` yields a `Date` — `parse()` and the stream must always agree.
- The stream-fuzz oracle is **js-yaml v5**; do not downgrade to v4 (YAML 1.1
  turns timestamps into `Date`, failing ~28 oracle assertions).
- Every code change bumps the version (`patch`/`minor`/`major`) with a
  `CHANGELOG.md` entry and a `vX.Y.Z` git tag. Docs-only changes may stay put.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for details.
