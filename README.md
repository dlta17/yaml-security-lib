# YAML Security Lib

[![npm version](https://img.shields.io/npm/v/yaml-security-lib)](https://www.npmjs.com/package/yaml-security-lib)
[![CI](https://github.com/dlta17/yaml-security-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/dlta17/yaml-security-lib/actions)
[![Downloads](https://img.shields.io/npm/dw/yaml-security-lib)](https://www.npmjs.com/package/yaml-security-lib)
[![Bundle Size](https://img.shields.io/bundlephobia/min/yaml-security-lib)](https://bundlephobia.com/package/yaml-security-lib)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue)](https://www.npmjs.com/package/yaml-security-lib)

**Secure YAML parser for JavaScript.** Protects against:
- **Duplicate keys** — Privilege escalation (K8s, GitLab, Ansible)
- **Anchor bombs** — Alias depth + circular alias tracking (prevents OOM/exhaustion)
- **Prototype pollution** — `__proto__` / `constructor` / `prototype` blocked
- **Billion Laughs** — Expansion limit detection
- **Runaway strings/keys** — `maxStringLength` / `maxKeys` limits (opt-in)

Zero dependencies. Works in Node.js ≥16 and all modern browsers.

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
| `maxDepth` | `50` | Max nesting depth in block mappings |
| `maxNodes` | `10000` | Max parsed nodes before abort |
| `maxExpansion` | `100000` | Max expansion factor (Billion Laughs) |
| `maxStringLength` | `0` (unlimited) | Max string length in parsed output. Set to e.g. `10000` to prevent overly long strings. |
| `maxKeys` | `0` (unlimited) | Max keys per mapping (block + inline). Set to e.g. `1000` to prevent mapping bombs. |
| `maxInputBytes` | `1048576` (1MB) | Max input size in bytes (set via `maxInputMB` too) |

> **Note on limits**: all limits use strict `>` semantics — a value equal to the limit is allowed, anything larger is blocked. E.g. `maxStringLength: 1000000` allows a 1,000,000-char string but blocks 1,000,001+. To block a specific size, set the limit one lower.

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

All limits (`maxNodes`, `maxDepth`, `maxKeys`, `maxExpansion`, `maxStringLength`, `maxAlias`, `maxAliasDepth`, `maxInputBytes`) are enforced **during** parsing. For example, `maxInputBytes` is checked on every `write()`, and `maxNodes`/`maxKeys` on every node/key seen.

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
| YAML Test Suite score | **245/351** (70%) | ~95% | ~95% |
| Browser bundle | ✅ (14KB gzip) | ✅ (17KB) | ✅ (26KB) |
| Dual license (AGPL + Commercial) | ✅ | ❌ (MIT) | ❌ (MIT) |
| Schema system | ✅ | ✅ | ✅ |
| Multi-document support | ✅ | ✅ | ✅ |
| **Streaming parser** (SAX events + async iterator) | ✅ | ❌ | ✅ |
| Zero dependencies (fully self-owned) | ✅ | ❌ | ❌ |

## YAML Test Suite

yaml-security-lib passes **245 of 351** official [YAML Test Suite](https://github.com/yaml/yaml-test-suite) tests (70%), covering all major security-relevant features. The remaining gaps are in edge cases of block scalars, flow collections, and YAML 1.2 type system completeness — none of which affect the security protections.

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
npm test        # unit + fuzz + stream + stream-fuzz (js-yaml oracle)
```

- Zero runtime dependencies; rollup (dev-only) rebuilds the bundles.
- Implicit timestamps resolve to **strings** (YAML 1.2 core); only explicit
  `!!timestamp` yields a `Date` — `parse()` and the stream must always agree.
- The stream-fuzz oracle is **js-yaml v5**; do not downgrade to v4 (YAML 1.1
  turns timestamps into `Date`, failing ~28 oracle assertions).
- Every code change bumps the version (`patch`/`minor`/`major`) with a
  `CHANGELOG.md` entry and a `vX.Y.Z` git tag. Docs-only changes may stay put.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for details.
