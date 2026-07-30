# YAML Security Lib

**Secure YAML parser for JavaScript.** Protects against:
- **Duplicate keys** — Privilege escalation (K8s, GitLab, Ansible)
- **Anchor bombs** — Alias depth tracking (prevents OOM/exhaustion)
- **Prototype pollution** — `__proto__` / `constructor` / `prototype` blocked
- **Billion Laughs** — Expansion limit detection

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
parser.parse("&a *a")  // self-reference
// → { ok: false, error: 'YAML: alias depth exceeds limit (10)' }
```

## API

### `new YamlSecurity(opts?)`

| Option | Default | Description |
|--------|---------|-------------|
| `maxAliasDepth` | `10` | Max anchor indirection depth |
| `maxNodes` | `10000` | Max parsed nodes before abort |
| `maxExpansion` | `100000` | Max expansion factor (Billion Laughs) |

### `parse(str)` → `{ ok, result } | { ok, error }`

Parses a YAML string. Always returns an object — never throws.

### `parseAll(str)` → `{ ok, result } | { ok, error }`

Parses multi-document YAML (`---` or `...` separated). Returns an array.

### `dump(obj, opts?)` → `{ ok, result } | { ok, error }`

Serializes a JavaScript value to YAML. Options: `indent` (default `2`), `flowLevel` (default `6`).

### `parseToJSON(str)` → `{ ok, result } | { ok, error }`

Parses YAML and returns pretty-printed JSON string.

### `YamlSecurity.setLimits(opts)`

Globally adjust limits for all parsers (affects existing and new instances).

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
| `resolve` | `() => true` | Returns truthy if the value should be implicitly resolved by this type (checked in order of registration) |
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
| `!!float` | Decimal numbers, scientific notation |
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
