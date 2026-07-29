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
