# YAML Security Lib

**Secure YAML parser for JavaScript.** Protects against:
- **Duplicate keys** — Privilege escalation (K8s, GitLab, Ansible)
- **Anchor bombs** — Alias depth tracking (prevents OOM/exhaustion)
- **Prototype pollution** — `__proto__` / `constructor` / `prototype` blocked
- **Trailing-space corruption** — Flow scalars auto-trimmed

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

// Parse safely
parser.parse("name: أحمد\nage: 30")
// → { ok: true, result: { name: 'أحمد', age: 30 } }

// Duplicate key → thrown
parser.parse("x: 1\nx: 2")
// → Error: Duplicate key 'x'

// Anchor bomb → thrown
parser.parse("&a *a")  // self-reference
// → Error: Alias depth exceeds limit (10)
```

## API

### `new YamlSecurity(opts?)`

| Option | Default | Description |
|--------|---------|-------------|
| `maxAliasDepth` | `10` | Max anchor indirection depth |
| `maxNodes` | `5000` | Max parsed nodes before abort |

### `parse(str)` → `{ ok, result }` or throws

### `dump(obj)` → `{ ok, result }`

### Static: `YamlSecurity.setLimits(opts)`

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
