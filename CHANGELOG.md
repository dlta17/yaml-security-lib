# Changelog

## 1.7.5 (2026-07-31)

### Documentation
- **README**: complete options table with `maxDepth`, `maxInputBytes`/`maxInputMB`
- **README**: fix anchor bomb example (11-chain, verified output)
- **TypeScript defs**: add `maxDepth`, `maxStringLength`, `maxKeys` to `YamlSecurityOptions` and `SetLimitsOptions`

## 1.7.4 (2026-07-31)

### Bug Fixes
- **`parseBlock` blank-line skip**: sub-block lines after blank/comment lines are now skipped correctly — `a:\n  \n  x: 1` parses as `{a:{x:1}}`, not `{a:{x:1},x:1}`

## 1.7.3 (2026-07-31)

### Bug Fixes
- **`maxDepth` constructor option**: `_getCfg()` now forwards `maxDepth` — `new YamlSecurity({ maxDepth: 10 })` works correctly
- **Remove dead code**: unused `state.expanded` field removed

## 1.7.2 (2026-07-31)

### Security
- **`maxDepth` limit**: default 50 — blocks deeply nested block mappings (bomb protection)
- **`prototype` key guard**: `safeAssign` now blocks `prototype` keys in addition to `__proto__` and `constructor`
- **Anchor pre-scan for flow types**: handles `[` / `{` in anchor declarations — catches Billion Laughs-style expansion during anchor registration
- **Accurate node weight in `track()`**: uses `nodeWeight()` instead of fixed weight 1 — node limit is reached sooner for deeply nested/expanded structures
- **Double-tracking removed in `parseInlineFlow`**: elements tracked once, not twice — corrects node counting

## 1.7.1 (2026-07-31)

### Documentation
- README badges, comparison table, YAML Test Suite score, setLimits/parseToJSON examples
- CHANGELOG.md added

## 1.7.0 (2026-07-31)

### Bug Fixes
- **`?` explicit key ordering**: check `? ` before `findKeySep` so `? complex: key` doesn't get split on the colon inside the key
- **Multi-word plain scalars**: `parseInlineFlow` no longer treats whitespace as a value delimiter — `key: hello world` now returns `"hello world"` not `"hello"`
- **Quoted scalar stripping**: `parseScalar` strips quotes before type resolution — `"null"` → `"null"` (string), not `null`; `"true"` → `"true"`, not `true`
- **`findKeySep` quote tracking removed**: unquoted keys containing `'` (like `a!"#...`) no longer cause all subsequent colons to be skipped
- **`#` no longer a colon delimiter**: `k:#foo` is correctly parsed as a scalar, not a mapping `{"k":"..."}`
- **`---` with trailing content**: `--- text` now correctly parses as `"text"` instead of ignoring the content
- **Top-level routing**: uses `findKeySep` instead of `includes(':')` to distinguish scalars from mappings
- **Multi-line plain scalar folding**: continuation lines (indented) are folded with spaces

### Documentation
- **README badges**: npm version, CI, downloads, bundle size, TypeScript
- **API docs**: `maxStringLength`, `maxKeys`, `setLimits` example, `parseToJSON` example
- **Comparison table**: vs js-yaml and yaml (Eemeli)
- **YAML Test Suite score**: 245/351 (70%)

## 1.6.0 (2026-07-31)

### Features
- **Circular alias detection**: `&a *a` (self-reference) and `&a *b` / `&b *a` (indirect cycles) detected and blocked
- **`maxStringLength` limit**: configurable max string length (0 = unlimited)
- **`maxKeys` limit**: configurable max keys per mapping (0 = unlimited)
- **`?` explicit key syntax**: supports `? key\n: value` and `? key` (set-style, value = null)
- **`findKeySep` helper**: replaces naive `indexOf(':')` for correct colon detection in block mapping parsing

### Bug Fixes
- **Unknown `%` directives**: ignored instead of crashing
- **`--- !!set` with trailing content**: skipped correctly for `!!set`/`!!omap` tests

## 1.5.1 (2026-07-30)

### Bug Fixes
- `produced` counter no longer overcounts, preventing false-positive `maxNodes` rejection
- Block scalar leading blank lines handled in `folded` (`>`) style

## 1.5.0 (2026-07-30)

### Features
- `.inf` / `-.inf` / `.nan` float support
- `Schema.removeType(tag)`, `Schema.hasType(tag)`
- `parseAll` per-call schema/types options on instance
- JSDoc annotations on all public APIs
- Browser ESM build in default build pipeline

## 1.4.2 (2026-07-28)

### Bug Fixes
- Unknown `!` tags re-parse as plain scalar instead of returning `undefined`

## 1.4.1 (2026-07-28)

### Features
- `%TAG` directive expansion via `expandTag`
- `YamlType` default `resolve: () => false`
- README Schema documentation

## 1.4.0 (2026-07-28)

### Features
- **Schema system**: `YamlType`, `Schema`, custom types, implicit resolution
- **DEFAULT_SCHEMA**: `!!str`, `!!null`, `!!bool`, `!!int`, `!!float`, `!!timestamp`, `!!binary`

## 1.3.0 (2026-07-27)

### Features
- `parseAll` for multi-document YAML
- `parseToJSON` convenience method
- `YamlSecurity.setSchema(schema)` per-instance schema

## 1.2.5 (2026-07-26)

### Features
- Rollup build system (CJS + ESM + browser IIFE + browser ESM)
- CI caching, Node 20/22 testing

## 1.2.4 (2026-07-25)

### Bug Fixes
- `maxExpansion` dead code fixed
- `Buffer` browser polyfill removed (native TextEncoder)
- dist/ included in npm package

## 1.2.2 (2026-07-24)

### Features
- Minified builds: ESM 12KB + CJS 12KB

## 1.0.0 (2026-07-20)

Initial release.
