# Changelog

## 1.12.2 (2026-08-07)

### Fixes: block plain-scalar continuation folding parity with js-yaml (batch + stream)
- **Batch now folds any deeper continuation line into an inline plain scalar**, whatever its leading indicator — `key: a\n  - b` → `"a - b"`, `key: a\n  "b"`, `key: a\n  &x b`, `key: a\n  ? b`, `key: a\n  |\n  text`, `key: a\n  *ref`, `key: a\n  !tag x`, `key: a\n  ---`/`...`. Previously the dash/anchor/quoted-key/`?` handlers intercepted these and threw. The continuation check now runs at the top of the block loop, before those handlers.
- **Sequence items fold too**: `- a\n  - b` → `["a - b"]`, `- a\n  b` → `["a b"]`.
- **Root plain scalars**: a deeper-indented `...`/`---` folds (`a\n  ...` → `"a ..."`), while a column-0 marker still ends the document (`a\n...` → `"a"`); a `...`/`---` containing a `: ` separator still throws `bad indentation of a mapping entry`.
- **Streaming multi-document fixes**: a column-0 `...` now correctly ends a root-scalar document and subsequent content starts a new document (`a\n...\nb: 1` → `["a", {b: 1}]`); an empty second document emits `null` instead of the stale first document value; deeper-indented `...`/`---` inside a plain scalar fold instead of closing the document.
- Tests: `test/index.js` +14, `test/stream.js` +12. Full suite green: 201 + 262 + 124 + 1645 + 406 (YAML Test Suite) + 262 + 95 + 60.

## 1.12.1 (2026-08-07)

### Fixes: plain-scalar `:` parsing parity with js-yaml (batch + stream)
- **Missing commas between flow entries are now rejected** (`{a: 1 b: 2}`, `[a: 1 b: 2]`). Previously a plain scalar tail swallowed the implicit next key; now the flow parser stops a plain scalar at the key-separator colon and throws `missed comma between flow collection entries`, matching js-yaml.
- **Block plain scalars cannot contain a `: ` key separator** (`key: a: b`, `key: a\n  b: c`, `key: a: # comment`). Previously these parsed as scalars; now they throw `bad indentation of a mapping entry` like js-yaml. Attached colons stay literal (`key: a:b`, `key: http://x`, `key: 10:30:00`).
- **Streaming plain-scalar continuations now fold js-yaml-style** (`key: a\n  - b` → `"a - b"`, `key: a\n  [1, 2]`, `key: a\n  {b:c}`), instead of the old code that truncated/ignored deeper continuation lines.
- `? key\n: a: b` explicit-key values still parse permissively (`{ key: { a: "b" } }`).
- Tests: `test/index.js` +30 (flow missing-comma, block `: ` rejection, block continuation), `test/stream.js` +21 (same coverage + folding). Full suite green: 187 + 262 + 112 + 1645 + 406 (YAML Test Suite) + 262 + 95 + 60.

## 1.12.0 (2026-08-07)

### New: YAML linter
- New `lint(yaml, options)` API returning `{ valid, issues, errors, warnings }` with per-issue `rule`, `severity`, `line`, `column`, and `snippet`.
- New `bin/yaml-lint.js` CLI (`yaml-lint` binary): lint files or stdin, `--json`, `--max-line-length`, `--help`, `--version`; exit code `1` on error-severity issues, `2` on IO/usage errors.
- `LINT_RULES` (frozen) lists the 10 default rules; `rules` option supports an array (enable only those) or a map (per-rule severity/off). Unknown rule names throw `TypeError`.
- Rules:
  - **error** — `syntax-error`, `duplicate-key`, `anchor-bomb`, `prototype-pollution`.
  - **warning** — `trailing-spaces`, `line-length` (default 120, `maxLineLength` option), `missing-newline-at-eof`, `space-after-colon` (URLs skipped), `space-after-dash` (numbers like `-5` skipped), `truthy-yes-no` (unquoted yes/no/on/off).
- Syntax + security rules reuse `YamlSecurity().parseAll`, so multi-document YAML (`---` separated) lints correctly.
- Linter lives in `src/lint.js` (parser injected to avoid a circular dependency); bundled by rollup into ESM/CJS/browser builds.
- TypeScript declarations added to `src/index.d.ts` (`LintIssue`, `LintResult`, `LintOptions`, `lint`, `LINT_RULES`).
- README: new "Linter" section documenting the API, rules table, options, and CLI usage.
- Tests: new `test/lint.js` suite (60 assertions) wired into `npm test`; added `npm run lint` script (CLI smoke test).

## 1.11.0 (2026-08-06)

### New: Schema Validation system
- New `src/validate.js` (zero-dep, bundled by rollup) with a Zod-like fluent builder (`s.string`, `s.int`, `s.number`, `s.bool`, `s.null`, `s.any`, `s.never`, `s.enum`, `s.timestamp`, `s.array`, `s.tuple`, `s.object`, `s.record`, `s.optional`, `s.nullable`, `s.oneOf`, `s.anyOf`, `s.allOf`, `s.not`, `s.custom`).
- `validate(value, spec)` → `{ ok, errors }` with JSON-pointer-like paths (`$.a.b[0]`).
- `validateYaml(yamlStr, spec)` → `{ ok, value, errors }` (never throws; parse errors captured as `$` errors).
- `fromJSONSchema(js)` / `toJSONSchema(spec)` — JSON Schema (draft-07 subset) bridge incl. local `$ref`/`$defs`.
- **Streaming integration**: `createStream({ validate: spec, abortOnError })` emits `violation` events incrementally as the SAX events arrive; `abortOnError` aborts on the first violation via an `error` event (early rejection before consuming the rest of the input). `parseStream(input, { validate })` yields `{ value, errors }` per document.
- `createStreamValidator(spec)` exported for custom event-driven consumers.
- `YamlSecurity` gained `validate(value, spec)` and `validateYaml(str, spec)` methods.
- Fixed a pre-existing streaming quirk: `_assignValue` now clears its slot bookkeeping even in `anchors: 'disable'` mode (previously emitted a spurious trailing `scalar=null` event).
- Tests: `test/validate.js` (95 assertions) wired into `npm test` and CI.

## 1.10.5 (2026-08-06)

### Docs & Types
- Documented the remaining public exports: `parseTree`, `renderTree`, `assembleAST` (with `TreeNode` / `TreeEvent` / `TreeDocument` types), and `getBaseConfig`, `unescapeYaml`, `byteLength` in README + `src/index.d.ts`.

## 1.10.4 (2026-08-06)

### Tooling
- `npm test` now also runs `test/yaml-test-suite.js` (406 cases) and `test/tree-suite.js` (262 + 82 expected throws); both skip cleanly when `YAML_SUITE_DIR` is not present.
- Added `prepack` script that rebuilds the CJS/ESM bundles automatically, so `npm publish`/`npm pack` can never ship stale bundles again.
- CI: clones the official YAML Test Suite and runs both conformance suites on Node 20/22.
- README: documented the `tree()` API and updated the testing section.

## 1.10.3 (2026-08-06)

### Citation
- **Zenodo DOI badge corrected to the permanent concept DOI: [10.5281/zenodo.21684897](https://doi.org/10.5281/zenodo.21684897)** — the DOI is stable and does not change between releases.
- **ORCID: [0009-0008-4915-4787](https://orcid.org/0009-0008-4915-4787)**

## 1.10.2 (2026-08-06)

### Packaging
- **Rebuilt bundles**: `src/index.cjs`, `src/index.min.js` and `dist/` now ship the `tree()` export (previously stale — npm consumers got a version without the tree event stream).
- **TypeScript**: `tree()` declared in `src/index.d.ts`.
- **Tests**: `test/tree-suite.js` added to `npm test` (all suites green: 127 + 262 + 51 + 1645 + 262 tree).

### Citation
- **Zenodo DOI: [10.5281/zenodo.21684897](https://doi.org/10.5281/zenodo.21684897)** — same DOI as v1.10.0; a new DOI is minted per future release.
- **ORCID: [0009-0008-4915-4787](https://orcid.org/0009-0008-4915-4787)**

## 1.10.1 (2026-08-06)

### Tree Event Stream (`tree()`)
- **100% YAML Test Suite tree conformance (262 / 262 tree-block cases)** — `tree()` now emits the exact `+STR`/`+DOC`/`+MAP`/`+SEQ`/`=VAL`/`=ALI` event stream the suite expects, with scalar styles (`:` plain, `'` single, `"` double, `|` literal, `>` folded), anchors, tags and flow-style markers.
- **`PW8X`**: the anchor pre-scan's `anchors[aname] !== undefined` early-return leaked `state._astSuppress`, silently dropping every tree event from later recursive `yamlToJS` calls (empty-dash sequence items, explicit-value compact maps). Fixed by decrementing the suppression counter before the early return.
- **`M2N8`**: explicit keys whose content is itself a compact mapping (`? : x`, `? []: x`) are now re-parsed as their own block node; previously the `: value` half of the key was dropped and the key emitted as a bare scalar.
- **`9MMW`**: in flow context a `:` directly after a quoted token or a closed flow collection (`"JSON like":adjacent`, `{JSON: like}:adjacent`) is now recognized as a key separator, so single-pair flow items with flow/quoted keys emit the expected `+MAP {}` pair.
- **Harness** (`/tmp/opencode/tree-conformance.mjs`): extraction of `yaml:`/`tree:` blocks now stops at the next test case, restoring a sane compared count (344 files).
- **Tests**: new `test/tree-suite.js` regression suite — **262 matched, 0 failed, 0 errored, 82 expected throws**.

### Citation
- **Zenodo DOI: [10.5281/zenodo.21684897](https://doi.org/10.5281/zenodo.21684897)** — archived at v1.10.0; this patch release shares the same DOI.
- **ORCID: [0009-0008-4915-4787](https://orcid.org/0009-0008-4915-4787)**

## 1.10.0 (2026-08-05)

### YAML Test Suite Conformance
- **406 / 406 test cases passing (351 files, 100%)** — every official YAML Test Suite case now passes, including the previously-failing edge cases below.

### Improvements — Anchors & Aliases
- **Anchor/alias names may contain `:`** (`&a:` / `*a:`): `findKeySep` no longer treats a colon inside an `&`/`*` token as a key separator (YAML 1.1).
- **`2SXE` anchor-on-key with colon in name**: `&a: key: &a value\nfoo:\n  *a:` now yields `{"key":"value","foo":"key"}`.
- **Alias as block value**: a lone `*alias` continuation line (e.g. `b:\n  *x`) resolves to its anchored value, matching inline `b: *x`.
- **Pre-scan safety errors propagate**: the best-effort anchor pre-scan silently skips benign parse noise (mapping entries with anchor-on-key), but re-throws safety-limit errors (alias bomb, alias depth, circular alias) so the protections can never be bypassed.
- **Root anchor intercept refinements** (`rootAnchorHasSibling`, `!rest.startsWith('!')`): a root `&anchor scalar` is only intercepted when it is truly a lone plain scalar; sibling lines and tag-suffixed anchors fall through to the block parser (`9KAX`/`KSS4`).

### Improvements — Blocks, Tags & Flow
- **`735Y`**: `splitProps` treats a trailing `# comment` after a sequence item's property line (`- !!map # comment`) as the line terminator instead of part of the key.
- **`M5C3`**: a standalone block-scalar indicator line (`|2`, `>-`, `>1`) following tag/anchor property lines becomes the key's value (off-by-one fixed: `i = bs.next`).
- **`4JVG`**: two anchors on one entry (`key: &a` then `&b v`) rejected with "bad indentation of a mapping entry", matching js-yaml.
- **`565N`**: `!!binary` with a folded double-quoted value spanning lines (`\` continuations) yields a Buffer; quoted `!!binary` values stay strings (no base64 decode).
- **`CN3R`**: flow anchors pre-scanned only when the flow collection is closed; `&anchor ` stripped from flow-mapping keys (`&c c:` → `c:`).
- **`CT4Q`**: explicit `?` keys in flow sequences (`[? foo\n bar : baz]`) parsed as implicit mappings.

### Tests
- `test/yaml-test-suite.js`: switched to `parseAll` with per-document JSON comparison (`splitJsonValues`), enabling multi-document checks; **406 passed, 0 failed, 0 errored**.
- `test/index.js`: 127 passed; `test/fuzz.js`: 262 passed; `test/stream.js`: 51 passed; `test/stream-fuzz.js`: 1645 passed.

## 1.9.0 (2026-08-04)

### YAML Test Suite Conformance
- **313 / 351 tests passing** (up from ~245 in v1.8.1 — ~68 new fixes).

### Improvements — Block Parser (`parseBlock`)
- **`findKeySep` overhaul**: quote-aware scanning (handles `"` and `'` with escapes), flow depth tracking (colon inside `[]`/`}` is not a key separator), mid-token quotes (`bla"keks`) treated as literal, `\n`/`\r` accepted as after-colon separators.
- **Tab indentation relaxation**: leading tabs are tolerated when followed by a flow collection (`[`, `{`), a comment (`#`), or nothing (tab as separation per YAML spec). Strict `getIndent` still rejects tabs for keys and sequence items; a new `contentIndent` helper handles scalar content.
- **Flow helpers**: `flowKeySep()` detects `: ` inside flow sequence items (implicit mapping detection), `scanFlowItemEnd()` finds `,`/`]`/`}` boundaries at flow depth 0, `tagContentValue()` extracts values after `!tag` prefixes.
- **Explicit key gather loop**: added `findKeySep(t) >= 0` break condition for same-indent mapping entries; fixed line-skipping via `i = vi - 1; continue`.
- **Sequence empty/comment items**: empty dash items (`- `, `- #comment`) now resolve to `null` in both the tree and streaming parsers.
- **Alias comment stripping**: clean up trailing comments from alias values.
- **BlockEnd scan**: break when `getIndent === indent && !startsWith('-')`.

### Improvements — Double-Quoted Strings (`unescapeYaml`)
- Added `\t` escape mapping.
- Hex digit validation for `\x`, `\u`, `\U` — short sequences now throw.
- Unknown escape sequences throw instead of silently returning the character.

### Improvements — Streaming Parser
- Empty sequence items (`- `) now emit `null` instead of `""`, matching the tree parser and YAML 1.2 spec.

### Improvements — Flow Collections
- **Flow implicit mapping in block sequences**: `- key: val` detected as implicit mapping items via `flowKeySep` lookahead; handles `- {map}`, `- [seq]`, empty items → `null`.
- **Flow implicit mapping in flow mappings (`{...}`)**: plain-key `?` prefix stripping, newline fold for plain scalars, tag parse via `parseScalar`, comment skip before/after `:`, empty value → `null`, tag prefix terminator guard.

### Tests
- `test/stream.js`: 51 → 51 (updated `dash alone` expectation to `null`)
- `test/yaml-test-suite.js`: 313/351 passing

## 1.8.1 (2026-08-03)

### Bug Fixes (Streaming Parser)
- **Multi-line plain scalars in block context**: inline values (`b: line1`) now fold continuation lines correctly (`b: line1\n  line2` → `"line1 line2"`); previously only the first line survived. Applies to map values and sequence items at any nesting depth.
- **Multi-line double/single-quoted scalars**: unterminated quotes (`a: "line1\n  line2"`) now accumulate lines and fold to a single space, matching reference parsers; previously the value was truncated after the first line.
- **Root multi-line scalars**: root plain scalars with a continuation line at indent 0 now fold like reference parsers (`line1\nline2` → `"line1 line2"`), including quoted roots.
- **Nested sequence items with empty-value map keys** (`- a:\n    line1\n    line2`): the map header is no longer folded into a scalar; it opens the nested mapping correctly.
- **Implicit timestamps resolve to strings**: plain scalars like `2023-01-15` now stay strings (YAML 1.2 core + reference-parser behavior) instead of becoming `Date` objects. Explicit `!!timestamp` tags still construct a `Date`.
- **Delayed scalar emission**: inline plain map values are now emitted lazily so continuation folding never requires a retroactive event retraction (except pathological `- -` indentation, tracked via the parser's `retractions` counter).

### Tests
- New `test/stream-fuzz.js` (4 layers): exhaustive split-point consistency, SAX event-replay reconstruction, 400 seeded random-grammar docs compared value-for-value against `js-yaml` (test-only devDependency), and 6 security bomb shapes. **1645 assertions, 0 failures.**
- `test/stream.js` updated to 52 assertions (51 pass) with explicit `datetime` expectation (strings).

### Follow-up fixes (same 1.8.1 release)
- **Parse-path timestamp bug**: `resolveMerges` treated every `Date`/`Uint8Array`/`Buffer` as an empty map, so `parse('a: 2023-01-15')` returned `{a: {}}`. Non-map leaves are now passed through untouched.
- **parse/stream consistency**: `parse()` implicit timestamps now resolve to strings (YAML 1.2 core), matching the stream; explicit `!!timestamp` still yields a `Date`.
- **CI fix**: `npm ci` failed on fresh installs because `package-lock.json` was stale (missing `js-yaml`, version stuck at 1.7.6). The lockfile was regenerated and the fuzz oracle upgraded to **js-yaml v5** (YAML 1.2 core — timestamps as strings). The stream-fuzz oracle must stay on v5; js-yaml 4.x (YAML 1.1, `Date` timestamps) fails ~28 assertions.
- **CI coverage**: `test/stream.js` and `test/stream-fuzz.js` added to `.github/workflows/ci.yml` (`stream-fuzz.js` runs after `npm ci` since it needs the js-yaml oracle).
- New unit tests for implicit/explicit/nested timestamps (127 total).

## 1.8.0 (2026-08-03)

### New Feature: Streaming Parser
- **`StreamParser`** (SAX-style): incremental push parser with `write()` / `end()` / `abort()` and event hooks — `documentStart`, `mappingStart`, `sequenceStart`, `key`, `scalar`, `mappingEnd`, `sequenceEnd`, `documentEnd`, `error`, `end`, plus a `document` convenience event
- **`createStream(opts?)`**: creates a streaming parser
- **`parseStream(input, opts?)`**: async generator yielding each document as it completes; accepts a string or any (async) iterable of chunks
- **`YamlSecurity.createStream()` / `YamlSecurity.parseStream()`**: instance-bound streaming API (uses the instance's schema)
- **Security enforced while streaming**: `maxInputBytes` per `write()`, `maxNodes` / `maxKeys` / `maxStringLength` per node/key/scalar, `maxDepth` on stack push, `maxAlias` / `maxAliasDepth` on alias resolution, merge-key `<<` overwrite guard, duplicate-key and tab-indentation errors
- **Anchors**: `anchors: 'buffer'` (default, supports `&`/`*`) vs `anchors: 'disable'` (rejects anchors outright for true zero-buffering)
- **Parsing coverage**: block maps/sequences, flow `[`/`{`, block scalars `|`/`>`, explicit keys, anchors/aliases, merge keys, multi-line plain scalars, quoted keys, top-level flow/scalar docs, `---`/`...` markers, `%TAG` directives, multi-document streams
- Streaming parser is async-iterable (`for await (const ev of stream)`)

### Tests
- New `test/stream.js` (51 cases): round-trip parity with `parse`/`parseAll`, event-stream correctness, `parseStream` string + chunked input, `anchors: 'disable'`, limit enforcement, `YamlSecurity.createStream`

### Documentation
- **README**: new "Streaming API" section, comparison table row, anchor strategy notes
- **TypeScript defs**: `StreamParser`, `StreamEvent`, `StreamOptions`, `createStream`, `parseStream`, `YamlSecurity.createStream/parseStream`

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
