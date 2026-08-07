# Architecture — YAML Security Lib

Zero-dependency YAML 1.2 parser with security hardening. The whole library
lives in a single source file: `src/index.js` (~5100 lines). It provides two
independent parsing engines — a **batch** parser and a **streaming** parser —
that must agree on the same YAML semantics, plus a dumper, a schema system,
an AST/tree renderer, a validator and a linter.

```
src/
  index.js     core parser/dumper/schema/AST/stream (single file)
  validate.js  runtime schema validation (`validate`, `createStreamValidator`)
  lint.js      YAML lint rules (syntax/security/style)
bin/
  yaml-lint.js CLI wrapper around the linter
```

---

## 1. Two engines, one contract

| | Batch (`yamlToJS`) | Streaming (`StreamParser`) |
|---|---|---|
| Input | Full string at once | Line-delimited chunks via `.write()` |
| Output | A single JS value (or `parseAll` → array of docs) | SAX events + a `document` event per doc |
| Memory | Whole tree in memory | Incremental; reassembles docs only in buffered mode |
| Oracle | YAML Test Suite + js-yaml v5 | `js-yaml.loadAll` (fuzz oracle) |
| Entry points | `parse`, `parseAll`, `YamlSecurity.parse` | `createStream`, `parseStream`, `YamlSecurity.createStream` |

Both engines share the same low-level helpers and the same security checks:

- `safeAssign()` — the single choke point for mapping writes (prototype pollution guard)
- `unescapeYaml()` — double-quoted escape sequences
- `foldFlowScalar()` — flow-scalar folding
- `findKeySep*` / `compactQuotedKeySep` / `blockKeySepTop` / `flowKeySepTop` — colon / key-separator scanning
- The schema (implicit type resolution)

A high-level contract is enforced by the test suite: batch and streaming
results must match each other and match `js-yaml` on the streaming fuzz corpus.

---

## 2. The batch parser

### 2.1 Pipeline

```
parse(yamlStr)
  └─ yamlToJS(yamlStr, cfg, 0, schema)        single document
parseAll(yamlStr)
  └─ parseAllYaml(...)                        splits at ---/...
        └─ yamlToJS(...)                      per document
```

`yamlToJS` is a recursive-descent parser:

1. **Directive scan** — handles `%YAML`, `%TAG`, `---`/`...` markers at the top
   of the input (`src/index.js` "Process YAML directives & markers").
2. **Anchor pre-scan** — a best-effort pass registers anchors before the real
   parse so that aliases used before their anchor line resolve correctly.
3. **Root dispatch** — decides the top-level node shape:
   - block scalar header (`|`, `>`) → `extractBlockScalar`
   - leading `&anchor` / `!tag` property lines → tag/anchor root node
   - flow root (`[`, `{`) → `parseInlineFlow`
   - tag-only root (`!!map`, `!foo ...`) → tagged node
   - root plain scalar (no key separator) → folded scalar
   - otherwise → `parseBlock`
4. **`parseBlock`** — the workhorse: walks lines by indentation, emitting
   mapping/sequence entries. Recurses into `parseBlock` for nested blocks and
   `parseInlineFlow` for flow values.

### 2.2 State threading

`yamlToJS` threads a single `state` object through every recursion:

- `anchors` / `anchorDepths` / `anchorSources` — anchor registry (alias chains)
- `produced` / `aliasHits` — running counters for `maxNodes`, `maxExpansion`, `maxAlias`
- `nodeWeights` — memoized subtree weights (aliased nodes are charged for every reference)
- `mergeOverrideKeys` — keys explicitly set at a level, to detect `<<` override attempts
- `_ast` / `_astOn` / `_astSuppress` — optional AST event collector

### 2.3 Key helper functions (batch)

| Function | Purpose |
|---|---|
| `parseScalar(s)` | Typed scalar resolution: quotes, folding, tags, implicit types |
| `parseInlineFlow(str, ...)` | Flow node parser → `{ value, endPos }` |
| `parseBlock(...)` | Block mapping/sequence parser |
| `extractBlockScalar(...)` | Collect + fold `|`/`>` block scalars |
| `foldFlowScalar(input)` | js-yaml port of flow-scalar line folding |
| `findKeySep(str, start)` | First block key-separator `:` (outside quotes/flow) |
| `compactQuotedKeySep(str)` | PyYAML-style `"a":b` key detection |
| `flowKeySep(s)` | Key separator inside a flow item |
| `flowScalarKeySep(s)` | `:` that would start a key inside a flow plain scalar |
| `scanFlowItemEnd(s)` | End of a flow item (`,`/`]`/`}` at depth 0) |
| `getIndent` / `contentIndent` | Indentation detection (tabs rejected for structure) |
| `splitPlainComment(line)` | Comment extraction from a plain-scalar line |
| `setAnchor` / `resolveAlias` / `track` | Anchor registry, alias expansion, limit charging |
| `resolveMerges(v)` | Post-parse `<<` merge-key resolution |

---

## 3. The streaming parser

`StreamParser` is a line-fed, event-emitting state machine. Public flow:

```
createStream(opts)
  ├─ .on(type, cb) / .on('*', cb)
  ├─ .write(chunk)      → buffers to complete lines → _feedLine(line)
  ├─ .end()             → flush pending state, emit documentEnd + end
  └─ for await (ev of parser)   (async iterable of events)
parseStream(input, opts)  → async generator yielding whole documents
```

### 3.1 State machine modes

`_feedLine` dispatches on the current mode:

- **pendingBlock** — collecting a `|`/`>` block scalar (`_feedBlockLine`).
- **rootMode: 'flow'** — a root flow collection, accumulated until `_flowBalanced`.
- **pendingFlow** — an inline flow value spanning lines.
- **rootMode: 'scalar'** — a root plain scalar (`_rootScalarLines`).
- **normal** — document markers (`---`/`...`), directives (`%TAG`), then content.

Content lines route through `_handleContentLine`, which decides between:

- `_handleSeqItem` — `- ...` sequence dashes
- `_parseMapKey` / `_handleMapKey` — mapping entries
- `_handleBareScalar` — plain scalar values / root scalars
- pending-scalar continuation handling (quoted + plain folding)

### 3.2 Context stack

Each open mapping/sequence is a **context** (`_openMap` / `_openSeq`) holding:

- `kind`, `indent`
- key registry (`keys`, `pendingKey`, `expectValue`) for maps
- item state (`pendingItem`, `pendingEmpty`, `lastInlineIndex`, `replaceInline`) for seqs
- `anchor` / `valueAnchor` bookkeeping
- `node` — the partially-assembled JS value (buffered mode only)

Indentation governs stack depth: a line with smaller indent than the top
context closes it (`_closeTop`). Closing attaches the finished node to its
parent (`_attachToParent`) and applies `<<` merge semantics (`_finalizeMap`).

### 3.3 Retraction

A sequence item that first parses as an inline scalar but is followed by an
indented block node (`- a\n  b: c`) must be replaced. `_retractSeqInline`
pops the provisional scalar and marks the index for replacement.

---

## 4. Security model

Every check is enforced identically in both engines.

| Limit | Default | Where enforced |
|---|---|---|
| `maxNodes` | 10,000 | `track()` (batch), `_count()` (stream) |
| `maxExpansion` | 100,000 | same (weighted, alias bombs) |
| `maxAlias` | 100 | `resolveAlias()` / `_resolveAlias()` |
| `maxAliasDepth` | 10 | `setAnchor()` / `_registerAnchor()` |
| `maxInputMB` / `maxInputBytes` | 1 MB | entry of `yamlToJS` / `parseAllYaml` / `write()` |
| `maxStringLength` | 0 (unlimited) | `track()` / `_checkString()` |
| `maxKeys` | 0 (unlimited) | `addKey()` / `_addMapKey()` / flow parsers |
| `maxDepth` | 50 | `parseBlock` recursion guard |

### 4.1 Prototype pollution

`safeAssign(obj, key, value)` refuses `__proto__`, `constructor` and
`prototype` keys with a `Security:` error. Every mapping entry in both engines
writes through it — block mappings, flow mappings, sequence-item mappings,
merge-key output and stream assembly — so a polluted key cannot slip through
any path.

### 4.2 Duplicate keys

Keys are tracked per mapping level (`seenKeys` in batch, `ctx.keys` in
stream). A repeated key throws `Duplicate key: "..."`. Merge keys use the
override set to catch `<<` overwriting an explicit key.

### 4.3 Alias bombs

`track()`/`nodeWeight()` charge an aliased node's full subtree weight on every
reference (`&a` + 100 `*a` grows the produced count geometrically) so
billion-laughs style documents are rejected before expansion completes.
`setAnchor` also tracks alias-source chains (`anchorSources`) and rejects
circular aliases.

### 4.4 Compact quoted-key mappings

`"a":b` (a quoted key with the value attached to the `:`) is accepted
PyYAML-style — js-yaml rejects it. Because the shape builds a real mapping
entry, the duplicate/prototype checks above fire on its keys automatically.
`compactQuotedKeySep` detects the shape at root, block-value and sequence-item
positions in both engines.

---

## 5. Schema system

- `YamlType` — a tag + kind + `construct`/`resolve` functions.
- `Schema` — a registry: `_explicit` (tag → type) + `_implicit` (resolution order).
- `DEFAULT_SCHEMA` — `null`, `bool`, `int`, `float`, `timestamp`, `binary`, `str`.

Implicit resolution runs through `_implicit` in registration order. **YAML 1.2
core invariant: implicit timestamps stay strings** — `2023-01-15` → `"2023-01-15"`,
never a `Date`; only an explicit `!!timestamp` constructs a `Date`. This is
enforced in both `parseScalar` (batch) and `resolveScalarTop` (stream).

Custom schemas: pass `schema` (a `Schema`) or `types` (an array of `YamlType`)
to any parse-family API; `Schema.addType`/`removeType` mutate an existing schema.

---

## 6. AST / tree system

The parser can collect a flat **event stream** while parsing:

- `{ t: 'doc', s, e }` — document boundaries
- `{ t: 'c', k: 'map'|'seq', s: 0|1, a, g }` — container open (block/flow, anchor, tag)
- `{ t: 'x', k }` — container close
- `{ t: 'v', c, s: 1..5, a, g }` — scalar (style id: plain/single/double/literal/folded)
- `{ t: 'al', n }` — alias

Two consumers render it:

- `tree()` → `renderTree(events)` — yaml-test-suite-style text event tree
- `parseTree()` → `assembleAST(events)` — nested document AST (JSON)

This is what powers the YAML Test Suite event comparisons (262/262 conformance
cases) and the `!!` event-style outputs.

---

## 7. Dumper

`yamlDump(value, opts)` — block style until `flowLevel`, then flow style.
Quoting rules prevent ambiguous output (empty, boolean/number-looking, `: ` or
comment markers). Options: `indent`, `flowLevel`, `sortKeys`, `lineWidth`,
`forceQuotes`, `quotingType`. Circular references throw.

---

## 8. Validator & linter

- `src/validate.js` — builder API (`s.object({...})`, `s.array(...)`, ...),
  `validate(value, spec)` for batch, `createStreamValidator(spec)` for
  incremental validation during streaming (emits `violation` events).
- `src/lint.js` — `lint(yaml, options)` returns `{ valid, issues, errors, warnings }`
  and a `LINT_RULES` list; the CLI `bin/yaml-lint.js` wraps it.

---

## 9. Public API surface

| Export | Kind | Description |
|---|---|---|
| `parse` / `parseAll` | function | Parse one / all documents |
| `dump` | function | Serialize to YAML |
| `tree` / `parseTree` | function | Event tree / AST |
| `validateYaml` | function | Parse + validate, never throws |
| `YamlSecurity` | class | Error-safe instance API (`.parse`, `.parseAll`, `.dump`, `.tree`, `.parseTree`, `.validate`, `.createStream`, `.parseStream`) |
| `setLimits` | function | Global limit overrides |
| `YamlType` / `Schema` / `DEFAULT_SCHEMA` | class/const | Schema system |
| `createStream` / `parseStream` | function | Streaming API |
| `renderTree` / `assembleAST` | function | Event rendering |
| `lint` / `LINT_RULES` | function/const | Linting |
| validator builder | functions | `s`, `string`, `int`, `object`, `validate`, `createStreamValidator`, ... |
| `YAMLException` | class | Error with optional `mark` (`{ line, column, snippet }`) |

---

## 10. Invariants to preserve

1. Batch and streaming engines must agree on values.
2. Streaming matches `js-yaml` v5 (the oracle) via `loadAll` on multi-doc streams.
3. Implicit timestamps stay strings (YAML 1.2 core).
4. Every mapping write goes through `safeAssign` (prototype-pollution guard).
5. `parse()` / `parseAll()` and the `YamlSecurity` instance API must not throw —
   they return `{ ok, ... }`; only the low-level `yamlToJS`/`parseAllYaml`
   throw raw `YAMLException`s.

## 11. Testing

```bash
npm test        # index.js + fuzz.js + stream.js + stream-fuzz.js
```

- `test/index.js` — unit + security + limits
- `test/fuzz.js` — invariant/security fuzz (batch)
- `test/stream.js` — streaming API
- `test/stream-fuzz.js` — js-yaml oracle fuzz (streaming)
- YAML Test Suite — 406 cases, 100% (351 files), event tree 262/262
