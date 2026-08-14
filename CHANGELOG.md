# Changelog

## 1.17.7 (2026-08-14)

### Fix & hardening: `maxAliasDepth` is now true resolve-time graph depth

- **`maxAliasDepth` previously only counted direct `&a *b` links.** A chain threaded through a flow or block collection — `&a [*b]`, `key: &a\n  v: *b`, `x: &a {<<: *b}` — registered depth 0/1 and could climb without bound (`&a [*b]`, `&b [*a]`, …). That anchor-bomb family was closed only by `maxExpansion`/`maxNodes` at high values, not by the depth cap.
- **Depth is now measured when an alias resolves**, in both engines: resolving `*x` walks the anchor-source chain (`anchorSources`) from `x` to its root and rejects when the hop count exceeds `maxAliasDepth` (`YAML: alias depth exceeds limit (N), possible anchor bomb`). Because the walk happens at resolution time, it sees every edge regardless of how the anchor value was built — direct, flow-wrapped, nested-block, or merge-key chains.
- **How the source edge is captured:** a per-document build-stack records the deepest alias resolved while any anchorable value is being assembled (flow collections, block values, nested blocks, root). `setAnchor` stores that source alongside the value, so `anchorSources` reflects the true graph and the resolve-time walk is exact. Every build site is balanced via `try/finally` (including the best-effort pre-scan, whose non-safety errors are swallowed), so an aborted parse can never leak a frame into the next document.
- **Behaviour change:** a document whose *effective* alias chain exceeds the limit now errors even when every link is collection-wrapped or deferred into a nested block; values at exactly `==` the limit still parse (limits are strict-`>`). The direct `&a *b` form is unchanged (still rejected by the "alias node should not have any properties" rule), and `maxExpansion`/`maxNodes` remain independent guards.
- **Tests:** new batch + stream cases — seq/map-wrap chains above the limit, `==`-limit acceptance with value-content checks, nested-block chains, deferred flow values (`key: &a\n  [*b]`), merge-key chains, and a pre-scan frame-leak regression (a swallowed non-safety error must not enable a later wrapped chain).

## 1.17.6 (2026-08-14)

### Fix & hardening: alias/anchor correctness + schema ReDoS guard

- **Security: schema-regex ReDoS guard.** A schema `pattern` or `patternProperties` key is now scanned before use (`compileSafePattern`); catastrophic patterns — nested quantifiers (`(a+)+b`), nullable loops (`(a*)*`, `(a|)` inside a repeat), ambiguous alternations inside a quantifier (`(a|aa)+`), and adjacent unbounded repeats over overlapping first chars (`a+a+`) — are refused with `unsafe regex pattern — possible catastrophic backtracking`, in the batch and streaming validators alike. A crafted input that previously hung for ~9 s now errors in single-digit milliseconds. Conservative by design: bounded quantifiers, disjoint alternations (`(a|b)`, `(ab|cd)`), and repeats separated by a literal (`a+@b+`, e-mail shapes) are untouched.
- **Fix: undefined aliases are now errors.** `main: *nope` previously parsed to `{ main: 'nope' }` (the alias silently became a literal string); it now throws `YAML: unresolved alias "*nope" — no anchor with that name`, in both the batch parser and the streaming parser — matching js-yaml/eemeli.
- **Fix: an anchor on an alias node is rejected.** `&a *b` (as a bare root, a sequence item `- &a *b`, or a mapping value `x: &a *b`) now errors with `YAML: alias node should not have any properties`, matching js-yaml/eemeli. This also closes the one remaining alias-bomb family (sequence-form anchor chains `- &n0 1\n- &n1 *n0…`) that previously parsed. Block anchor chains (`&a hello\n&b *a…`) with cycle detection still work, and self-references (`&a *a`, `&a *b\n&b *a`) still fail with the circular-alias error.
- **Fix: anchors are document-scoped in the streaming parser.** A `*alias` in one document can no longer resolve against an anchor defined in an earlier document; anchors (and chain depths) are reset at every document boundary, so batch and stream now reject cross-document references identically, while a later document may still redefine its own anchor.
- **Tests: dump() safeguards.** `YamlSecurity#dump()` already returns `{ ok: false }` (never throws) on circular references and pathologically deep values; the module-level `dump()` is the documented raw/low-level variant that does throw. Both behaviours are now covered by explicit tests (circular → `{ ok:false, error }`, 120 k-deep object/array → `{ ok:false }`).
- **Tests:** new ReDoS-guard cases (11 hazardous / 12 safe patterns), unresolved-alias coverage (batch + stream), anchor-on-alias rejection, and cross-document isolation.

## 1.17.5 (2026-08-11)

### Chore: package metadata, end-to-end example, CI Node 24

- **package.json metadata** — added `homepage` (GitHub README) and `bugs` (issues URL) so the npm page links work; `funding` intentionally not added (no verified funding URL exists yet).
- **New `examples/pipeline.mjs`** (runnable via `npm run example:pipeline`) — end-to-end pipeline: safe parse → schema validation (`validateYaml`) → lint, wired to `examples/basic.yaml` and exiting non-zero on any rejection.
- **CI matrix now `[16, 18, 20, 22, 24]`** — full suite, YAML Test Suite (406 cases), tree suite (262/262), CLI regression, types check and all bundles build verified locally on **Node 24** before the claim was updated; README/USAGE Node-version claims updated to match.
- No library behaviour or API changes.

## 1.17.4 (2026-08-11)

### Docs: `docs/USAGE.md` — practical guide, troubleshooting, FAQ

- **New `docs/USAGE.md`** — a scenario-based guide on top of the README API reference: 12 copy-paste recipes (safe parse, `strict` profile, per-instance vs global limits, js-yaml drop-in, multi-document, streaming with incremental validation, schema validation, custom schemas/tags, linter, CLI, browser/CDN, `tree()`/`parseTree()`), a **limits reference** (standard vs `strict` defaults), a **troubleshooting table** mapping each real rejection message to its cause and fix, and an FAQ.
- Every claim was verified against a live run before writing — including three corrections captured on the way: standalone `parse`/`parseAll` are the low-level **throwing** variants; `createStreamValidator` is an event-hook object (not a `.write()` API, which is `createStream({ validate, abortOnError })`); and `abortOnError: true` rejects by **throwing** `YAMLException` from the offending `write()`/`end()` rather than via an `error` event.
- README top nav now points new users to the guide.
- Docs only — no library behaviour, bundles, or API changes.

## 1.17.3 (2026-08-10)

### Test & docs: CLI regression suite locks in the 1.16/1.17 fixes

- **New `test/cli.js` (33 assertions)** — runs `bin/yaml-lint.js` as a real child process and asserts the documented exit-code contract: `0` clean, `1` lint errors, `2` argument/IO problems. Covers stdin + multiple files, the always-printed summary with `(N could not be read)`, `--json` reporting unreadable files as `{ file, error }`, `-v`/`-h`, unknown-option and bad `--max-line-length` rejection, warning-only rules keeping exit code `0`, and — critically — that the CLI works with **no build artifacts present** (the `ERR_MODULE_NOT_FOUND` regression from 1.17.1).
- Wired into `npm test` and a dedicated CI step so every Node matrix row runs it.
- `docs/ARCHITECTURE.md` §8 now documents the 14 lint rules, the CLI exit-code/`--json`/source-import contract; §11 lists all test suites including `test/cli.js`.
- Test/docs only — no library behaviour, runtime, bundle or API changes.

## 1.17.2 (2026-08-10)

### Fix: build tooling on Node 16/18 — CI matrix green again

- **`serialize-javascript@7` (pulled in by `@rollup/plugin-terser`) calls the global `crypto.getRandomValues`, which does not exist on Node < 17.4** — so `npm run build` crashed with `ReferenceError: crypto is not defined` on the Node 16 and 18 matrix rows (that failure surfaced right after the 1.17.1 CLI fix turned CI from red→still-red). The fast, correct fix for a build-only problem is a package override, not a runtime change: npm now resolves `serialize-javascript` to **6.0.2** (which reads `require('crypto')`, present on every supported Node), keeping `build:cjs` / `build:esm` / `build:browser` working on 16, 18, 20 and 22.
- The library runtime and the published tarball are unaffected (this only pins a transitive devDependency).

## 1.17.1 (2026-08-10)

### Fix: CLI crashed on a fresh checkout / in CI; summary now always printed

- **The `yaml-lint` binary imported `../src/index.min.js` — a gitignored build artifact.** Running the CLI from a clean `git clone` (or in CI before the build step) crashed with `ERR_MODULE_NOT_FOUND`, and CI on `main` was **red** for the 1.16.0 and 1.17.0 pushes. The bin now imports the committed ES module source (`../src/index.js`), and `src/index.js` is added to the package `files` so the published binary resolves it too. The CLI now works from a fresh checkout, in CI, and from the installed package — no build step required.
- **The result summary was silently suppressed** whenever any requested file could not be read (`results.length > 1 || targets.length === 1` heuristic). It is now always printed, with a `(N could not be read)` suffix in that case.
- **`--json` mode now reports unreadable files** as `{ file, error }` entries (plus a top-level `unreadable` count) instead of silently dropping them.

## 1.17.0 (2026-08-10)

### Docs & tooling: comparison, honest benchmarks, threat model, verified Node range

- **New README "Why yaml-security-lib?"** — capability comparison vs `js-yaml@4` and `eemeli/yaml`. Every claim was verified empirically (Node 24, 2026-08), including corrections to common assumptions: current js-yaml *does* detect plain duplicate keys, and both js-yaml and eemeli store `__proto__` as an own data key (on null-prototype objects) rather than polluting. The clear differentiators are **default-on resource guards** (`maxNodes`, `maxExpansion`, `maxAliasDepth`, input-size), **iterative (no-recursion) parsing**, the **never-throw `{ ok, error }` API**, streaming, the schema toolkit, and the linter.
- **New `bench/benchmark.js` + `npm run bench`** — reproducible 3-way benchmark (ours vs js-yaml vs eemeli `yaml`) with two adversary shapes:
  - *Alias graph bomb* (384 B → ~780 k aliased nodes): we reject in ~10 ms, eemeli rejects in ~40 ms, js-yaml accepts (aliases become shared references).
  - *Flat mapping bomb* (10 k distinct keys): we refuse past the default 10 k-node cap in ~360 ms; js-yaml builds it (~310 ms, linear); **eemeli `yaml` is quadratic on wide mappings (~23.5 s)**.
  - Throughput on a 2.3 KB config: ours 5.69 ms vs js-yaml 1.58 ms vs eemeli 12.19 ms — honest, machine-dependent, regenerable via `npm run bench`.
- **New README "Threat model"** — attack shape → defence mapping (Billion Laughs, alias bomb, mapping bomb, deep nesting, runaway scalars, duplicate keys, prototype pollution, hidden/bidi chars, code-execution tags).
- **Node range verified** — core suites pass on Node 16 & 18 (previously only 20/22 were CI-tested); CI matrix is now `[16, 18, 20, 22]`, backing the README "Node.js ≥16 (CI-tested)" claim.
- **`SECURITY.md` expanded** — linter security rules (unsafe-tag, hidden-character) added to the protections list.
- Dev-only: `yaml` (eemeli) added as a devDependency for the benchmark (never ships in the published package).

## 1.16.0 (2026-08-10)

### Feature: four new linter rules (security + consistency)

New `LINT_RULES`, all `warning` severity and toggleable like any other rule:

- **`unsafe-tag`** — flags code-execution tags such as `!!js/function`, `!!python/object`, `!!ruby/object`, `!!perl/...`, `!!php/...`. The parser treats these as inert, but tools that implement them (js-yaml `FULL_SCHEMA`, PyYAML, …) run code when they see one — and this YAML library itself parses them without error, so nothing else catches them.
- **`hidden-character`** — flags invisible / bidi text controls (U+200B–U+200F, U+202A–U+202E incl. the right-to-left-override used in trojan-source attacks, U+2060–U+2061/66–69, soft hyphen, BOM, …). Reports the offending `U+XXXX`.
- **`merge-key`** — flags the YAML merge key `<<`, which can amplify alias/entity expansion when fed untrusted merged aliases.
- **`inconsistent-eol`** — flags documents mixing CRLF and LF line endings (reported at the first LF-only line).

Like the existing style rules they operate on the raw text (so they also fire when the YAML is otherwise valid), respect block-scalar skipping, and follow the same `rules` array/object toggling. `test/lint.js` grew from 60 → 85 checks.

## 1.15.0 (2026-08-10)

### Build & tooling: fix `build:types`, browser lean bundles, CI that catches build breakage

- **Fixed broken `build:types`.** The script ran `tsc --emitDeclarationOnly`, which required a TypeScript install but `typescript` was never in `devDependencies` — so it always failed with `tsc: not found`. TypeScript is now a devDependency, and the script was repurposed to *validate* the shipped declarations instead of generating inferred ones: `tsc --noEmit -p tsconfig.json --allowJs false`, which type-checks only `src/*.d.ts` (and fails CI if one ever gets broken). `types/` output is gitignored.
- **Browser lean bundles.** `build:browser` now emits a CDN bundle per subpath, so browser users get the same slim options as Node:

  | File | Global | Exports |
  |------|--------|---------|
  | `dist/yaml-security.mjs` / `.min.js` | `YamlSecurity` | Everything |
  | `dist/core.mjs` / `core.min.js` | `YamlSecurityCore` | Parser + stream + validateYaml |
  | `dist/validate.mjs` / `validate.min.js` | `YamlSecurityValidate` | Schema toolkit, no parser |
  | `dist/lint.mjs` / `lint.min.js` | `YamlSecurityLint` | Linter |

  (the full-bundle filenames are unchanged, so existing CDN links keep working). `rollup.config.js` gained per-entry `BROWSER_TARGETS` (`browser-esm` + `browser-iife`).
- **CI now catches the kind of breakage that hit the `dist/` bundles in 1.13.0.** The test job builds every bundle (`npm run build`: 8 Node + 8 browser) and smoke-tests CJS + ESM subpath imports and all browser outputs, plus a new `build:types` step.
- Docs: README "Browser → Lean CDN bundles" section with globals/table + examples.

## 1.14.2 (2026-08-10)

### Docs: Academic / Personal License section

- **README "License" section rewritten** with clear, student-friendly guidance: dual-license table, a "Students & academic users — free" walkthrough (coursework / theses / research are free under §4 of `LICENSE.COMMERCIAL`, with the §4b citation requirement and the optional §4c courtesy copy), a personal-use note, and the commercial tiers table.
- **`LICENSE.COMMERCIAL` §4b DOI placeholder filled** with the real identifier (`https://doi.org/10.5281/zenodo.21684897`, same one shown in the README badges).
- No code changes — docs/legal-docs only.

## 1.14.1 (2026-08-10)

### Fix: TypeScript declarations for the lean subpaths

- **`yaml-security-lib/core`, `/validate` and `/lint` now ship their own `.d.ts`.** `v1.14.0` added the runtime subpath entries but the package only had one root declaration file, so TypeScript consumers hit *"Could not find a declaration file for module …"* on `import … from 'yaml-security-lib/core'` (etc.).
- Each subpath gets a `types` condition in `exports` (`src/core.d.ts`, `src/validate.d.ts`, `src/lint.d.ts`) that re-exports exactly the entry's public names — so `core` has no `validate`/`lint`/`s` types, `validate` has no parser types, `lint` has no class types (mirrors the runtime surfaces verified in `test/entries.js`).
- Verified with real `tsc` (strict, `moduleResolution: node16`, ESM consumer): all subpath imports resolve; `@ts-expect-error` guards confirm `validate`/`lint` are absent from `core`, `YamlSecurity` absent from `validate`/`lint`, and `validateYaml` absent from `validate`.
- Docs: README "Lean builds" notes each subpath ships its own declarations.

## 1.14.0 (2026-08-10)

### Feature: lean subpath imports (`core` / `validate` / `lint`) + smaller bundles

- **New exports map with tree-shakeable subpaths**, all backward compatible (`yaml-security-lib` stays the full API):
  - `yaml-security-lib/core` — parser + dump + streaming + `YamlSecurity` (no schema builder, no linter): **102 KB min / 28 KB gzip**.
  - `yaml-security-lib/validate` — pure schema toolkit (`s.*`, `validate`, `createStreamValidator`, `fromJSONSchema`/`toJSONSchema`) imported straight from `src/validate.js`, so it bundles **no parser**: **16 KB min / 4.7 KB gzip**.
  - `yaml-security-lib/lint` — `lint` + `LINT_RULES`.
- **The linter no longer pulls in the streaming engine.** `lint()` used `new YamlSecurity().parseAll()` internally, dragging the whole `YamlSecurity` class (and with it ~half of the streaming parser) into any bundle that imported `lint`. It now wraps the standalone batch `parseAll` behind a tiny `{ ok }` catch-wrapper with identical error semantics — the lint bundle dropped from ~106 KB to **58 KB min / 17 KB gzip**.
- **`rollup.config.js` is now multi-entry**: `esm`/`cjs` builds emit one self-contained minified file per entry (`index`, `core`, `validate`, `lint`); browser builds are unchanged.
- Docs: README "Lean builds (subpath imports)" table with per-subpath sizes + usage examples.
- Tests: `test/entries.js` (+34) verifies each subpath exposes exactly its public names (`core` has no `s`/`lint`, `validate` has no `YamlSecurity`/`parse`, `lint` has no class) and smoke-tests parse, pure-validate, and lint. Full suite green: 274 + 262 + 157 + 1645 + 406 (YAML Test Suite) + 262 + 95 + 60 + 34.

## 1.13.2 (2026-08-10)

### Docs: Quick Start guide — pick the right method fast

- New **"Quick Start — which method should I use?"** section right after Install: a table contrasting `new YamlSecurity().parse()` (recommended, never throws), `parse()` (throws `YAMLException`), `validateYaml()` (parse + schema error report), and `lint()` (style + security rules), all with the same bomb-protection defaults.
- Includes a recommended Safe-API example, a **drop-in replacement for `js-yaml`** (`yaml.load(str)` → `new YamlSecurity().parse(str)`), a Custom-limits snippet, and a pointer to the `strict` preset.
- No code changes — docs only.

## 1.13.1 (2026-08-10)

### Fix: publish browser bundles (`dist/`) built with the `strict` preset

- **`dist/yaml-security.mjs` and `dist/yaml-security.min.js` shipped stale.** The browser bundles are produced by `build:browser`, which was **not** part of `prepack` (only `build:cjs` + `build:esm` ran on publish), so `v1.13.0`'s tarball contained the old `v1.12.6` browser builds without `strict`. The Node entry points (`src/index.min.js` for `import`, `src/index.cjs` via `index.cjs` for `require`) were built fresh and did contain the preset — the regression only affected consumers pulling the `dist/` bundles.
- **Root cause fixed:** `prepack` now runs `build:browser` too, so every publish rebuilds all entry points (CJS, Node ESM, browser IIFE/ESM) from the current source.
- No source change; the browser bundles were rebuilt from the same `src/index.js` as `v1.13.0`. Verified the published `dist/` files contain the `strict` preset logic.

## 1.13.0 (2026-08-10)

### Feature: one-line hardened `strict` preset

- **`strict: true` swaps the defaults for a tighter preset profile** without breaking anyone on the standard defaults. Accepted everywhere limits go — `new YamlSecurity({ strict: true })`, `YamlSecurity.setLimits({ strict: true })`, `createStream({ strict: true })`, `parseStream({ strict: true })`. The strict profile: `maxNodes 5000`, `maxAlias 20`, `maxAliasDepth 5`, `maxExpansion 10000`, `maxInputBytes 1MB`, `maxStringLength 1MB` (was unlimited), `maxKeys 10000` (was unlimited), `maxDepth 30`.
- **Explicit limit keys override the profile**: `{ strict: true, maxStringLength: 0 }` re-opens strings; other keys keep the strict value.
- **`setLimits({ strict: true })`** sets the global base to the strict profile (reflected by `getBaseConfig()`); **`setLimits({ strict: false })`** resets it to the standard `DEFAULTS`.
- **Strict instances ignore the global base.** `new YamlSecurity({ strict: true })` always starts from `STRICT_DEFAULTS`, so a later `setLimits({ maxDepth: 1000 })` cannot loosen it.
- **Instance streams now inherit the instance's constructor limits** (including `strict`): `YamlSecurity.createStream()` / `parseStream()` forward the instance's `strict` flag and constructor overrides to the underlying `StreamParser`, matching the documented "bound to the instance's schema and limits" contract. Per-call stream options override them.
- Docs: README "Strict profile" section + `strict` row in the constructor table + instance-stream precedence note + `getBaseConfig` note; `docs/ARCHITECTURE.md` §4.0.
- Tests: `test/index.js` +21 (profile values, depth/keys/alias/expansion ceilings, overrides, global vs instance semantics), `test/stream.js` +6 (2MB string, depth-40 mapping, instance inheritance, overrides, global strict). Full suite green: 274 + 262 + 157 + 1645 + 406 (YAML Test Suite) + 262 + 95 + 60.

## 1.12.6 (2026-08-10)

### Fix: flow gathering is linear-time (batch + stream) + anchor counting

- **Multi-line flow collections no longer re-scan the accumulated text.** Both engines previously checked whether an in-progress flow (`[`, `{`) was balanced by re-walking the whole accumulated string on every new line, turning `a: [\n  x,\n  x,\n …` into O(n²) work and hanging on a few thousand lines. The batch parser (`gatherFlowValue` / prescan) and the stream parser now feed each continuation line through an incremental quote/bracket state machine (`makeFlowTracker` / `makeStreamFlowTracker`), so gathering a 200 000-line flow is linear: ~1.5 s instead of tens of seconds.
- **Single-line flow sequences no longer slice the remainder of the string per item.** `parseInlineFlow` and the offset-aware scanners (`scanFlowItemEndAt`, `flowKeySepAt`) now bound each item to its terminator instead of building `s.slice(i)` for every item, which was O(n²) on a single-line `[1,2,3,…]`. A 1.6 M-item flow sequence now parses in ~10 s.
- **Anchored block values are counted once, not three times.** The batch parser charged `track(sub)` three times per anchored block value (value anchor + bare anchor name + assignment), so a few hundred `key: &a` sub-blocks tripped a false `expansion limit exceeded (possible bomb)` at the default limits. The pre-scan path also restores its node/alias counters so the anchor-lookup probe no longer inflates the real pass's counts (safety-limit errors still propagate).
- Tests: `test/index.js` +10 (multiline flow linear, unterminated flow errors fast, flow seq linear, 1000 anchored sub-blocks), `test/stream.js` +4 (stream multiline flow + flow seq linear). Full suite green: 253 + 262 + 151 + 1645 + 406 (YAML Test Suite) + 262 + 95 + 60.

## 1.12.5 (2026-08-08)

### Fix: `maxDepth` counting parity between batch and stream (sequence items)

- **Batch no longer resets the depth counter at sequence items.** The batch parser previously re-entered `yamlToJS` for every sequence item with a fresh counter, so `a:\n  - b:\n      c: 1` counted as depth 2 and slipped past `maxDepth: 2`, while the stream parser (depth = `this.stack.length`, never reset) blocked it. `yamlToJS` gained a trailing `blockDepth` parameter that sequence items, block values and anchor pre-scans forward as `blockDepth + 1` (explicit keys forward `blockDepth` unchanged). Both engines now enforce the same limit on the same documents.
- **Counting model (documented in README "How `maxDepth` is counted")**: root block collection = depth 0; every nested block mapping/sequence = `+1`; flow `[...]`/`{...}` don't count; `maxDepth: 0` disables. Strict `>`: `maxDepth: 3` allows `a.b.c.d` (depth 3), blocks `a.b.c.d.e` (depth 4).
- Docs: README `maxDepth` row + worked examples (pure maps, sequence items, streaming note), `docs/ARCHITECTURE.md` §4.5 with the `yamlToJS` depth-threading rationale.
- Tests: `test/index.js` +9, `test/stream.js` +3. Full suite green: 243 + 262 + 147 + 1645 + 406 (YAML Test Suite) + 262 + 95 + 60.

## 1.12.4 (2026-08-08)

### Fixes: unified limit handling + streaming alias-bomb protection
- **`new YamlSecurity({...})` now applies every limit key exactly like `setLimits`.** Previously the constructor silently dropped `maxAlias`, `maxInputMB` and `maxInputBytes`, and performed no validation. Now all nine limit keys (`maxNodes`, `maxAlias`, `maxAliasDepth`, `maxExpansion`, `maxInputMB`, `maxInputBytes`, `maxStringLength`, `maxKeys`, `maxDepth`) are honored and validated with the same rules as `setLimits` — invalid values throw immediately (`YamlSecurity: maxNodes must be a positive integer`, etc.), and unknown keys are ignored.
- **`createStream({...})` validates limits the same way** (e.g. `createStream({ maxNodes: -1 })` now throws instead of silently disabling the guard).
- **Streaming alias bombs are now bounded by `maxExpansion`/`maxNodes`, not just `maxAlias`.** The stream parser previously charged 1 node per alias reference, so a large anchored collection expanded through many `*x` aliases slipped past `maxExpansion` as long as `maxAlias` was raised. Each aliased subtree (and tagged construct) is now charged its full weight against `maxNodes`/`maxExpansion`, mirroring the batch parser's weighted counting — e.g. a 200-node anchor referenced 300 times is rejected at the 25th alias with `expansion limit exceeded (possible bomb)`.
- Tests: `test/index.js` +10, `test/stream.js` +2. Full suite green: 234 + 262 + 144 + 1645 + 406 (YAML Test Suite) + 262 + 95 + 60.

## 1.12.3 (2026-08-07)

### Fixes: compact quoted-key mappings (PyYAML-style) now flow through the security checks
- **`"a":b` (quoted key, value attached to the `:` with no whitespace) now parses as a real mapping entry** `{a: 'b'}` in block context — root, nested, sequence-item and multi-line forms. Previously the parser split off the key but silently dropped the value (`parse('"a":b')` → `"a"`) and the key bypassed the duplicate/prototype-pollution checks.
- Because the shape now builds a real entry, the existing checks fire automatically: `"__proto__":x` / `"constructor":x` are blocked, `"a":b\n"a":c` is a duplicate key, `- "__proto__":x` is blocked in sequences, and `x:\n  "a":b` nests correctly.
- Unchanged: `"a":` → `{a: null}`, `"a"` → `"a"`, `"a": b` (spaced) → `{a: 'b'}`, and plain-scalar continuation folding (`key: a\n  "b":c` still folds to `{key: 'a "b":c'}`). js-yaml rejects the compact form ("a whitespace character is expected after the key-value separator within a block mapping"); we accept it PyYAML-style so the security checks apply to the shape.
- Tests: `test/index.js` +25, `test/stream.js` +18. Full suite green: 224 + 262 + 142 + 1645 + 406 (YAML Test Suite) + 262 + 95 + 60.

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
