# Agent conventions — YAML Security Lib

Guidelines for AI agents and humans working on this repo. Read this before editing.
For a full walkthrough of the parser internals and the security model, see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Overview

Zero-dependency YAML parser with security hardening (duplicate-key detection,
alias-depth limiting, prototype-pollution prevention, resource limits). The
whole library is a single file: `src/index.js`. It provides:

- `parse` / `parseAll` / `yamlToJS` (tree API)
- `createStream` / `parseStream` / `StreamParser` (SAX-style streaming API)
- `YamlSecurity` (configurable instance API, used by the official YAML Test
  Suite harness and most tests)

Generated bundles (`src/index.cjs`, `src/index.min.js`, `dist/`) are
gitignored; only the static `index.cjs` CJS wrapper is tracked.

## Testing

No linter exists. Run everything with:

```bash
npm test        # index.js + fuzz.js + stream.js + stream-fuzz.js
```

- `test/index.js` — unit + security + limits (127 assertions)
- `test/fuzz.js` — invariant/security fuzz (262 assertions)
- `test/stream.js` — streaming API (51 assertions)
- `test/stream-fuzz.js` — js-yaml oracle fuzz (1645 assertions)

## Hard invariants (do not break)

1. **Implicit timestamps are strings (YAML 1.2 core).** `2023-01-15` parses to
   `"2023-01-15"`, never a `Date`. Explicit `!!timestamp` → `Date`. `parse()`
   and the stream MUST agree. (`resolveScalar` in the parse path and
   `resolveScalarTop` in the stream path both skip the implicit timestamp type.)

2. **`js-yaml` (the fuzz oracle) must stay on v5.x.** `test/stream-fuzz.js`
   compares values against `js-yaml@5` (YAML 1.2 core — returns strings for
   timestamps). js-yaml 4.x is YAML 1.1 and returns `Date` for timestamps,
   which fails ~28 stream-fuzz assertions. Never downgrade the devDependency,
   and keep `package-lock.json` in sync (`npm ci` fails with "Missing from
   lock file" otherwise). This bit us once: a stale lockfile made CI red.

3. **`resolveMerges` must never strip Date/Uint8Array/Buffer leaves.** Merge-key
   resolution (`<<`) rebuilds mappings; guard non-map values first or explicit
   `!!timestamp` and `!!binary` values silently become `{}`.

4. **Security limits apply in every code path** (tree API, streaming, flow,
   aliases). New features must respect `maxNodes`, `maxKeys`,
   `maxStringLength`, `maxDepth`, `maxAlias`, `maxInputBytes`.

## Versioning & releases

Every code/feature change bumps the version — no pushing code on an old
version. Docs-only changes may stay on the current version.

1. Decide the bump: `patch` (fix), `minor` (feature), `major` (breaking).
2. Update `version` in `package.json` **and** `package-lock.json` (run
   `npm install` to sync the lockfile automatically).
3. Add a dated section to `CHANGELOG.md` describing the change.
4. Commit, then push main **and** a lightweight tag (matches the existing repo
   convention — all tags are lightweight, e.g. `v1.8.1`):
   `git tag v1.8.1 && git push origin main --tags`.

## CI

`.github/workflows/ci.yml` runs on Node 20/22 (push + PR to `main`):
zero-dep tests before `npm ci`; `stream-fuzz.js` (needs js-yaml) and the
rollup builds after. Verify a change passes the whole pipeline in order
before pushing.

## Schemas / types

Built-in YAML types (`!!str`, `!!int`, `!!float`, `!!bool`, `!!null`,
`!!timestamp`, `!!binary`) are declared in `src/schema.js` and attached to
`DEFAULT_SCHEMA` in `src/index.js`. The YAML Test Suite conformance target is

~100% (406/406), matching the YAML 1.2 type-system choices above.