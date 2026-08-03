# Contributing to YAML Security Lib

Thank you for your interest! By contributing, you agree to the
**Contributor License Agreement (CLA)** below.

## CLA

When you submit code, documentation, or any other material:

1. You grant **Nedal Ibrahim** a perpetual, worldwide, royalty-free,
   irrevocable license to use, modify, distribute, and sublicense
   your contribution under both:
   - [AGPL-3.0](LICENSE) (open source)
   - [Commercial License](LICENSE.COMMERCIAL) (proprietary)

2. You warrant that you own the rights to your contribution and
   have the authority to grant this license.

3. No monetary compensation will be provided for contributions.

By submitting a pull request, you accept these terms.

## Development

```bash
npm install
npm test
```

`npm test` runs the unit, fuzz, stream, and js-yaml-oracle suites. See
[AGENTS.md](AGENTS.md) for hard invariants (timestamps, the js-yaml v5
oracle, merge-key resolution) and the exact CI pipeline.

## Versioning & Releases

Every code/feature change bumps the version (`patch` fix / `minor` feature /
`major` breaking) — never push code on an old version. Docs-only changes may
stay on the current version.

1. Update `version` in `package.json` and `package-lock.json` (run `npm install`
   to sync the lockfile).
2. Add a dated section to `CHANGELOG.md`.
3. Commit, then `git tag vX.Y.Z` (lightweight, matching existing repo tags) and
   `git push origin main --tags`.

## Reporting Issues

- Security vulnerabilities: email **salamanedal@gmail.com**
- Bugs & feature requests: GitHub Issues
