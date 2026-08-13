// End-to-end pipeline example: parse → schema validate → lint.
// Run with: node examples/pipeline.mjs
import { readFileSync } from 'node:fs';
import { YamlSecurity, s, lint } from '../src/index.js';

const yaml = readFileSync(new URL('./basic.yaml', import.meta.url), 'utf8');

const spec = s.object({
  server: s.object({
    host: s.string(),
    port: s.int({ min: 1, max: 65535 }),
    features: s.array(s.string()),
    limits: s.array(s.int()),
  }),
});

const parser = new YamlSecurity();

// 1. Safe parse — never throws, always answers { ok, result } | { ok, error }
const parsed = parser.parse(yaml);

// 2. Parse + structured schema report — { ok, value, errors }
const checked = parser.validateYaml(yaml, spec);

// 3. Lint the raw source — style + security rules, never throws
const linted = lint(yaml);

console.log('1. parse :', parsed.ok ? 'ok' : 'rejected: ' + parsed.error);
console.log('2. schema:', checked.ok
  ? 'valid'
  : checked.errors.map((e) => e.path + ' ' + e.message).join('; '));
console.log('3. lint  :', linted.valid
  ? 'clean'
  : linted.issues.length + ' issue(s): ' +
    linted.issues.map((i) => i.rule + '@' + i.line + ':' + i.column).join(', '));

if (!parsed.ok || !checked.ok || !linted.valid) process.exitCode = 1;