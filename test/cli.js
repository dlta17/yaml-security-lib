// CLI regression suite: spawns bin/yaml-lint.js as a real child process and
// asserts exit codes + stdout/stderr. Guards the behaviors that regressed in
// the 1.16–1.17 era (fresh-checkout import, summary suppression, --json
// dropped files) and the documented exit-code contract.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const BIN = resolve(dirname(fileURLToPath(import.meta.url)), '../bin/yaml-lint.js');
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let pass = 0, fail = 0;
const fails = [];

function check(name, cond, detail) {
  if (cond) pass++;
  else { fail++; fails.push(name + (detail !== undefined ? ': ' + detail : '')); }
}

function run(args, input) {
  return spawnSync(process.execPath, [BIN, ...args], { input, encoding: 'utf8' });
}

function tmpYaml(files) {
  const dir = mkdtempSync(join(tmpdir(), 'yaml-lint-test-'));
  const paths = {};
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name);
    writeFileSync(p, content);
    paths[name] = p;
  }
  return { dir, paths };
}

const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;

// ── basics & exit codes ──
{
  const r = run([], 'a: 1\nb: 2\n');
  check('stdin valid exit 0', r.status === 0, 'status=' + r.status + ' ' + r.stderr);
  check('stdin valid summary', /0 errors, 0 warnings/.test(r.stdout), r.stdout);
}
{
  const r = run([], 'a: 1\na: 2\n');
  check('dup-key exit 1', r.status === 1, 'status=' + r.status);
  check('dup-key issue printed', /duplicate-key/.test(r.stdout), r.stdout);
  check('dup-key summary', /1 error, 0 warnings/.test(r.stdout), r.stdout);
}
{
  const r = run([], 'a: 1');
  check('missing-newline warning exit 0', r.status === 0, 'status=' + r.status);
  check('missing-newline issue', /missing-newline-at-eof/.test(r.stdout), r.stdout);
}
{
  const r = run(['-v']);
  check('-v prints version + exit 0', r.status === 0 && r.stdout.trim() === version, r.stdout);
}
{
  const r = run(['--help']);
  check('--help exit 0', r.status === 0, 'status=' + r.status);
  check('--help usage text', /Usage: yaml-lint/.test(r.stdout), r.stdout);
}
{
  const r = run(['--bogus']);
  check('unknown option exit 2', r.status === 2, 'status=' + r.status);
  check('unknown option on stderr', /Unknown option: --bogus/.test(r.stderr), r.stderr);
}
{
  const r = run(['--max-line-length', '0']);
  check('bad max-line-length exit 2', r.status === 2, 'status=' + r.status);
  check('bad max-line-length message', /positive integer/.test(r.stderr), r.stderr);
}
{
  const r = run(['--max-line-length', '10'], 'a: 12345678901\n');
  check('line-length warning applied', /line-length/.test(r.stdout), r.stdout);
  check('line-length warning exit 0', r.status === 0, 'status=' + r.status);
}

// ── files ──
{
  const { dir, paths } = tmpYaml({ good: 'k: 1\n', bad: 'a: 1\na: 2\n' });
  try {
    {
      const r = run([paths.good]);
      check('valid file exit 0', r.status === 0, 'status=' + r.status);
      check('valid file summary', /Linted 1 source: 0 errors/.test(r.stdout), r.stdout);
    }
    {
      const r = run([paths.bad]);
      check('bad file exit 1', r.status === 1, 'status=' + r.status);
      check('bad file line ref', new RegExp(escapeRe(paths.bad) + ':2:2').test(r.stdout), r.stdout);
    }
    {
      const r = run([paths.bad, join(dir, 'missing.yaml')]);
      check('partial exit 2', r.status === 2, 'status=' + r.status);
      check('partial lint issue kept', /duplicate-key/.test(r.stdout), r.stdout);
      check('partial cannot-read stderr', /cannot read .*missing\.yaml/.test(r.stderr), r.stderr);
      check('partial summary with unreadable', /Linted 2 sources: 1 error, 0 warnings \(1 could not be read\)/.test(r.stdout), r.stdout);
    }
    {
      const r = run([join(dir, 'missing.yaml')]);
      check('single missing exit 2', r.status === 2, 'status=' + r.status);
      check('single missing summary counts', /Linted 1 source: 0 errors, 0 warnings \(1 could not be read\)/.test(r.stdout), r.stdout);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ── --json ──
{
  const r = run(['--json'], 'x: 1\n');
  let parsed = null;
  try { parsed = JSON.parse(r.stdout); } catch { /* noop */ }
  check('json valid parses', parsed !== null, r.stdout);
  check('json valid fields', parsed && parsed.files.length === 1 && parsed.files[0].valid === true && parsed.errors === 0, JSON.stringify(parsed));
}
{
  const { dir, paths } = tmpYaml({ bad: 'a: 1\na: 2\n' });
  try {
    const r = run(['--json', paths.bad, join(dir, 'nope.yaml')]);
    let parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch { /* noop */ }
    check('json partial exit 2', r.status === 2, 'status=' + r.status);
    check('json partial linted file present', parsed && parsed.files.length === 2 && parsed.files[0].errors === 1, JSON.stringify(parsed));
    check('json partial unreadable entry', parsed && parsed.files[1].error && /no such file/.test(parsed.files[1].error), JSON.stringify(parsed));
    check('json partial unreadable count', parsed && parsed.unreadable === 1, JSON.stringify(parsed));
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ── source import: no built artifact required (the 1.16/1.17 regression) ──
{
  const r = run(['--json'], '');
  check('runs without any build artifacts', r.status === 0, 'status=' + r.status + ' ' + r.stderr);
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

console.log('\n' + pass + ' passed, ' + fail + ' failed');
if (fails.length) {
  for (const f of fails) console.log('  FAIL: ' + f);
  process.exit(1);
}