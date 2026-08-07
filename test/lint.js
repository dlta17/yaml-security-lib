import { lint, LINT_RULES } from '../src/index.js';

let pass = 0, fail = 0;
const fails = [];

function check(name, cond, detail) {
  if (cond) pass++;
  else { fail++; fails.push(name + (detail !== undefined ? ': ' + detail : '')); }
}

function rulesOf(yaml, opts) {
  return lint(yaml, opts).issues.map(i => i.rule);
}

function hasRule(yaml, rule, opts) {
  return lint(yaml, opts).issues.some(i => i.rule === rule);
}

function validYaml() {
  return 'server:\n  host: localhost\n  port: 8080\n  features:\n    - ssl\n    - cors\n  limits:\n    - 5\n    - 10\n';
}

// ── basics ──
{
  const r = lint(validYaml());
  check('valid doc', r.valid === true && r.errors === 0 && r.warnings === 0, JSON.stringify(r));
  const e = lint('');
  check('empty doc', e.valid === true && e.issues.length === 0);
  const nul = lint('\n\n# just a comment\n');
  check('comment only', nul.valid === true && nul.issues.length === 0);
  const d = lint('---\na: 1\n---\nb: 2\n');
  check('multi-doc', d.valid === true);
}

// ── syntax & security rules ──
check('syntax-error', hasRule('key: [1, 2\n', 'syntax-error'));
check('syntax-error tab', hasRule('a:\n\tb: 1\n', 'syntax-error'));
check('duplicate-key', hasRule('a: 1\nb: 2\na: 3\n', 'duplicate-key'));
check('prototype-pollution', hasRule('a: 1\n__proto__: 2\n', 'prototype-pollution'));
check('anchor-bomb circular', hasRule('&a *a\nb: 1\n', 'anchor-bomb'));
check('anchor-bomb cycle', hasRule('&a *b\n&b *a\nc: 1\n', 'anchor-bomb'));
{
  const r = lint('a: 1\nb: 2\na: 3\n');
  const dup = r.issues.find(i => i.rule === 'duplicate-key');
  check('duplicate-key location', dup && dup.line === 3 && dup.column === 2, JSON.stringify(dup));
  check('syntax error invalidates', lint('key: [1, 2\n').valid === false);
  check('duplicate invalidates', lint('a: 1\na: 2\n').valid === false);
}

// ── style rules ──
check('trailing-spaces', hasRule('a: 1 \n', 'trailing-spaces'));
check('trailing-spaces tab', hasRule('a: 1\t\n', 'trailing-spaces'));
{
  const r = lint('a: 1 \n');
  const ts = r.issues.find(i => i.rule === 'trailing-spaces');
  check('trailing-spaces column', ts && ts.column === 5, JSON.stringify(ts));
}
check('no trailing-spaces clean', !hasRule('a: 1\nb: 2\n', 'trailing-spaces'));
check('line-length default', hasRule('a: ' + 'x'.repeat(150) + '\n', 'line-length'));
check('line-length below', !hasRule('a: ' + 'x'.repeat(100) + '\n', 'line-length'));
check('line-length custom', hasRule('a: ' + 'x'.repeat(50) + '\n', 'line-length', { maxLineLength: 40 }));
check('line-length custom ok', !hasRule('a: ' + 'x'.repeat(30) + '\n', 'line-length', { maxLineLength: 40 }));
check('missing-newline-at-eof', hasRule('a: 1', 'missing-newline-at-eof'));
check('missing-newline no issue', !hasRule('a: 1\n', 'missing-newline-at-eof'));
check('space-after-colon', hasRule('a:1\n', 'space-after-colon'));
check('space-after-colon ok', !hasRule('a: 1\n', 'space-after-colon'));
check('space-after-colon url', !hasRule('url: http://example.com\n', 'space-after-colon'));
check('space-after-colon eol', !hasRule('a:\n  b: 1\n', 'space-after-colon'));
check('space-after-dash', hasRule('-item\n', 'space-after-dash'));
check('space-after-dash ok', !hasRule('- item\n', 'space-after-dash'));
check('space-after-dash number', !hasRule('-5\n', 'space-after-dash'));
check('space-after-dash nested', hasRule('a:\n  -item\n', 'space-after-dash'));
check('truthy-yes-no', hasRule('a: yes\n', 'truthy-yes-no'));
check('truthy-on-off', hasRule('a: off\nb: on\n', 'truthy-yes-no'));
check('truthy-capital', hasRule('a: YES\n', 'truthy-yes-no'));
check('truthy-quoted', !hasRule('a: "yes"\n', 'truthy-yes-no'));
check('truthy-plain', !hasRule('a: yesman\n', 'truthy-yes-no'));
check('truthy-dash', hasRule('- no\n', 'truthy-yes-no'));
check('truthy-dash-number', !hasRule('- 5\n', 'truthy-yes-no'));
check('truthy-comment', hasRule('a: yes # comment\n', 'truthy-yes-no'));

// ── block scalars must not trigger colon/dash rules on content lines ──
{
  const y = 'text: |\n  line one\n  line: two\n- item\nmore: 1\n';
  const r = lint(y);
  const rules = r.issues.map(i => i.rule);
  check('block scalar content skipped', !rules.includes('space-after-colon') && !rules.includes('space-after-dash'), JSON.stringify(rules));
}
{
  const y = 'text: >\n  folded: content\n- x\n';
  const r = lint(y);
  check('folded content skipped', !r.issues.some(i => i.rule === 'space-after-colon'), JSON.stringify(r.issues));
}

// ── CRLF handling ──
{
  const r = lint('a: 1\r\nb: two\r\n');
  check('crlf no trailing-spaces', !r.issues.some(i => i.rule === 'trailing-spaces'), JSON.stringify(r.issues));
  check('crlf valid', r.valid === true);
}

// ── rule toggling ──
check('rules array', !hasRule('a: yes\n', 'truthy-yes-no', { rules: ['syntax-error'] }));
check('rules array keeps dup', hasRule('a: 1\na: 2\n', 'duplicate-key', { rules: ['syntax-error', 'duplicate-key'] }));
check('rules array style stays off', !hasRule('a: yes \n', 'trailing-spaces', { rules: ['syntax-error'] }));
check('rules off string', !hasRule('a: yes\n', 'truthy-yes-no', { rules: { 'truthy-yes-no': 'off' } }));
check('rules off bool', !hasRule('a: yes\n', 'truthy-yes-no', { rules: { 'truthy-yes-no': false } }));
check('rules off zero', !hasRule('a: yes\n', 'truthy-yes-no', { rules: { 'truthy-yes-no': 0 } }));
check('rules off means valid', lint('a: yes\n', { rules: { 'truthy-yes-no': 'off' } }).valid === true);
check('rules explicit error', lint('a: yes\n', { rules: { 'truthy-yes-no': 'error' } }).valid === false);
check('rules explicit warn', lint('a: yes\n', { rules: { 'truthy-yes-no': 'warning' } }).valid === true);

// ── error handling ──
{
  let threw = null;
  try { lint('a: 1\n', { rules: { nope: 'error' } }); } catch (e) { threw = e; }
  check('unknown rule throws', threw instanceof TypeError && /unknown rule "nope"/.test(threw.message), threw && threw.message);
}
{
  let threw = null;
  try { lint('a: 1\n', { maxLineLength: 0 }); } catch (e) { threw = e; }
  check('bad maxLineLength throws', threw instanceof TypeError, threw && threw.message);
}
{
  let threw = null;
  try { lint(123); } catch (e) { threw = e; }
  check('non-string throws', threw instanceof TypeError, threw && threw.message);
}

// ── severity / counts ──
{
  const r = lint('a: 1\na: 2\nb: yes \nc: x\n');
  check('counts', r.errors === 1 && r.warnings === 2 && r.issues.length === 3, JSON.stringify({ errors: r.errors, warnings: r.warnings }));
  check('severities', r.issues.every(i => i.severity === 'error' || i.severity === 'warning'));
}
{
  const r = lint('a: 1\nb: yes\n', { rules: { 'truthy-yes-no': 'error' } });
  check('warn rule escalated', r.errors === 1 && r.valid === false, JSON.stringify(r));
}
check('LINT_RULES frozen', Object.isFrozen(LINT_RULES));
check('LINT_RULES severities', LINT_RULES['syntax-error'] === 'error' && LINT_RULES['line-length'] === 'warning');

console.log('\n' + pass + ' passed, ' + fail + ' failed');
if (fails.length) {
  for (const f of fails) console.log('  FAIL: ' + f);
  process.exit(1);
}
