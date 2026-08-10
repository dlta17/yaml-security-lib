// Subpath entry surfaces (src/entries/*). These are the lean bundles shipped
// as `yaml-security-lib/core`, `yaml-security-lib/validate`, `yaml-security-lib/lint`.
// Each entry exposes ONLY its public names, so the built bundles stay small.
import * as core from '../src/entries/core.js';
import * as validateEntry from '../src/entries/validate.js';
import * as lintEntry from '../src/entries/lint.js';

let passed = 0;
let failed = 0;
const fails = [];

function assert(cond, msg) {
  if (cond) passed++;
  else { failed++; fails.push(msg); }
}
function assertMissing(mod, name, msg) {
  assert(!(name in mod), msg);
}

// core — parsing/dumping/streaming, no validator builder, no linter.
assert(typeof core.YamlSecurity === 'function', 'core exports YamlSecurity');
assert(typeof core.parse === 'function', 'core exports parse');
assert(typeof core.parseAll === 'function', 'core exports parseAll');
assert(typeof core.dump === 'function', 'core exports dump');
assert(typeof core.createStream === 'function', 'core exports createStream');
assert(typeof core.parseStream === 'function', 'core exports parseStream');
assert(typeof core.validateYaml === 'function', 'core exports validateYaml');
assert(typeof core.setLimits === 'function', 'core exports setLimits');
assert(typeof core.tree === 'function', 'core exports tree');
assert(typeof core.YAMLException === 'function', 'core exports YAMLException');
assertMissing(core, 's', 'core does not export the s builder');
assertMissing(core, 'validate', 'core does not export pure validate');
assertMissing(core, 'fromJSONSchema', 'core does not export fromJSONSchema');
assertMissing(core, 'lint', 'core does not export lint');
assertMissing(core, 'LINT_RULES', 'core does not export LINT_RULES');

const c = new core.YamlSecurity();
assert(c.parse('a: 1\nb: 2').ok === true, 'core parse ok');
assert(c.parse('a: 1\na: 2').ok === false, 'core duplicate key blocked');
assert(c.dump({ x: 1 }).result.includes('x: 1'), 'core dump works');
const cd = c.validateYaml('age: -5', { __s: 'object', shape: { age: { __s: 'int', min: 0 } } });
assert(cd.ok === false && Array.isArray(cd.errors), 'core validateYaml reports errors');

// validate — lean schema toolkit WITHOUT the parser.
assert(typeof validateEntry.s === 'object', 'validate exports s');
assert(typeof validateEntry.validate === 'function', 'validate exports validate');
assert(typeof validateEntry.fromJSONSchema === 'function', 'validate exports fromJSONSchema');
assert(typeof validateEntry.toJSONSchema === 'function', 'validate exports toJSONSchema');
assert(typeof validateEntry.createStreamValidator === 'function', 'validate exports createStreamValidator');
assert(typeof validateEntry.string === 'function', 'validate exports string builder');
assertMissing(validateEntry, 'YamlSecurity', 'validate entry does not export YamlSecurity');
assertMissing(validateEntry, 'parse', 'validate entry does not export parse');
assertMissing(validateEntry, 'validateYaml', 'validate entry does not export validateYaml');

const spec = validateEntry.s.object({
  name: validateEntry.s.string({ min: 1 }),
  age: validateEntry.s.int({ min: 0 }),
});
const vr = validateEntry.validate({ name: 'Ali', age: 30 }, spec);
assert(vr.ok === true, 'pure validate ok on good value');
const vr2 = validateEntry.validate({ name: '', age: -1 }, spec);
assert(vr2.ok === false && vr2.errors.length === 2, 'pure validate catches 2 errors');

// lint — linter without the class/streaming.
assert(typeof lintEntry.lint === 'function', 'lint exports lint');
assert(typeof lintEntry.LINT_RULES === 'object' && lintEntry.LINT_RULES !== null, 'lint exports LINT_RULES');
assert(lintEntry.lint('a: 1\na: 2').issues.some(i => i.rule === 'duplicate-key'), 'lint catches duplicate keys');
assertInternal();
function assertInternal() {
  try {
    assert(typeof lintEntry.YamlSecurity === 'undefined', 'lint entry does not export YamlSecurity');
  } catch (e) { failed++; fails.push('lint entry export check threw: ' + e.message); }
}

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (fails.length) {
  for (const f of fails) console.log('  FAIL: ' + f);
  process.exit(1);
}