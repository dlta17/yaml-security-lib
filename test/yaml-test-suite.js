import fs from 'fs';
import path from 'path';
import { parse, YamlSecurity } from '../src/index.js';

const suiteDir = '/tmp/yaml-test-suite/src';
const parser = new YamlSecurity();

let passed = 0;
let failed = 0;
let errored = 0;
const failures = [];

const files = fs.readdirSync(suiteDir).filter(f => f.endsWith('.yaml'));
console.log('YAML Test Suite: ' + files.length + ' test files');

for (const file of files) {
  const fullPath = path.join(suiteDir, file);
  const content = fs.readFileSync(fullPath, 'utf8');

  let testCases;
  try {
    testCases = parser.parse(content);
    if (!testCases.ok) { errored++; failures.push({ file, error: 'parse error: ' + testCases.error }); continue; }
    testCases = testCases.result;
    if (!Array.isArray(testCases)) testCases = [testCases];
  } catch (e) {
    errored++; failures.push({ file, error: 'exception: ' + e.message }); continue;
  }

  for (const tc of testCases) {
    const name = tc.name || file;
    const yaml = tc.yaml;
    const expectedJson = tc.json;

    if (!yaml) continue;

    // Normalize visible space markers
    const cleanYaml = yaml.replace(/␣/g, ' ');

    const result = parser.parse(cleanYaml);
    if (!result.ok) {
      if (tc.error) { passed++; continue; }
      failed++; failures.push({ file, name, error: result.error }); continue;
    }

    if (expectedJson) {
      let expected;
      try { expected = JSON.parse(expectedJson.trim()); }
      catch (e) {
        try { expected = eval('(' + expectedJson.trim() + ')'); }
        catch (e2) { failed++; failures.push({ file, name, error: 'bad json: ' + e.message }); continue; }
      }
      if (deepEqual(result.result, expected)) { passed++; }
      else { failed++; failures.push({ file, name, error: 'mismatch', expected: JSON.stringify(expected), actual: JSON.stringify(result.result) }); }
    } else {
      passed++;
    }
  }
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null || a === undefined || b === undefined) return a === b;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false;
    return true;
  }
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  if (ka.length !== kb.length) return false;
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return false;
    if (!deepEqual(a[ka[i]], b[ka[i]])) return false;
  }
  return true;
}

console.log('\n' + passed + ' passed, ' + failed + ' failed, ' + errored + ' errored');
if (failures.length > 0) {
  // Group by error type
  const errorTypes = {};
  for (const f of failures) errorTypes[f.error] = (errorTypes[f.error] || 0) + 1;
  console.log('\nError summary:');
  const sorted = Object.entries(errorTypes).sort((a, b) => b[1] - a[1]);
  for (const [err, count] of sorted.slice(0, 30))
    console.log('  [' + count + 'x] ' + err.slice(0, 120));
  console.log('\nSample failures:');
  for (const f of failures.slice(0, 10)) {
    console.log('  ' + f.file + ' — ' + (f.name || ''));
    if (f.error) console.log('    error: ' + f.error);
    if (f.expected) console.log('    expected: ' + f.expected);
    if (f.actual) console.log('    actual: ' + f.actual);
  }
}
process.exit(failed > 0 ? 1 : 0);
