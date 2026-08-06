import fs from 'fs';
import path from 'path';
import { parse, YamlSecurity } from '../src/index.js';

const suiteDir = process.env.YAML_SUITE_DIR || '/home/nedal/yaml-test-suite/src';

if (!fs.existsSync(suiteDir)) {
  console.log('YAML Test Suite: SKIPPED (suite dir not found: ' + suiteDir + '); set YAML_SUITE_DIR to enable');
  process.exit(0);
}

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

    // Normalize visible space markers, tab markers, trailing-newline markers,
    // CR markers, BOM markers, and end-of-file marker. The tab glyph is any
    // number of em-dashes followed by » (deeper tabs use longer dashes).
    const cleanYaml = yaml
      .replace(/␣/g, ' ')
      .replace(/—*»/g, '\t')
      .replace(/↵/g, '')
      .replace(/←/g, '\r')
      .replace(/⇔/g, '\uFEFF')
      .replace(/∎\n?$/, '');

    const result = parser.parseAll(cleanYaml);
    if (!result.ok) {
      if (tc.fail) { passed++; continue; }
      failed++; failures.push({ file, name, error: result.error }); continue;
    }
    if (tc.fail) {
      failed++; failures.push({ file, name, error: 'expected parse failure but succeeded', actual: JSON.stringify(result.result) }); continue;
    }

    if (expectedJson) {
      const expectedValues = splitJsonValues(expectedJson);
      if (expectedValues === null) {
        failed++; failures.push({ file, name, error: 'bad json: ' + expectedJson.slice(0, 80) }); continue;
      }
      const docs = Array.isArray(result.result) ? result.result : [result.result];
      if (docs.length !== expectedValues.length) {
        failed++; failures.push({ file, name, error: 'document count mismatch', expected: expectedValues.length, actual: docs.length }); continue;
      }
      let ok = true;
      for (let d = 0; d < docs.length; d++) {
        if (!deepEqual(docs[d], expectedValues[d])) { ok = false; break; }
      }
      if (ok) passed++;
      else { failed++; failures.push({ file, name, error: 'mismatch', expected: JSON.stringify(expectedValues), actual: JSON.stringify(docs) }); }
    } else {
      passed++;
    }
  }
}

// Split a YAML test-suite `json:` field into its top-level values. The suite
// stores one JSON value per document, so multi-document tests have several
// top-level values (objects, strings, null, arrays) concatenated.
function splitJsonValues(text) {
  const out = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    while (i < n && /\s/.test(text[i])) i++;
    if (i >= n) break;
    const ch = text[i];
    let end;
    if (ch === '{' || ch === '[') {
      end = findJsonClose(text, i, ch);
      if (end < 0) return null;
      end++;
    } else if (ch === '"' || ch === "'") {
      end = findJsonStringEnd(text, i, ch);
      if (end < 0) return null;
      end++;
    } else {
      let j = i;
      while (j < n && !/\s/.test(text[j])) j++;
      end = j;
    }
    out.push(text.slice(i, end));
    i = end;
  }
  const parsed = [];
  for (const v of out) {
    try { parsed.push(JSON.parse(v)); }
    catch (e) {
      try { parsed.push(eval('(' + v + ')')); }
      catch (e2) { return null; }
    }
  }
  return parsed;
}

function findJsonClose(text, start, open) {
  const close = open === '{' ? '}' : ']';
  let depth = 0;
  let inStr = null;
  let esc = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") { inStr = ch; continue; }
    if (ch === open) depth++;
    else if (ch === close) { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function findJsonStringEnd(text, start, quote) {
  let esc = false;
  for (let i = start + 1; i < text.length; i++) {
    const ch = text[i];
    if (esc) { esc = false; continue; }
    if (ch === '\\') { esc = true; continue; }
    if (ch === quote) return i;
  }
  return -1;
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
