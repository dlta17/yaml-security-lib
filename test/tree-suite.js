import fs from 'fs';
import path from 'path';
import { tree } from '../src/index.js';

const suiteDir = process.env.YAML_SUITE_DIR || '/home/nedal/yaml-test-suite/src';

if (!fs.existsSync(suiteDir)) {
  console.log('Tree event stream suite: SKIPPED (suite dir not found: ' + suiteDir + '); set YAML_SUITE_DIR to enable');
  process.exit(0);
}

let matched = 0;
let failed = 0;
let errored = 0;
let expectedThrows = 0;
const failures = [];

function dedent(s) {
  const lines = String(s).split('\n');
  let min = Infinity;
  for (const l of lines) {
    if (l.trim() === '') continue;
    min = Math.min(min, /^[ \t]*/.exec(l)[0].length);
  }
  return lines.map(l => l.slice(min)).join('\n');
}

function normTree(s) {
  return String(s).replace(/␣/g, ' ').split('\n').map(l => l.trimStart()).filter(l => l !== '').join('\n');
}

const files = fs.readdirSync(suiteDir).filter(f => f.endsWith('.yaml'));
console.log('Tree event stream suite: ' + files.length + ' test files');

for (const file of files) {
  const content = fs.readFileSync(path.join(suiteDir, file), 'utf8');
  const yamlM = content.match(/yaml: \|\n((?:[^\n]*\n)*?)\s{2}\w+:/);
  const treeM = content.match(/tree: \|\n((?:[^\n]*\n)*?)(?:  \w+:|\s*$)/);
  if (!yamlM || !treeM || treeM[1].trim() === '') continue;

  const cut = s => { const i = s.indexOf('\n- '); return i < 0 ? s : s.slice(0, i); };
  const yaml = dedent(cut(yamlM[1]))
    .replace(/␣/g, ' ')
    .replace(/—*»/g, '\t')
    .replace(/↵/g, '')
    .replace(/←/g, '\r')
    .replace(/⇔/g, '\uFEFF')
    .replace(/∎\n?$/, '');
  const firstCaseBlock = content.split('\n- ').slice(0, 2).join('\n- ');
  const isFailCase = firstCaseBlock.includes('fail: true');

  let ours;
  try {
    ours = tree(yaml);
  } catch (e) {
    if (isFailCase) { expectedThrows++; continue; }
    errored++;
    failures.push({ file, error: 'unexpected throw: ' + e.message });
    continue;
  }
  if (isFailCase) {
    failed++;
    failures.push({ file, error: 'expected parse failure but tree() succeeded' });
    continue;
  }

  const expected = normTree(dedent(cut(treeM[1])));
  if (normTree(ours) === expected) matched++;
  else {
    failed++;
    failures.push({ file, expected, actual: normTree(ours) });
  }
}

console.log('\n' + matched + ' matched, ' + failed + ' failed, ' + errored + ' errored, ' + expectedThrows + ' expected throws');
if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures.slice(0, 20)) {
    console.log('  ' + f.file);
    if (f.error) console.log('    error: ' + f.error);
    if (f.expected) console.log('    expected:\n' + indentLines(f.expected));
    if (f.actual) console.log('    actual:\n' + indentLines(f.actual));
  }
}
process.exit(failed > 0 ? 1 : 0);

function indentLines(s) {
  return s.split('\n').map(l => '      ' + l).join('\n');
}
