import { parse, parseAll, createStream, parseStream, YamlSecurity } from '../src/index.js';

let pass = 0, fail = 0;
const fails = [];

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
    if (!deepEqual(a[ka[i]], b[kb[i]])) return false;
  }
  return true;
}

function check(name, yaml, expectedOverride) {
  let expected;
  if (expectedOverride !== undefined) {
    expected = expectedOverride;
  } else {
    try { expected = parse(yaml); } catch (e) { expected = undefined; }
  }
  if (expected === undefined) { fail++; fails.push(name + ': no reference (parse threw)'); return; }
  const stream = createStream();
  const docs = [];
  stream.on('document', d => docs.push(d));
  let threw = null;
  try { stream.write(yaml); stream.end(); } catch (e) { threw = e; }
  if (threw) { fail++; fails.push(name + ': threw: ' + threw.message); return; }
  const got = docs[0];
  if (!deepEqual(got, expected)) {
    fail++;
    fails.push(name + ': mismatch\nexpected: ' + JSON.stringify(expected) + '\nactual:   ' + JSON.stringify(got));
  } else pass++;
}

const cases = {
  'simple map': 'a: 1\nb: two\nc: true',
  'nested map': 'a:\n  b: 1\n  c:\n    d: [1, 2, 3]',
  'seq scalars': '- a\n- b\n- 42',
  'seq maps': '- name: Ali\n  age: 30\n- name: Sara\n  age: 25',
  'seq nested': '- - 1\n  - 2\n- - 3',
  'block scalar literal': 'text: |\n  hello\n  world\n',
  'block scalar folded': 'text: >\n  hello\n  world\n',
  'block scalar strip': 'text: |-\n  hello\n',
  'block scalar keep': 'text: |+\n  hello\n',
  'flow seq': 'a: [1, 2, {b: 3}]',
  'flow map': 'a: {b: 1, c: [2, 3]}',
  'quoted keys': '"hello": 1\n\'world\': 2',
  'empty value': 'a:\nb: 2',
  'null scalar': 'a: null\nb: ~',
  'anchors': 'base: &b\n  x: 1\n  y: 2\ncopy: *b',
  'alias inline': 'a: &x 5\nb: *x',
  'top scalar': 'just a string',
  'merge keys': 'defaults: &d\n  a: 1\n  b: 2\nthing:\n  <<: *d\n  b: 3',
  'explicit key': '? key\n: value',
  'deep nested': 'a:\n  b:\n    c:\n      d: 1',
  'comments': '# top\nkey: val # inline\n# between\nother: 2',
  'empty doc': '',
  'dash empty item': '- \n- b',
  'seq item map empty val': '- a:\n    b: 2\n- c: 3',
  'top flow': '[1, 2, 3]',
  'top flow map': '{a: 1, b: 2}',
  'datetime': 'when: 2023-01-15\nwhen2: 2023-01-15T10:30:00Z',
  'multiline plain scalar': 'hello\n  world',
  'root quoted': '"hello"\n',
  'root single quoted': "'hi there'\n",
  'root tag scalar': 'a: &an:chor value\nb: *an:chor',
  'seq of maps block': '-\n  name: Mark\n-\n  name: Sammy\n',  'multiline plain value': 'plain:\n  This unquoted scalar\n  spans many lines.\n',
  'plain value then key': 'plain:\n  This is the value\nnext: 2\n',
  'dash alone': '-\n- b\n',
  'flow seq item': '- [ a, b ]\n- { a: b }\n',
  'seq anchor item': '- &a a\n- *a\n- &b !!str b\n',
  'anchor empty node': 'a: &anchor\nb: *anchor\n',
  'unicode anchor': '- &😁 unicode anchor\n',
  'seq flow mapping': '- { url: http://example.org }\n- [name, hr, avg]\n',
  'inline flow multiline': 'key: [\n  1, 2\n  ]\n',
  'own line flow': 'key:\n  [1, 2]\n',
  'own line flow multi': 'key:\n  [\n    1,\n    2\n  ]\n',
  'own line flow map': 'key:\n  {a: 1}\n',
  'root multiline flow': '[\n  1, 2, x\n]\n',
  'root flow comment': '[\n  1, # one\n  2\n]\n',
  'flow comment': 'key: [\n  1, # one\n  2\n  ]\n',
  'inline flow then item': '- [\n  1, 2\n  ]\n- 3\n',
  'own line flow then key': 'key:\n  [\n    1,\n    2\n  ]\nnext: 2\n',
  'inline flow trail comment': 'key: [\n  1, 2\n  ] # trail\n',
  'nested own line flow': 'a:\n  b:\n    [1, 2]\n  c: 3\n',
  'flow seq implicit maps': 'key: [a: 1, b: 2]\n',
  'flow seq quoted key map': 'key: ["a": 1]\n',
  'flow seq nested implicit': 'key: [a: [1, 2], b: {c: 3}]\n',
  'flow seq explicit keys': 'key: [? a, ? b]\n',
  'flow map explicit keys': 'key: {? a : 1, ? b : 2}\n',
  'flow map key no value': 'key: {a}\n',
  'flow attached colon scalar': 'key: {a: b:c}\n',
  'flow scheme colon scalar': 'key: {a: http://x}\n',
  'flow colon value': 'key: {a: :3}\n',
  'flow nested attached colon key': 'key: {a: {b:c}}\n',
  'flow seq numeric implicit key': 'key: [1: 2]\n',
};

const overrides = {
  'seq of maps block': [{ name: 'Mark' }, { name: 'Sammy' }],
  'multiline plain value': { plain: 'This unquoted scalar spans many lines.' },
  'plain value then key': { plain: 'This is the value', next: 2 },
  'dash alone': [null, "b"],
  'seq nested': [[1, 2], [3]],
  'datetime': { when: '2023-01-15', when2: '2023-01-15T10:30:00Z' },
};

for (const [name, yaml] of Object.entries(cases)) check(name, yaml, overrides[name]);

function checkThrows(name, yaml) {
  let threw = null;
  try {
    const stream = createStream();
    stream.write(yaml);
    stream.end();
  } catch (e) { threw = e; }
  if (!threw) { fail++; fails.push(name + ': expected throw but parsed ok'); } else pass++;
}

checkThrows('inline flow dedented closer', 'key: [\n  1, 2\n]\n');
checkThrows('seq inline flow dedented closer', '- [\n  1, 2\n]\n');
checkThrows('own line flow dedented item', 'key:\n  [\n1\n  ]\n');
checkThrows('flow comment dedented', 'key: [\n# comment\n  1, 2\n  ]\n');
checkThrows('quoted scalar dedented continuation', 'quoted: "a\nb"\n');
checkThrows('unbalanced inline flow at eof', 'key: [1, 2\n');
checkThrows('unbalanced root flow at eof', '[1, 2\n');
checkThrows('unbalanced flow map at eof', 'key: {a: 1\n');
checkThrows('empty flow seq entry', 'key: [,]\n');
checkThrows('empty flow seq entry middle', 'key: [1, , 2]\n');
checkThrows('empty flow map key', 'key: {,}\n');
checkThrows('empty flow map entry middle', 'key: {a: 1, , b: 2}\n');
checkThrows('missing comma in flow map', 'key: {a: 1 b: 2}\n');
checkThrows('missing comma in flow map 3', 'key: {a: 1 b: 2 c: 3}\n');
checkThrows('missing comma in flow seq', 'key: [a: 1 b: 2]\n');
checkThrows('missing comma after value', 'key: {a: 1, b: 2 c: 3}\n');
checkThrows('missing comma before comma', 'key: {a: 1 b: 2, c: 3}\n');
checkThrows('colon-space value', 'key: {a: : 3}\n');
checkThrows('empty colon value', 'key: {a: :}\n');
checkThrows('block plain colon-space', 'key: a: b\n');
checkThrows('block plain colon-space later', 'key: some text: more\n');
checkThrows('block plain tab colon-space', 'key: a\tb: c\n');
checkThrows('block value nested key', 'key: - a: b\n');
checkThrows('block value numeric colon-space', 'key: 1: 2\n');
checkThrows('block value trailing colon', 'key: a:\n');
checkThrows('block value comment colon-space', 'key: a: # comment\n');
checkThrows('block indented key continuation', 'key: a\n  b: c\n');
checkThrows('block indented flow map continuation', 'key: a\n  {b: 1}\n');
checkThrows('block seq mapping deeper indent', '- a: b\n    c: d\n');
checkThrows('block plain then quoted', 'key: a "b: c"\n');

checkAll('block plain attached colon', 'key: a:b\n');
checkAll('block plain scheme colon', 'key: http://x\n');
checkAll('block plain space colon', 'key: a :b c\n');
checkAll('block plain folded seq dash', 'key: a\n  [1, 2]\n');
checkAll('block plain folded map', 'key: a\n  {b:c}\n');
checkAll('block plain folded plain', 'key: a\n  b c\n');
checkAll('block sibling key ends scalar', 'key: a\nb: c\n');
checkAll('block seq item mapping', 'list:\n  - a: b\n');
checkAll('block seq item mapping multi', '- a: b\n  c: d\n');
checkAll('block dash continuation folds', 'key: a\n  - b\n');
checkAll('block anchor continuation folds', 'key: a\n  &x b\n');
checkAll('block question continuation folds', 'key: a\n  ? b\n');
checkAll('block quoted continuation folds', 'key: a\n  "b"\n');
checkAll('block deeper doc-end folds', 'key: a\n  ...\n');
checkAll('block deeper doc-start folds', 'key: a\n  ---\nnext: 1\n');
checkAll('block multi-line continuation folds', 'key: a\n  - b\n  c d\nnext: 1\n');
checkAll('root scalar deeper doc-end folds', 'a\n  ...\n');
checkAll('root scalar column-0 doc-end', 'a\n...\n');
checkAll('root scalar col-0 doc-start multi-doc', 'a\n---\n');
checkAll('seq dash continuation folds', '- a\n  - b\n');
checkAll('root scalar multi-doc after end', 'a\n...\nb: 1\n');
checkAll('compact quoted key', '"a":b\n');
checkAll('compact single-quoted key', "'a':b\n");
checkAll('compact key space before colon', '"a" :b\n');
checkAll('compact key with sibling', '"a":b\nc: d\n');
checkAll('compact key two keys', '"a":b\n"b":c\n');
checkAll('compact key nested', 'x:\n  "a":b\n');
checkAll('compact key seq item', '- "a":b\n');
checkAll('compact keys separate seq items', '- "a":b\n- "a":c\n');
checkAll('compact key seq item sibling', '- "a":b\n  c: d\n');
checkAll('compact key flow value', '"a": {b: 1}\n');
checkAll('compact key quoted value', '"a": "b:c"\n');
checkAll('compact key empty value', '"a":\n');
checkAll('compact key value folds', '"a":b\n  c\n');
checkThrows('compact proto key blocked', '"__proto__":x\n');
checkThrows('compact proto seq key blocked', '- "__proto__":x\n');
checkThrows('compact duplicate keys blocked', '"a":b\n"a":c\n');
checkThrows('compact nested duplicate keys blocked', 'x:\n  "a":b\n  "a":c\n');
checkThrows('compact proto duplicates blocked', '"__proto__":x\n"__proto__":y\n');

function checkAll(name, yaml) {
  const expected = parseAll(yaml);
  const stream = createStream();
  const docs = [];
  stream.on('document', d => docs.push(d));
  let threw = null;
  try { stream.write(yaml); stream.end(); } catch (e) { threw = e; }
  if (threw) { fail++; fails.push(name + ': threw ' + threw.message); return; }
  if (!deepEqual(docs, expected)) {
    fail++; fails.push(name + ': mismatch\nexpected: ' + JSON.stringify(expected) + '\nactual:   ' + JSON.stringify(docs));
  } else pass++;
}
checkAll('multidoc', 'a: 1\n---\nb: 2\n---\n- x');
checkAll('multidoc with ---', '---\na: 1\n---\nb: 2');
checkAll('single doc', 'a: 1');

async function testParseStream() {
  let n = 0;
  for await (const doc of parseStream('a: 1\n---\nb: 2')) n++;
  if (n !== 2) { fail++; fails.push('parseStream count: ' + n); } else pass++;
}
await testParseStream();

async function testParseStreamChunks() {
  async function* chunks() {
    yield 'a: 1\n---\n';
    yield 'b: 2\n';
  }
  const got = [];
  for await (const doc of parseStream(chunks())) got.push(doc);
  if (!deepEqual(got, [{ a: 1 }, { b: 2 }])) { fail++; fails.push('parseStream chunks: ' + JSON.stringify(got)); } else pass++;
}
await testParseStreamChunks();

async function testEventIter() {
  const stream = createStream();
  const types = [];
  const consumer = (async () => { for await (const ev of stream) types.push(ev.type); })();
  await new Promise(r => setTimeout(r, 0));
  stream.write('a: 1\n');
  stream.write('b: [1, 2]\n');
  stream.end();
  await consumer;
  const want = ['documentStart', 'mappingStart', 'key', 'scalar', 'key', 'sequenceStart', 'scalar', 'scalar', 'sequenceEnd', 'mappingEnd', 'documentEnd'];
  if (!deepEqual(types, want)) { fail++; fails.push('event iter: ' + JSON.stringify(types)); } else pass++;
}
await testEventIter();

function testAnchorsDisable() {
  const s = createStream({ anchors: 'disable' });
  let threw = false;
  try { s.write('a: &x 1\nb: *x\n'); s.end(); } catch (e) { threw = true; }
  if (!threw) { fail++; fails.push('anchors:disable should reject anchors'); } else pass++;
}
testAnchorsDisable();

function testLimits() {
  const s = createStream({ maxNodes: 5 });
  let threw = false;
  try { s.write('a:\n  b:\n    c:\n      d:\n        e:\n          f: 1\n'); s.end(); } catch (e) { threw = true; }
  if (!threw) { fail++; fails.push('maxNodes not enforced'); } else pass++;

  const s2 = createStream({ maxDepth: 3 });
  let threw2 = false;
  try { s2.write('a:\n  b:\n    c:\n      d:\n        e: 1\n'); s2.end(); } catch (e) { threw2 = true; }
  if (!threw2) { fail++; fails.push('maxDepth not enforced'); } else pass++;

  // Sequence items keep the depth counter (batch/stream parity: no reset).
  const s5 = createStream({ maxDepth: 2 });
  let threwA = false;
  try { s5.write('a:\n  - b:\n      c: 1\n'); s5.end(); } catch (e) { threwA = true; }
  if (!threwA) { fail++; fails.push('maxDepth not enforced across seq items'); } else pass++;

  const s6 = createStream({ maxDepth: 2 });
  let threwB = false;
  try { s6.write('- b:\n    c:\n      d: 1\n'); s6.end(); } catch (e) { threwB = true; }
  if (!threwB) { fail++; fails.push('maxDepth not enforced for nested seq item maps'); } else pass++;

  const s7 = createStream({ maxDepth: 1 });
  let threwC = false;
  try { s7.write('- a\n- b\n'); s7.end(); } catch (e) { threwC = true; }
  if (threwC) { fail++; fails.push('maxDepth=1 should allow a root sequence of scalars'); } else pass++;

  const s3 = createStream({ maxKeys: 2 });
  let threw3 = false;
  try { s3.write('a: 1\nb: 2\nc: 3\n'); s3.end(); } catch (e) { threw3 = true; }
  if (!threw3) { fail++; fails.push('maxKeys not enforced'); } else pass++;

  // Alias expansion bomb must be caught by maxExpansion (not just maxAlias):
  // each `*x` re-exposes the full anchored subtree and is charged its weight.
  const anchor = Array.from({ length: 200 }, (_, i) => i);
  const bomb = 'a: &x ' + JSON.stringify(anchor) + '\n'
    + Array.from({ length: 300 }, (_, i) => 'k' + i + ': *x').join('\n');
  const s4 = createStream({ maxExpansion: 5000, maxAlias: 100000 });
  let threw4 = false;
  try { s4.write(bomb); s4.end(); } catch (e) { threw4 = true; }
  if (!threw4) { fail++; fails.push('maxExpansion not enforced against alias bomb'); } else pass++;

  // createStream validates limits like setLimits / the YamlSecurity constructor
  let threw5 = false;
  try { createStream({ maxNodes: -1 }); } catch (e) { threw5 = true; }
  if (!threw5) { fail++; fails.push('createStream does not validate limits'); } else pass++;
}
testLimits();

function testClass() {
  const ys = new YamlSecurity();
  const s = ys.createStream();
  const docs = [];
  s.on('document', d => docs.push(d));
  s.write('a: 1');
  s.end();
  if (!deepEqual(docs, [{ a: 1 }])) { fail++; fails.push('YamlSecurity.createStream'); } else pass++;
}
testClass();

function testStrict() {
  const bigStr = '"' + 'a'.repeat(2_000_000) + '"';
  // Default maxStringLength is unlimited: 2MB string passes with raised input.
  const allow = createStream({ maxInputBytes: 5_000_000, maxNodes: 1_000_000 });
  let allowThrew = false;
  try { allow.write('s: ' + bigStr + '\n'); allow.end(); } catch (e) { allowThrew = true; }
  if (allowThrew) { fail++; fails.push('default stream allows 2MB string'); } else pass++;

  // strict maxStringLength=1MB enforced while streaming.
  const str = createStream({ strict: true, maxInputBytes: 5_000_000, maxNodes: 1_000_000 });
  let threw = false;
  try { str.write('s: ' + bigStr + '\n'); str.end(); } catch (e) { threw = true; }
  if (!threw) { fail++; fails.push('strict stream maxStringLength=1MB not enforced'); } else pass++;

  // strict maxDepth=30 blocks a depth-40 mapping.
  let deep = 'x: 1';
  for (let i = 0; i < 40; i++) deep = 'a:\n  ' + deep.replace(/\n/g, '\n  ');
  const sDeep = createStream({ strict: true, maxNodes: 1_000_000 });
  let threw2 = false;
  try { sDeep.write(deep + '\n'); sDeep.end(); } catch (e) { threw2 = true; }
  if (!threw2) { fail++; fails.push('strict stream maxDepth=30 not enforced'); } else pass++;

  // Strict instance limits carry over to instance streams.
  const ys = new YamlSecurity({ strict: true, maxInputBytes: 5_000_000, maxNodes: 1_000_000 });
  const inst = ys.createStream();
  let threw3 = false;
  try { inst.write('s: ' + bigStr + '\n'); inst.end(); } catch (e) { threw3 = true; }
  if (!threw3) { fail++; fails.push('strict instance createStream does not inherit limits'); } else pass++;

  // Explicit limits override the strict profile.
  const over = createStream({ strict: true, maxStringLength: 0, maxInputBytes: 5_000_000, maxNodes: 1_000_000 });
  let overThrew = false;
  try { over.write('s: ' + bigStr + '\n'); over.end(); } catch (e) { overThrew = true; }
  if (overThrew) { fail++; fails.push('strict + maxStringLength:0 override ignored'); } else pass++;

  // Standalone streams inherit the strict global profile set via setLimits.
  YamlSecurity.setLimits({ strict: true });
  const after = createStream({ maxInputBytes: 5_000_000, maxNodes: 1_000_000 });
  let afterThrew = false;
  try { after.write('s: ' + bigStr + '\n'); after.end(); } catch (e) { afterThrew = true; }
  if (!afterThrew) { fail++; fails.push('createStream should inherit strict global profile'); } else pass++;
  YamlSecurity.setLimits(); // reset
}
testStrict();

// ── DoS regression: multiline flow & large flow seq parse in linear time ──
{
  const flow = 'a: [\n' + '  x,\n'.repeat(20000) + '  ]';
  const t0 = Date.now();
  const s = createStream({ maxNodes: 1000000000, maxInputBytes: 1000000000, maxExpansion: 1000000000 });
  const docs = [];
  s.on('document', d => docs.push(d));
  let threw = null;
  try { s.write(flow); s.end(); } catch (e) { threw = e; }
  const ms = Date.now() - t0;
  if (threw) { fail++; fails.push('stream multiline flow threw: ' + threw.message); }
  else if (!docs[0] || !Array.isArray(docs[0].a) || docs[0].a.length !== 20000) { fail++; fails.push('stream multiline flow mismatch'); }
  else pass++;
  if (ms >= 3000) { fail++; fails.push('stream multiline flow too slow: ' + ms + 'ms'); } else pass++;
}
{
  const s = '[' + Array(50000).fill('1').join(',') + ']';
  const t0 = Date.now();
  const st = createStream({ maxNodes: 1000000000, maxInputBytes: 1000000000, maxExpansion: 1000000000 });
  const docs = [];
  st.on('document', d => docs.push(d));
  let threw = null;
  try { st.write(s); st.end(); } catch (e) { threw = e; }
  const ms = Date.now() - t0;
  if (threw) { fail++; fails.push('stream flow seq threw: ' + threw.message); }
  else if (!docs[0] || !Array.isArray(docs[0]) || docs[0].length !== 50000) { fail++; fails.push('stream flow seq mismatch'); }
  else pass++;
  if (ms >= 3000) { fail++; fails.push('stream flow seq too slow: ' + ms + 'ms'); } else pass++;
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
if (fails.length) {
  for (const f of fails) console.log('  FAIL: ' + f);
  process.exit(1);
}
