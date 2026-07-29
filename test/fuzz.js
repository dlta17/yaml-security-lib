import { YamlSecurity, setLimits } from '../src/index.js';

let passed = 0;
let failed = 0;
let blocked = 0;

function assert(cond, msg) {
  if (cond) { passed++; }
  else { failed++; console.error('FAIL:', msg); }
}

function assertSafe(yamlStr, desc) {
  const r = p.parse(yamlStr);
  if (!r.ok) blocked++;
  assert(typeof r.ok === 'boolean', `${desc}: should return ok boolean`);
  if (r.ok) {
    assert(typeof r.result !== 'undefined' || r.result === null, `${desc}: result should be defined`);
  } else {
    assert(typeof r.error === 'string', `${desc}: error should be a string`);
  }
}

function assertThrows(fn, msg) {
  try { fn(); failed++; console.error('FAIL:', msg, '- no throw'); }
  catch { passed++; }
}

const p = new YamlSecurity();
const strict = new YamlSecurity({ maxAliasDepth: 5, maxExpansion: 5000, maxInputBytes: 1024 * 1024 });

// ── Empty / minimal ──
assertSafe('', 'empty string');
assertSafe('   ', 'whitespace only');
assertSafe('\n\n\n', 'newlines only');
assertSafe('# comment only', 'comment only');
assertSafe('---', 'doc marker only');
assertSafe('...', 'end marker only');
assertSafe('%YAML 1.2', 'yaml directive only');
assertSafe('%TAG !x! tag:example.com:', 'tag directive only');

// ── Unicode / special chars ──
assertSafe('key: "\\u0000"', 'null byte in string');
assertSafe('key: "\\x00\\x01\\x02"', 'control chars');
assertSafe('emoji: 😀🎉🚀', 'emoji values');
assertSafe('日本語: こんにちは', 'unicode keys/values');
assertSafe('a: "\\n\\t\\r\\\\"', 'escaped special chars');
assertSafe('"\x00\x01": val', 'control chars in key');
assertSafe('a: "\x1b[31mred"', 'ANSI escape in string');

// ── Edge case numbers ──
assertSafe('x: 999999999999999999999999999', 'huge int');
assertSafe('x: -999999999999999999999999999', 'huge negative int');
assertSafe('x: 1e999', 'float overflow');
assertSafe('x: .inf', 'infinity');
assertSafe('x: .Inf', 'Inf');
assertSafe('x: .INF', 'INF');
assertSafe('x: .nan', 'nan');
assertSafe('x: .NaN', 'NaN');
assertSafe('x: 0.0000000000000001', 'tiny float');

// ── Sequences edge cases ──
assertSafe('- ', 'empty sequence item');
assertSafe('-\n  -\n    -', 'nested empty seqs');
assertSafe('[*a, *b]', 'undefined aliases in flow');
assertSafe('[1, 2, 3, 4, 5, 6, 7, 8, 9, 0]', 'long flow seq');
assertSafe('- [1, 2]\n- [3, 4]', 'nested flow seqs');

// ── Mappings edge cases ──
assertSafe('{}', 'empty inline mapping');
assertSafe('{ }', 'space in empty mapping');
assertSafe('"": value', 'empty string key');
assertSafe("'': value", 'empty single-quoted key');
assertSafe(': value', 'empty key (bare colon)');
assertSafe('null: value', 'null as key');

// ── Prototype pollution variants ──
assertSafe('__proto__: x', 'proto direct');
assertSafe('__proto__:\n  x: 1', 'proto nested');
assertSafe('constructor: x', 'constructor direct');
assertSafe('constructor:\n  prototype:\n    x: 1', 'constructor.prototype');
assertSafe('a:\n  __proto__: x\n  b: 1', 'nested proto');
assertSafe('"__proto__": x', 'quoted proto key');
assertSafe("'__proto__': x", 'single-quoted proto key');
assertSafe('["__proto__"]: x', 'flow proto key');
assertSafe('constructor:\n  ["prototype"]:\n    x: 1', 'flow constructor.prototype');

// ── Duplicate key variants ──
assertSafe('a: 1\na: 2', 'dup key simple');
assertSafe('a: 1\n"a": 2', 'dup key quoted');
assertSafe("a: 1\n'a': 2", 'dup key single-quoted');
assertSafe('{a: 1, a: 2}', 'dup key inline');
assertSafe('a:\n  b: 1\n  b: 2', 'dup nested key');
assertSafe('x: &a 1\n<<: *a\nx: 2', 'dup after merge');
assertSafe('x: &a 1\n<<: *a\n<<: *a', 'double merge');

// ── Block scalar edge cases ──
assertSafe('x: |\n  \n  \n', 'literal block blank lines');
assertSafe('x: |\n', 'literal block empty');
assertSafe('x: |+\n  hello\n  world\n', 'literal keep');
assertSafe('x: |-\n  hello\n  world\n', 'literal strip');
assertSafe('x: >\n  \n  \n', 'folded block blank lines');
assertSafe('x: >+\n  hello\n  world\n', 'folded keep');
assertSafe('x: >-\n  hello\n  world\n', 'folded strip');
assertSafe('x: |\n  hello\n  \n  world\n', 'literal with empty line');

// ── Anchor / alias edge cases ──
assertSafe('&a [1, 2]\nb: *a', 'anchor on flow seq');
assertSafe('&a {x: 1}\nb: *a', 'anchor on flow mapping');
assertSafe('&a hello\n&b *a\nc: *b', 'alias chain length 2');
assertSafe('&a hello\nc: *a\nd: *a', 'alias used twice');
assertSafe('x: *nonexistent', 'undefined alias');
assertSafe('[*nonexistent]', 'undefined alias in seq');

// ── ReDoS / regex bombs ──
assertSafe('x: "' + '\\\\'.repeat(100) + '"', 'many backslashes');
assertSafe('x: "' + '\\n\\t'.repeat(1000) + '"', 'many escape sequences');
assertSafe('x: "' + 'a'.repeat(10000) + '"', 'very long string in quotes');
assertSafe('x: ' + 'a'.repeat(10000), 'very long unquoted string');

// ── Deep nesting ──
function deepNest(depth) {
  if (depth <= 0) return 'x: 1';
  return 'a:\n  ' + deepNest(depth - 1).replace(/\n/g, '\n  ');
}
assertSafe(deepNest(100), 'deep nesting 100 levels');

// ── Mixed tabs/spaces ──
assertSafe('a:\n\tb: 1', 'tab in indentation');
assertSafe('a:\n  \tb: 1', 'mixed tab+space');

// ── Document separators ──
assertSafe('%YAML 1.2\n---\n%TAG !t! tag:x:\n---\na: 1', 'directives before each doc');
assertSafe('a: 1\n...\nb: 2', 'doc end marker mid-stream');
assertSafe('key: value\n...\n%YAML 1.2\n---\nother: val', 'end marker then new doc');

// ── Maximum expansion bomb ──
function genBomb(levels) {
  let s = '&a lol\n';
  let prev = 'a';
  for (let i = 0; i < levels; i++) {
    const name = String.fromCharCode(98 + i); // b, c, d, ...
    s += `${name}: &${name} [*${prev}, *${prev}]\n`;
    prev = name;
  }
  s += `z: *${prev}`;
  return s;
}
assertSafe(genBomb(10), 'bomb 10 levels');
assertSafe(genBomb(20), 'bomb 20 levels');

// ── Deep alias chain ──
function genChain(n) {
  let s = '';
  for (let i = 0; i < n; i++) {
    s += `&a${i} ${i === 0 ? i : '*a' + (i-1)}\n`;
  }
  s += `key: *a${n-1}`;
  return s;
}
assertSafe(genChain(100), 'alias chain 100');
assertSafe(genChain(1000), 'alias chain 1000');

// ── Random input stress ──
const randomStrs = [
  '\x00\x00\x00\x00', '\xff\xfe\xfd\xfc',
  'null: undefined: NaN: Infinity:',
  '[...]', '{...}', '[,]', '{,}',
  '!!!!!!!!', '@@@@@@@@', '$$$$$$$$',
  '<<<<<', '>>>>>', '|||||',
  'truefalse', 'yesno', 'onnof',
  '1.2.3', '1,2,3', '1:2:3',
  '2020-01-01', '12:34:56',
  '<<', '>>', '**', '&&',
  '"""', "'''", '"""\n"""',
  '[][][]', '{}{}{}',
];
for (const s of randomStrs) {
  assertSafe(s, `random input: ${JSON.stringify(s)}`);
}

// ── Binary / non-YAML ──
const pngMagic = '\x89PNG\r\n\x1a\n';
assertSafe(pngMagic, 'PNG magic bytes');
assertSafe('<html>\n<body>\nhello\n</body>\n</html>', 'HTML injection');
assertSafe('<?xml version="1.0"?>\n<root/>', 'XML injection');
assertSafe('#!/usr/bin/env node\nconsole.log("hello")', 'shebang injection');

// ── Duplicate key in merged content ──
assertSafe('base: &b\n  x: 1\n  y: 2\nother:\n  <<: *b\n  x: 10', 'merge with override');
assertSafe('base: &b\n  x: 1\nextra: &e\n  x: 2\nboth:\n  <<: [*b, *e]', 'merge list');

// ── Quote edge cases ──
assertSafe('"key\\nwith\\tescapes": value', 'escaped quotes key');
assertSafe("'key\\nwith\\traw': value", 'single-quoted raw');
assertSafe('x: "value with \\"quotes\\" inside"', 'double quote inside value');

// ── Flow collection edge cases ──
assertSafe('[1, [2, [3, [4, [5]]]]]', 'deep flow seq');
assertSafe('{a: {b: {c: {d: {e: 1}}}}}', 'deep flow mapping');
assertSafe('[{a: 1}, {b: 2}, {c: [3, 4]}]', 'mixed flow seq/mapping');

// ── Tag abuse variants ──
assertSafe('x: !!str', 'tag with no value');
assertSafe('x: !!int hello', 'wrong tag type');
assertSafe('x: !!bool 7', 'bool with number');
assertSafe('x: !!null something', 'null with value');
assertSafe('!!str x: 1', 'tag on key');
assertSafe('!!str [1, 2, 3]', 'tag on seq');

// ── Oversized inputs ──
const hugeObjStr = 'a: ' + JSON.stringify(Array.from({length: 500}, (_, i) => ({[`k${i}`]: 'v'.repeat(100)})));
assertSafe(hugeObjStr, 'large object (500 keys)');

const longLine = 'x: ' + 'a'.repeat(50000);
assertSafe(longLine, '50KB line');

// ── Multi-document edge cases ──
const pd = p.parseAll;
assertSafe('a: 1\n...\nb: 2\n...\nc: 3', 'multi-doc with ... separators');

// ── Recursive yamlToJS guard ──
const deepSeqYaml = 'x: [1, [2, [3, [4, [5, [6, [7, [8, [9, [10, [11, [12, [13, [14, [15, [16, [17, [18, [19, [20, [21, [22, [23, [24, [25]]]]]]]]]]]]]]]]]]]]]]]]';
assertSafe(deepSeqYaml, 'deep seq 25 levels handled safely');

// ── Summary ──
console.log(`\n${passed} passed, ${failed} failed, ${blocked} blocked (expected)`);
process.exit(failed > 0 ? 1 : 0);
