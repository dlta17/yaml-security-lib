import { YamlSecurity } from '../src/index.js';

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) { passed++; }
  else { failed++; console.error('FAIL:', msg); }
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
function assertEqual(a, b, msg) {
  if (deepEqual(a, b)) { passed++; }
  else { failed++; console.error('FAIL:', msg, '- got:', JSON.stringify(a), 'expected:', JSON.stringify(b)); }
}

function assertThrows(fn, msg) {
  try { fn(); failed++; console.error('FAIL:', msg, '- no throw'); }
  catch { passed++; }
}

const p = new YamlSecurity();

// ── Basic parsing ──
assertEqual(p.parse('a: 1').result, { a: 1 }, 'basic kv');
assertEqual(p.parse('name: hello').result, { name: 'hello' }, 'string value');
assertEqual(p.parse('flag: true').result, { flag: true }, 'bool true');
assertEqual(p.parse('flag: false').result, { flag: false }, 'bool false');
assertEqual(p.parse('n: null').result, { n: null }, 'null');
assertEqual(p.parse('n: ~').result, { n: null }, 'tilde null');

// ── Nested ──
const nested = p.parse('user:\n  name: Ali\n  age: 25').result;
assertEqual(nested, { user: { name: 'Ali', age: 25 } }, 'nested object');

// ── Sequences ──
assertEqual(p.parse('- a\n- b\n- c').result, ['a', 'b', 'c'], 'basic sequence');
assertEqual(p.parse('- 1\n- 2\n- 3').result, [1, 2, 3], 'number sequence');

// ── Inline flow ──
assertEqual(p.parse('[1, 2, 3]').result, [1, 2, 3], 'inline array');
assertEqual(p.parse('{a: 1, b: 2}').result, { a: 1, b: 2 }, 'inline object');

// ── Duplicate keys ──
assert(!p.parse('x: 1\nx: 2').ok, 'duplicate key detected');
assert(!p.parse('{a: 1, a: 2}').ok, 'inline duplicate key');

// ── Prototype pollution ──
assert(!p.parse('__proto__: polluted').ok, 'proto pollution blocked');
assert(!p.parse('constructor:\n  prototype:\n    x: 1').ok, 'constructor.prototype blocked');

// ── Alias depth ──
const chain = '&a hello\n&b *a\n&c *b\n&d *c\n&e *d\n&f *e\n&g *f\n&h *g\n&i *h\n&j *i\n&k *j\nkey: *k';
assert(p.parse(chain).ok, 'alias chain depth=10 ok');
YamlSecurity.setLimits({ maxAliasDepth: 3 });
assert(!p.parse(chain).ok, 'alias chain depth=10 blocked at limit=3');
YamlSecurity.setLimits();

// ── Anchor with alias ref (scalar) ──
assertEqual(p.parse('&a hello\nb: *a').result, { b: 'hello' }, 'anchor + alias scalar');

// ── Merge keys ──
const merged = p.parse('defaults: &d\n  x: 1\n  y: 2\ncustom:\n  <<: *d\n  z: 3').result;
assertEqual(merged.custom, { x: 1, y: 2, z: 3 }, 'merge keys (<<:)');

// ── Tags ──
assertEqual(p.parse('x: !!str 42').result, { x: '42' }, '!!str tag');
assertEqual(p.parse('x: !!int 3.14').result, { x: 3 }, '!!int tag');
assertEqual(p.parse('x: !!null hello').result, { x: null }, '!!null tag');
assertEqual(p.parse('x: !!bool true').result, { x: true }, '!!bool tag');
assertEqual(p.parse('x: !!bool false').result, { x: false }, '!!bool false');

// ── Block scalars ──
assertEqual(p.parse('x: |\n  hello\n  world').result, { x: 'hello\nworld\n' }, 'literal block');
assertEqual(p.parse('x: >\n  hello\n  world').result, { x: 'hello world\n' }, 'folded block');

// ── Quoted keys ──
assertEqual(p.parse('"a:b": 1').result, { 'a:b': 1 }, 'quoted key with colon');

// ── YAML Directives ──
assertEqual(p.parse('%YAML 1.2\n---\nhello: world').result, { hello: 'world' }, '%YAML directive');
assertEqual(p.parse('---\nkey: value').result, { key: 'value' }, '--- doc start');
assertEqual(p.parse('x: 1\n...\ny: 2').result, { x: 1 }, '... doc end stops parsing');
assertEqual(p.parse('# comment\n%YAML 1.2\n---\nval: 42').result, { val: 42 }, 'directives with comments');

// ── Escape sequences in double-quoted strings ──
assertEqual(p.parse('x: "hello\\nworld"').result, { x: 'hello\nworld' }, 'double-quoted \\n');
assertEqual(p.parse('x: "tab\\there"').result, { x: 'tab\there' }, 'double-quoted \\t');
assertEqual(p.parse('x: "back\\\\slash"').result, { x: 'back\\slash' }, 'double-quoted \\\\');
assertEqual(p.parse('x: "quo\\"ted"').result, { x: 'quo"ted' }, 'double-quoted \\"');
assertEqual(p.parse('x: "null\\0char"').result, { x: 'null\x00char' }, 'double-quoted \\0');
assertEqual(p.parse('x: "\\x1Bescape"').result, { x: '\x1Bescape' }, 'double-quoted \\x hex');

// ── Merge key list ──
const mergeList = p.parse('base: &b\n  x: 1\n  y: 2\nextra: &e\n  z: 3\nmerged:\n  <<: [*b, *e]\n  w: 4').result;
assertEqual(mergeList.merged, { x: 1, y: 2, z: 3, w: 4 }, 'merge key list (<<: [*a,*b])');

// ── Standalone scalars ──
assertEqual(p.parse('hello').result, 'hello', 'standalone scalar string');
assertEqual(p.parse('42').result, 42, 'standalone scalar number');
assertEqual(p.parse('true').result, true, 'standalone scalar bool');
assertEqual(p.parse('null').result, null, 'standalone scalar null');

// ── Tab indentation (YAML 1.2 disallows tabs, but handle without crash) ──
assert(p.parse('a:\n\tb: 1').ok !== undefined, 'tab indentation handled without crash');

// ── Block scalar indent indicators ──
assertEqual(p.parse('x: |1\n  hello').result, { x: 'hello\n' }, 'literal block indent |1');
assertEqual(p.parse('x: >1\n  hello\n  world').result, { x: 'hello world\n' }, 'folded block indent >1');

// ── ... as multi-doc separator in parseAll ──
const multiEnd = p.parseAll('a: 1\n...\nb: 2');
assertEqual(multiEnd.result, [{ a: 1 }, { b: 2 }], '... as multi-doc separator');

// ── Multi-document ──
const docs = p.parseAll('a: 1\n---\nb: 2\n---\nc: 3');
assertEqual(docs.result, [{ a: 1 }, { b: 2 }, { c: 3 }], 'multi-document');

// ── Dump ──
const dumped = p.dump({ x: 1, y: 'hello' });
assert(dumped.ok, 'dump ok');
assert(dumped.result.includes('x: 1'), 'dump contains x: 1');

// ── Circular ref in dump ──
const circ = { a: 1 };
circ.self = circ;
assert(!p.dump(circ).ok, 'circular dump blocked');

// ── parseToJSON ──
const json = p.parseToJSON('a: 1');
assert(json.ok, 'parseToJSON ok');
assert(json.result.includes('"a"'), 'parseToJSON has key');

// ── Constructor options ──
const strict = new YamlSecurity({ maxAliasDepth: 2 });
assert(!strict.parse('&w hello\n&x *w\n&y *x\n&z *y\nb: *z').ok, 'constructor opts maxAliasDepth=2');

// ── Billion Laughs protection ──
const billionLaughs = '&a lol\nb: &b [*a, *a]\nc: &c [*b, *b]\nd: &d [*c, *c]\ne: &e [*d, *d]\nf: &f [*e, *e]\ng: &g [*f, *f]\nh: &h [*g, *g]\ni: &i [*h, *h]\nj: &j [*i, *i]\nk: &k [*j, *j]\nl: &l [*k, *k]\nm: &m [*l, *l]\nn: &n [*m, *m]\no: &o [*n, *n]\np: *o';
assert(!p.parse(billionLaughs).ok, 'Billion Laughs (16 levels) blocked');
const small = new YamlSecurity({ maxExpansion: 1000 });
assert(!small.parse(billionLaughs).ok, 'Billion Laughs blocked with maxExpansion=1000');
const normal = new YamlSecurity({ maxExpansion: 200_000 });
assert(!normal.parse(billionLaughs).ok, 'Billion Laughs blocked even with maxExpansion=200K');

// ── Summary ──
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
