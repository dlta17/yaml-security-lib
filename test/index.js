import { YamlSecurity, parse, parseAll, dump, YAMLException, YamlType, Schema, getBaseConfig } from '../src/index.js';

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

// ── Multiline flow ──
assertEqual(p.parse('key:\n  [1, 2]').result, { key: [1, 2] }, 'own line flow');
assertEqual(p.parse('key:\n  [\n    1,\n    2\n  ]').result, { key: [1, 2] }, 'own line flow multi');
assertEqual(p.parse('key:\n  {a: 1}').result, { key: { a: 1 } }, 'own line flow map');
assertEqual(p.parse('key: [\n  1, 2\n  ]').result, { key: [1, 2] }, 'inline flow multiline');
assertEqual(p.parse('- [\n  1, 2\n  ]\n- 3').result, [[1, 2], 3], 'inline flow then item');
assertEqual(p.parse('[\n  1, # one\n  2\n]').result, [1, 2], 'root flow comment');
assertEqual(p.parse('key: [\n  1, # one\n  2\n  ]').result, { key: [1, 2] }, 'flow comment');
assert(!p.parse('key: [\n  1, 2\n]').ok, 'dedented closer rejected');
assert(!p.parse('- [\n  1, 2\n]').ok, 'dedented seq closer rejected');
assert(!p.parse('key:\n  [\n1\n  ]').ok, 'own line dedented item rejected');
assert(!p.parse('key: [1, 2').ok, 'unbalanced inline flow rejected');
assert(!p.parse('[1, 2').ok, 'unbalanced root flow rejected');
assert(!p.parse('key: {,}').ok, 'empty flow map key rejected');
assert(!p.parse('key: {a: 1, , b: 2}').ok, 'empty flow map entry rejected');
assertEqual(p.parse('key: {a: 1, b: 2,}').result, { key: { a: 1, b: 2 } }, 'trailing comma in flow map');
assertEqual(p.parse('key: {}').result, { key: {} }, 'empty flow map');
assertEqual(p.parse('key: [a: 1, b: 2]').result, { key: [{ a: 1 }, { b: 2 }] }, 'flow seq implicit maps');
assertEqual(p.parse('key: ["a": 1]').result, { key: [{ a: 1 }] }, 'flow seq quoted key map');
assertEqual(p.parse('key: [a: [1, 2], b: {c: 3}]').result, { key: [{ a: [1, 2] }, { b: { c: 3 } }] }, 'flow seq nested implicit');
assertEqual(p.parse('key: [? a, ? b]').result, { key: [{ a: null }, { b: null }] }, 'flow seq explicit keys');
assertEqual(p.parse('key: {? a : 1, ? b : 2}').result, { key: { a: 1, b: 2 } }, 'flow map explicit keys');
assertEqual(p.parse('key: {a}').result, { key: { a: null } }, 'flow map key no value');
// Missing comma between flow entries (js-yaml parity)
assert(!p.parse('{a: 1 b: 2}').ok, 'missing comma in flow map rejected');
assert(!p.parse('{a: 1 b: 2 c: 3}').ok, 'missing comma (3 entries) rejected');
assert(!p.parse('[a: 1 b: 2]').ok, 'missing comma in flow seq rejected');
assert(!p.parse('{a: 1, b: 2 c: 3}').ok, 'missing comma after value rejected');
assert(!p.parse('{a: 1 b: 2, c: 3}').ok, 'missing comma before comma rejected');
assertEqual(p.parse('{a: b:c}').result, { a: 'b:c' }, 'attached colon stays scalar');
assertEqual(p.parse('{a: http://x}').result, { a: 'http://x' }, 'scheme colon stays scalar');
assertEqual(p.parse('{a: 1:b}').result, { a: '1:b' }, 'number+colon stays scalar');
assertEqual(p.parse('{a: :3}').result, { a: ':3' }, 'colon-prefixed value stays scalar');
assert(!p.parse('{a: : 3}').ok, 'colon-space value rejected');
assertEqual(p.parse('{a: {b:c}}').result, { a: { 'b:c': null } }, 'nested attached-colon key');
assertEqual(p.parse('[1: 2]').result, [{ 1: 2 }], 'flow seq numeric implicit key');

// ── Block plain-scalar ':' key separators rejected (js-yaml parity) ──
assert(!p.parse('key: a: b').ok, 'block plain value with colon-space rejected');
assert(!p.parse('key: some text: more').ok, 'colon-space later in value rejected');
assert(!p.parse('key: a b: c').ok, 'colon-space after multiword rejected');
assert(!p.parse('key: a\tb: c').ok, 'tab before colon-space rejected');
assert(!p.parse('key: - a: b').ok, 'block value then nested key rejected');
assert(!p.parse('key: 1: 2').ok, 'numeric block value colon-space rejected');
assert(!p.parse('key: a:').ok, 'trailing colon-space rejected');
assert(!p.parse('key: a :').ok, 'space before trailing colon rejected');
assert(!p.parse('key: x# c: d').ok, 'comment-looking value colon-space rejected');
assert(!p.parse('key: a: # comment').ok, 'value then comment colon-space rejected');
assertEqual(p.parse('key: a :b c').result, { key: 'a :b c' }, 'attached colon stays scalar');
assertEqual(p.parse('key: http://x').result, { key: 'http://x' }, 'scheme colon stays scalar');
assertEqual(p.parse('key: a:b').result, { key: 'a:b' }, 'attached colon stays scalar');
assertEqual(p.parse('key: 10:30:00').result, { key: '10:30:00' }, 'time colon stays scalar');
assert(!p.parse('key: a "b: c"').ok, 'plain scalar then quoted scalar rejected');

// ── Block plain-scalar continuation (js-yaml parity) ──
assert(!p.parse('key: a\n  b: c').ok, 'indented key continuation rejected');
assert(!p.parse('key: a\n  b: c\nnext: 1').ok, 'indented key continuation with sibling rejected');
assert(!p.parse('key: a: b\n  c: d').ok, 'nested key continuation after value rejected');
assert(!p.parse('key: a\n  {b: 1}').ok, 'flow map continuation rejected');
assertEqual(p.parse('key: a\n  {b:c}').result, { key: 'a {b:c}' }, 'attached-colon flow folds');
assertEqual(p.parse('key: a\n  b c').result, { key: 'a b c' }, 'plain continuation folds');
assertEqual(p.parse('key: a\n  [1, 2]').result, { key: 'a [1, 2]' }, 'flow seq continuation folds');
assertEqual(p.parse('key: a\nb: c').result, { key: 'a', b: 'c' }, 'sibling key ends scalar');
assertEqual(p.parse('list:\n  - a: b\n').result, { list: [{ a: 'b' }] }, 'seq item block mapping valid');
assertEqual(p.parse('- a: b\n  c: d').result, [{ a: 'b', c: 'd' }], 'seq block mapping multi-key valid');
assert(!p.parse('- a: b\n    c: d').ok, 'seq block mapping deeper indent rejected');
assertEqual(p.parse('key: a\n  - b').result, { key: 'a - b' }, 'dash continuation folds');
assertEqual(p.parse('key: a\n  "b"').result, { key: 'a "b"' }, 'quoted continuation folds');
assertEqual(p.parse('key: a\n  &x b').result, { key: 'a &x b' }, 'anchor continuation folds');
assertEqual(p.parse('key: a\n  ? b').result, { key: 'a ? b' }, 'question continuation folds');
assertEqual(p.parse('key: a\n  ...').result, { key: 'a ...' }, 'deeper doc-end marker folds');
assertEqual(p.parse('key: a\n  ---').result, { key: 'a ---' }, 'deeper doc-start marker folds');
assertEqual(p.parse('key: a\n  |\n  text').result, { key: 'a | text' }, 'block-scalar indicator folds');
assertEqual(p.parse('key: a\n  *ref').result, { key: 'a *ref' }, 'alias token folds');
assertEqual(p.parse('key: a\n  !tag x').result, { key: 'a !tag x' }, 'tag folds');
assertEqual(p.parse('key: a\n  - b\n  c d\nnext: 1').result, { key: 'a - b c d', next: 1 }, 'multi-line continuation folds');
assertEqual(p.parse('- a\n  - b').result, ['a - b'], 'seq dash continuation folds');
assertEqual(p.parse('a\n  ...').result, 'a ...', 'root scalar deeper doc-end folds');
assertEqual(p.parse('a\n...').result, 'a', 'root scalar column-0 doc-end terminates');
assert(!p.parse('key: a\n  ... : x').ok, 'marker with key-sep rejected');

// ── Duplicate keys ──
assert(!p.parse('x: 1\nx: 2').ok, 'duplicate key detected');
assert(!p.parse('{a: 1, a: 2}').ok, 'inline duplicate key');

// ── Prototype pollution ──
assert(!p.parse('__proto__: polluted').ok, 'proto pollution blocked');
assert(!p.parse('constructor:\n  prototype:\n    x: 1').ok, 'constructor.prototype blocked');

// ── Compact quoted-key mappings (attached value, PyYAML-style) ──
assertEqual(p.parse('"a":b').result, { a: 'b' }, 'compact double-quoted key/value');
assertEqual(p.parse("'a':b").result, { a: 'b' }, 'compact single-quoted key/value');
assertEqual(p.parse('"a" :b').result, { a: 'b' }, 'compact key with space before colon');
assertEqual(p.parse('"a":b c').result, { a: 'b c' }, 'compact key attached multi-word value');
assertEqual(p.parse('"a": {b: 1}').result, { a: { b: 1 } }, 'compact key flow value');
assertEqual(p.parse('"a": "b:c"').result, { a: 'b:c' }, 'compact key quoted value');
assertEqual(p.parse('"a":').result, { a: null }, 'compact key empty value stays null');
assertEqual(p.parse('"a":b\nc: d').result, { a: 'b', c: 'd' }, 'compact key with sibling');
assertEqual(p.parse('"a":b\n"b":c').result, { a: 'b', b: 'c' }, 'two compact keys');
assertEqual(p.parse('x:\n  "a":b').result, { x: { a: 'b' } }, 'nested compact key');
assertEqual(p.parse('"a":b\n  c').result, { a: 'b c' }, 'compact key value folds continuation');
assertEqual(p.parse('- "a":b').result, [{ a: 'b' }], 'compact key as seq item');
assertEqual(p.parse('- "a":b\n- "a":c').result, [{ a: 'b' }, { a: 'c' }], 'compact keys in separate seq items');
assertEqual(p.parse('- "a":b\n  c: d').result, [{ a: 'b', c: 'd' }], 'compact key seq item with sibling');
assertEqual(p.parse('a:\n  - "b":c').result, { a: [{ b: 'c' }] }, 'compact key nested seq item');
assertEqual(p.parse('"a"').result, 'a', 'bare quoted scalar unchanged');
assertEqual(p.parse('key: a\n  "b":c').result, { key: 'a "b":c' }, 'compact quoted token in continuation still folds');
assert(!p.parse('"__proto__":x').ok, 'compact proto key blocked');
assert(!p.parse('"constructor":x').ok, 'compact constructor key blocked');
assert(!p.parse('- "__proto__":x').ok, 'compact proto key in seq blocked');
assert(!p.parse('"a":b\n"a":c').ok, 'compact duplicate keys blocked');
assert(!p.parse('x:\n  "a":b\n  "a":c').ok, 'compact nested duplicate keys blocked');
assert(!p.parse('"__proto__":x\n"__proto__":y').ok, 'compact proto duplicates blocked');

// ── Alias depth ──
const chain = '&a hello\n&b *a\n&c *b\n&d *c\n&e *d\n&f *e\n&g *f\n&h *g\n&i *h\n&j *i\n&k *j\nkey: *k';
assert(p.parse(chain).ok, 'alias chain depth=10 ok');
YamlSecurity.setLimits({ maxAliasDepth: 3 });
assert(!p.parse(chain).ok, 'alias chain depth=10 blocked at limit=3');
YamlSecurity.setLimits();

// ── Anchor with alias ref (scalar) ──
assertEqual(p.parse('&a hello\nb: *a').result, { b: 'hello' }, 'anchor + alias scalar');

// ── Unresolved aliases ──
assert(!p.parse('main: *nope').ok, 'undefined alias blocked');
assert(!p.parse('[*nonexistent]').ok, 'undefined alias in flow blocked');
assert(!p.parse('a: 1\nb: *a').ok, 'alias to non-anchor key blocked');

// ── Cross-document anchors are isolated (js-yaml/eemeli reject them) ──
assert(!p.parseAll('a: &x 1\n---\nb: *x').ok, 'cross-doc anchor blocked (batch)');
{
  const docs = p.parseAll('a: &x 1\n---\nb: &x 2\nc: *x');
  assert(docs.ok, 'doc may redefine its own anchor');
  assertEqual(docs.result, [{ a: 1 }, { b: 2, c: 2 }], 'redefined anchor stays document-local');
}

// ── Anchor on an alias node (invalid per spec; matches js-yaml/eemeli) ──
assert(!p.parse('- &a *a').ok, 'seq anchor-on-alias self-ref blocked');
assert(!p.parse('- &n0 1\n- &n1 *n0').ok, 'seq anchor-on-alias chain blocked');
assert(!p.parse('x: &a *b').ok, 'mapping value anchor-on-alias blocked');

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
assertEqual(p.parse('x: |1\n  hello').result, { x: ' hello\n' }, 'literal block indent |1');
assertEqual(p.parse('x: >1\n  hello\n  world').result, { x: ' hello\n world\n' }, 'folded block indent >1');

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
assert(/circular/i.test(p.dump(circ).error), 'circular dump error message');

// Deep nesting: dump must not blow the stack or throw — it reports { ok:false }.
{
  let deep = {};
  let cursor = deep;
  for (let i = 0; i < 120000; i++) { cursor.k = {}; cursor = cursor.k; }
  const r = p.dump(deep);
  assert(!r.ok, 'deep dump blocked (no throw)');
}
{
  let deep = { a: 1 };
  let cursor = deep;
  for (let i = 0; i < 120000; i++) { const k = {}; cursor.child = k; cursor = k; }
  const r = p.dump(deep);
  assert(!r.ok, 'deep object dump blocked (no throw)');
}
{
  const deepArr = [];
  let cur = deepArr;
  for (let i = 0; i < 120000; i++) { const a = []; cur.push(a); cur = a; }
  assert(!p.dump(deepArr).ok, 'deep array dump blocked (no throw)');
}

// Module-level dump is raw/low-level and may throw — documented behavior.
{
  const muc = { a: 1 }; muc.self = muc;
  try { dump(muc); assert(false, 'module dump throws on circular'); }
  catch (e) { assert(e instanceof YAMLException || /circular/i.test(e.message), 'module dump circular throw'); }
}
{
  let deep = {};
  let cursor = deep;
  for (let i = 0; i < 120000; i++) { cursor.k = {}; cursor = cursor.k; }
  try { dump(deep); assert(false, 'module dump throws on deep'); }
  catch (e) { assert(e instanceof RangeError || /call stack|cannot/.test(e.message), 'module dump deep throws'); }
}

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

// ── Error messages with line/column/snippet ──
const errResult = p.parse('x:\n  y: 1\n  y: 2');
assert(!errResult.ok, 'error on duplicate key');
assert(errResult.error.includes('line 3'), 'error includes line number');

// ── Standalone functions ──
assertEqual(parse('test: 42'), { test: 42 }, 'standalone parse');
const allDocs = parseAll('a: 1\n---\nb: 2');
assertEqual(allDocs, [{ a: 1 }, { b: 2 }], 'standalone parseAll');
const dumpStr = dump({ hello: 'world' });
assert(dumpStr.includes('hello:'), 'standalone dump');

// ── setLimits validation ──
assertThrows(() => YamlSecurity.setLimits({ maxNodes: -1 }), 'setLimits rejects negative');
assertThrows(() => YamlSecurity.setLimits({ maxNodes: 0 }), 'setLimits rejects zero');
assertThrows(() => YamlSecurity.setLimits({ maxNodes: 1.5 }), 'setLimits rejects float');
assertThrows(() => YamlSecurity.setLimits({ maxExpansion: Infinity }), 'setLimits rejects Infinity');
YamlSecurity.setLimits(); // reset

// ── Constructor opts honor every limit key, like setLimits ──
const ctorAlias = new YamlSecurity({ maxAlias: 2 });
assert(ctorAlias.parse('&x 1\na: *x\nb: *x\nc: *x').ok === false, 'constructor maxAlias=2 blocks 3 aliases');
assert(ctorAlias.parse('&x 1\na: *x\nb: *x').ok, 'constructor maxAlias=2 allows 2 aliases');
const ctorMB = new YamlSecurity({ maxInputMB: 0.001 });
assert(ctorMB.parse('x: ' + 'a'.repeat(2000)).ok === false, 'constructor maxInputMB=0.001 blocks large input');
const ctorBytes = new YamlSecurity({ maxInputBytes: 10 });
assert(ctorBytes.parse('key: value_longer_than_10_bytes').ok === false, 'constructor maxInputBytes=10 blocks large input');
const ctorDeep = new YamlSecurity({ maxAliasDepth: 2 });
assert(!ctorDeep.parse('&w hello\n&x *w\n&y *x\n&z *y\nb: *z').ok, 'constructor maxAliasDepth=2');
// Constructor validates limits with the same rules as setLimits
assertThrows(() => new YamlSecurity({ maxNodes: -1 }), 'constructor rejects negative limit');
assertThrows(() => new YamlSecurity({ maxExpansion: Infinity }), 'constructor rejects Infinity limit');
assertThrows(() => new YamlSecurity({ maxKeys: 0.5 }), 'constructor rejects float limit');
assertThrows(() => new YamlSecurity({ maxInputMB: 0 }), 'constructor rejects zero maxInputMB');

// ── Strict preset ──
const deep40 = (() => {
  let d = 'x: 1';
  for (let i = 0; i < 40; i++) d = 'a:\n  ' + d.replace(/\n/g, '\n  ');
  return d;
})();
const bigStr = '"' + 'a'.repeat(2_000_000) + '"';
{
  // Default limits (unlimited string length/keys, depth 50) still hold for
  // non-strict instances with raised input/nodes.
  const loose = new YamlSecurity({ maxInputBytes: 5_000_000, maxNodes: 1_000_000 });
  assert(loose.parse('s: ' + bigStr).ok, 'default allows 2MB string');
  assert(loose.parse(deep40).ok, 'default allows depth-40 mapping');

  // strict: true applies the hardened profile in one line.
  const strict = new YamlSecurity({ strict: true, maxInputBytes: 5_000_000, maxNodes: 1_000_000 });
  assert(!strict.parse('s: ' + bigStr).ok, 'strict maxStringLength=1MB blocks 2MB string');
  assert(strict.parse('s: ' + 'a'.repeat(500_000)).ok, 'strict allows 0.5MB string');
  assert(!new YamlSecurity({ strict: true }).parse(deep40).ok, 'strict maxDepth=30 blocks depth-40 mapping');

  // strict maxKeys=10000 blocks a 12000-key mapping; default allows it.
  const keys = Array.from({ length: 12000 }, (_, i) => 'k' + i + ': 1').join('\n');
  assert(loose.parse(keys).ok, 'default allows 12000-key mapping');
  const strictKeys = new YamlSecurity({ strict: true, maxNodes: 1_000_000, maxInputBytes: 5_000_000 });
  assert(!strictKeys.parse(keys).ok, 'strict maxKeys=10000 blocks 12000-key mapping');

  // strict maxAlias=20 / maxAliasDepth=5.
  const aliases = '&a 1\n' + Array.from({ length: 25 }, (_, i) => 'x' + i + ': *a').join('\n');
  assert(new YamlSecurity({ strict: true, maxNodes: 100_000 }).parse(aliases).ok === false, 'strict maxAlias=20 blocks 25 aliases');
  assert(new YamlSecurity({ maxNodes: 100_000 }).parse(aliases).ok, 'default maxAlias=100 allows 25 aliases');
  const chain7 = '&a hello\n&b *a\n&c *b\n&d *c\n&e *d\n&f *e\n&g *f\nkey: *g';
  assert(new YamlSecurity({ strict: true }).parse(chain7).ok === false, 'strict maxAliasDepth=5 blocks depth-7 chain');
  assert(new YamlSecurity().parse(chain7).ok, 'default maxAliasDepth=10 allows depth-7 chain');

  // strict maxExpansion=10000 blocks a modest expansion bomb; default allows it.
  const bomb = 'a: &x ' + JSON.stringify(Array(200).fill(0)) + '\n'
    + Array.from({ length: 60 }, (_, i) => 'k' + i + ': *x').join('\n');
  assert(new YamlSecurity({ strict: true, maxNodes: 1_000_000, maxAlias: 1000 }).parse(bomb).ok === false, 'strict maxExpansion=10000 blocks expansion bomb');
  assert(new YamlSecurity({ maxNodes: 1_000_000, maxAlias: 1000 }).parse(bomb).ok, 'default maxExpansion=100000 allows expansion bomb');

  // Explicit limits override the strict profile values.
  const relaxed = new YamlSecurity({ strict: true, maxStringLength: 0, maxInputBytes: 5_000_000, maxNodes: 1_000_000 });
  assert(relaxed.parse('s: ' + bigStr).ok, 'strict + maxStringLength:0 override');

  // A strict instance ignores the (possibly loosened) global base.
  YamlSecurity.setLimits({ maxDepth: 1000 });
  assert(!new YamlSecurity({ strict: true }).parse(deep40).ok, 'strict instance ignores loosened global base');
  YamlSecurity.setLimits(); // reset
}

// ── setLimits strict ──
{
  const STRICT_PROFILE = {
    maxNodes: 5000, maxAlias: 20, maxAliasDepth: 5, maxExpansion: 10000,
    maxInputMB: 1, maxInputBytes: 1048576, maxStringLength: 1048576,
    maxKeys: 10000, maxDepth: 30,
  };
  YamlSecurity.setLimits({ strict: true });
  assertEqual(getBaseConfig(), STRICT_PROFILE, 'setLimits({strict:true}) applies STRICT_DEFAULTS');
  assert(!new YamlSecurity().parse(deep40).ok, 'global strict blocks depth-40');
  YamlSecurity.setLimits({ strict: false });
  assertEqual(getBaseConfig(), { ...STRICT_PROFILE, maxStringLength: 0, maxKeys: 0, maxDepth: 50, maxNodes: 10000, maxAlias: 100, maxAliasDepth: 10, maxExpansion: 100000 }, 'setLimits({strict:false}) resets to standard defaults');
  assert(new YamlSecurity().parse(deep40).ok, 'global reset allows depth-40 again');
  YamlSecurity.setLimits({ strict: true, maxDepth: 1000 });
  assert(new YamlSecurity().parse(deep40).ok, 'global strict + maxDepth override');
  assertEqual(getBaseConfig().maxStringLength, 1048576, 'other strict values kept alongside override');
  YamlSecurity.setLimits(); // reset
}
// Unknown constructor keys are ignored
assert(p.parse('a: 1').ok, 'p still usable after constructor tests');

// ── Tab indentation ──
assert(!p.parse('a:\n\tb: 1').ok, 'tab indentation rejected');

// ── Hex / octal / binary integers ──
assertEqual(p.parse('x: 0xFF').result, { x: 255 }, 'hex 0xFF');
assertEqual(p.parse('x: 0o77').result, { x: 63 }, 'octal 0o77');
assertEqual(p.parse('x: 0b1010').result, { x: 10 }, 'binary 0b1010');

// ── Leading zeros are strings (YAML 1.2) ──
assertEqual(p.parse('x: 0123').result, { x: '0123' }, 'leading zero is string');

// ── Dumper: sortKeys ──
const sorted = dump({ b: 2, a: 1 }, { sortKeys: true });
assert(sorted.indexOf('a:') < sorted.indexOf('b:'), 'dump sortKeys');

// ── Dumper: forceQuotes ──
const quoted = dump({ key: 'value' }, { forceQuotes: true });
assert(quoted.includes("'key'") || quoted.includes('"key"'), 'dump forceQuotes');

// ── Schema System ──

// Explicit tags via Schema
assertEqual(p.parse('x: !!str 42').result, { x: '42' }, '!!str via schema');
assertEqual(p.parse('x: !!int 3.14').result, { x: 3 }, '!!int truncates via schema');
assertEqual(p.parse('x: !!null hello').result, { x: null }, '!!null via schema');
assertEqual(p.parse('x: !!bool true').result, { x: true }, '!!bool via schema');
assertEqual(p.parse('x: !!float 3').result, { x: 3 }, '!!float via schema');
assertEqual(p.parse('x: !!binary d29ybGQ=').result, { x: Uint8Array.from([119, 111, 114, 108, 100]) }, '!!binary via schema');

// Implicit resolution via Schema
assertEqual(p.parse('42').result, 42, 'standalone int via schema');
assertEqual(p.parse('true').result, true, 'standalone bool via schema');
assertEqual(p.parse('null').result, null, 'standalone null via schema');
assertEqual(p.parse('hello').result, 'hello', 'standalone string via schema');

// Custom type via standalone parse with { types }
const upperType = new YamlType('!upper', {
  kind: 'scalar',
  construct: (v) => String(v).toUpperCase(),
  resolve: () => false,
});
assertEqual(parse('x: !upper hello', { types: [upperType] }), { x: 'HELLO' }, 'custom type via opts.types');

// Custom type with implicit resolution (custom schema without default int)
// Order matters: add evenType before str so it gets checked first
const evenSchema = new Schema()
  .addType(new YamlType('!even', {
    kind: 'scalar',
    construct: (v) => ({ value: parseInt(v, 10), even: parseInt(v, 10) % 2 === 0 }),
    resolve: (v) => /^\d+$/.test(v) && parseInt(v, 10) % 2 === 0,
  }))
  .addType(new YamlType('tag:yaml.org,2002:str', { kind: 'scalar', construct: (v) => String(v), resolve: () => true }));
assertEqual(parse('4', { schema: evenSchema }), { value: 4, even: true }, 'custom implicit type matches even');
assertEqual(parse('5', { schema: evenSchema }), '5', 'custom implicit type skipped for odd (falls through to str)');

// Custom Schema instance
const customSchema = new Schema()
  .addType(new YamlType('tag:yaml.org,2002:str', {
    kind: 'scalar',
    construct: (v) => String(v),
    resolve: () => true,
  }))
  .addType(new YamlType('!reverse', {
    kind: 'scalar',
    construct: (v) => String(v).split('').reverse().join(''),
    resolve: () => false,
  }));

assertEqual(parse('x: !reverse hello', { schema: customSchema }), { x: 'olleh' }, 'custom schema via opts.schema');

// setSchema on YamlSecurity instance
const sec = new YamlSecurity();
sec.setSchema(customSchema);
assertEqual(sec.parse('x: !reverse world').result, { x: 'dlrow' }, 'setSchema on instance');
assertEqual(sec.parse('hello').result, 'hello', 'setSchema still resolves strings via str type');

// Schema tagFor
const s = new Schema().addType(new YamlType('!custom', { kind: 'scalar', construct: (v) => v, resolve: () => false }));
assertEqual(s.tagFor(42), 'tag:yaml.org,2002:int', 'tagFor int');
assertEqual(s.tagFor('hello'), 'tag:yaml.org,2002:str', 'tagFor string');
assertEqual(s.tagFor(true), 'tag:yaml.org,2002:bool', 'tagFor bool');
assertEqual(s.tagFor(null), 'tag:yaml.org,2002:null', 'tagFor null');

// Schema addType returns this for chaining
const dummyType = new YamlType('!dummy', { kind: 'scalar', construct: (v) => v, resolve: () => false });
const chained = new Schema().addType(upperType).addType(dummyType);
assert(chained instanceof Schema, 'chained addType returns Schema');

// %TAG directive + Schema integration
const tagSchema = new Schema()
  .addType(new YamlType('tag:yaml.org,2002:str', { kind: 'scalar', construct: (v) => String(v), resolve: () => true }))
  .addType(new YamlType('tag:example.com,2000:app:upper', {
    kind: 'scalar',
    construct: (v) => String(v).toUpperCase(),
    resolve: () => false,
  }));
const tagResult = parse('%TAG !e! tag:example.com,2000:app:\n---\nx: !e!upper hello', { schema: tagSchema });
assertEqual(tagResult, { x: 'HELLO' }, '%TAG directive + custom schema via expandTag');

// maxInputBytes / maxInputMB limit
YamlSecurity.setLimits({ maxInputBytes: 10 });
const smallLimit = new YamlSecurity();
assert(!smallLimit.parse('key: value_longer_than_10_bytes').ok, 'maxInputBytes=10 blocks large input');
YamlSecurity.setLimits({ maxInputMB: 0.001 });
const tinyMB = new YamlSecurity();
assert(!tinyMB.parse('x: ' + 'a'.repeat(2000)).ok, 'maxInputMB=0.001 blocks large input');
YamlSecurity.setLimits(); // reset

// ── Schema.removeType / hasType ──
const rtSchema = new Schema()
  .addType(new YamlType('!a', { kind: 'scalar', construct: (v) => v, resolve: () => false }))
  .addType(new YamlType('!b', { kind: 'scalar', construct: (v) => v, resolve: () => false }));
assert(rtSchema.hasType('!a'), 'hasType true before remove');
assert(rtSchema.removeType('!a'), 'removeType returns true');
assert(!rtSchema.hasType('!a'), 'hasType false after remove');
assert(!rtSchema.removeType('!nonexistent'), 'removeType returns false for missing');
assert(rtSchema.hasType('!b'), 'other types preserved after remove');

// ── .inf / .nan float resolution ──
assertEqual(p.parse('x: .inf').result, { x: Infinity }, '.inf resolves to Infinity');
assertEqual(p.parse('x: .Inf').result, { x: Infinity }, '.Inf resolves to Infinity');
assertEqual(p.parse('x: -.inf').result, { x: -Infinity }, '-.inf resolves to -Infinity');
const nanResult = p.parse('x: .nan').result;
assert(typeof nanResult.x === 'number' && isNaN(nanResult.x), '.nan resolves to NaN');
const nanResult2 = p.parse('x: .NaN').result;
assert(typeof nanResult2.x === 'number' && isNaN(nanResult2.x), '.NaN resolves to NaN');

// ── parseAll per-call opts on instance ──
const customParseAllSchema = new Schema()
  .addType(new YamlType('tag:yaml.org,2002:str', { kind: 'scalar', construct: (v) => String(v), resolve: () => true }))
  .addType(new YamlType('!upper', { kind: 'scalar', construct: (v) => v.toUpperCase(), resolve: () => false }));
const paInstance = new YamlSecurity();
const paResult = paInstance.parseAll('x: !upper hello\n---\ny: world', { schema: customParseAllSchema });
assertEqual(paResult.result, [{ x: 'HELLO' }, { y: 'world' }], 'parseAll per-call schema');

// ── Block scalar with ! tag ──
assertEqual(p.parse('x: !upper |\n  hello\n  world').result, { x: 'hello\nworld\n' }, 'block scalar with ! tag');
assertEqual(p.parse('x: !!str |\n  hello').result, { x: 'hello\n' }, 'block scalar with !! tag');

// ── Sequence items with tags ──
assertEqual(p.parse('- !!str 42\n- !!int 3.14').result, ['42', 3], 'sequence items with !! tags');
assertEqual(p.parse('[!!str 42, !!int 3.14]').result, ['42', 3], 'inline seq items with !! tags');

// ── setSchema reset with no args ──
const resetSchema = new YamlSecurity();
resetSchema.setSchema(new Schema().addType(new YamlType('!custom', { kind: 'scalar', construct: (v) => v, resolve: () => true })));
// After reset, default types still work (int, bool, null, etc.)
resetSchema.setSchema(); // reset to defaults
assertEqual(resetSchema.parse('x: 42').result, { x: 42 }, 'default int resolution after schema reset');
assertEqual(resetSchema.parse('y: true').result, { y: true }, 'default bool after schema reset');
assertEqual(resetSchema.parse('z: null').result, { z: null }, 'default null after schema reset');

// ── produced counter is global across recursive yamlToJS calls ──
YamlSecurity.setLimits({ maxNodes: 14 });
const globalCount = new YamlSecurity();
// Without fix: each yamlToJS call has its own maxNodes budget
// With fix: sub-mapping nodes count toward global limit (total > 14 → fail)
assert(!globalCount.parse('a: 1\nb: 2\nc: 3\nd: 4\nsub:\n  x: 5\n  y: 6').ok,
  'produced counter shared globally across recursive yamlToJS calls');
YamlSecurity.setLimits();

// ── Circular alias detection ──
assert(!p.parse('&a *a\nb: 1').ok, 'circular alias self-reference &a *a blocked');
assert(!p.parse('&a *b\n&b *a\nc: 1').ok, 'circular alias indirect cycle &a->&b->&a blocked');
// Non-circular aliases still work
assertEqual(p.parse('&a hello\nb: *a').result, { b: 'hello' }, 'non-circular alias still works');

// ── maxStringLength ──
YamlSecurity.setLimits({ maxStringLength: 10 });
const strLimit = new YamlSecurity();
assert(!strLimit.parse('x: "aaaaaaaaaaa"').ok, 'maxStringLength=10 blocks 11-char string');
assert(strLimit.parse('x: "aaaaaaaaaa"').ok, 'maxStringLength=10 allows 10-char string');
YamlSecurity.setLimits();

// ── maxKeys ──
YamlSecurity.setLimits({ maxKeys: 3 });
const keyLimit = new YamlSecurity();
assert(!keyLimit.parse('a: 1\nb: 2\nc: 3\nd: 4').ok, 'maxKeys=3 blocks 4-key mapping');
assert(keyLimit.parse('a: 1\nb: 2\nc: 3').ok, 'maxKeys=3 allows 3-key mapping');
// Inline flow
assert(!keyLimit.parse('{a: 1, b: 2, c: 3, d: 4}').ok, 'maxKeys=3 blocks 4-key inline mapping');
YamlSecurity.setLimits();

// ── maxDepth ──
const d3 = new YamlSecurity({ maxDepth: 3 });
assert(d3.parse('a:\n  b:\n    c:\n      d: 1').ok, 'maxDepth=3 allows 3 nested maps (a.b.c.d)');
assert(!d3.parse('a:\n  b:\n    c:\n      d:\n        e: 1').ok, 'maxDepth=3 blocks 4 nested maps (a.b.c.d.e)');
const d2 = new YamlSecurity({ maxDepth: 2 });
assert(!d2.parse('a:\n  b:\n    c:\n      d: 1').ok, 'maxDepth=2 blocks 3 nested maps');
assert(!d2.parse('a:\n  - b:\n      c: 1').ok, 'maxDepth=2 counts seq items (map>seq>map depth 3)');
assert(!d2.parse('- b:\n    c:\n      d: 1').ok, 'maxDepth=2 counts nested seq item maps (depth 3)');
const dOff = new YamlSecurity({ maxDepth: 0 });
assert(dOff.parse('a:\n  b:\n    c:\n      d:\n        e: 1').ok, 'maxDepth=0 disables the depth guard');
const d1 = new YamlSecurity({ maxDepth: 1 });
assert(d1.parse('- a\n- b').ok, 'maxDepth=1 allows a root sequence of scalars');
assert(!d1.parse('- a\n- b:\n    c: 1').ok, 'maxDepth=1 blocks a nested seq item map');
// Sequence items do not reset the depth counter (batch/stream parity)
assert(!new YamlSecurity({ maxDepth: 2 }).parse('a:\n  - b:\n      c: 1').ok,
  'seq items keep the block depth counter (no reset across yamlToJS)');

// ── Timestamps (YAML 1.2: implicit = string, explicit !!timestamp = Date) ──
assertEqual(p.parse('x: 2001-01-23').result, { x: '2001-01-23' }, 'implicit date stays string (YAML 1.2 core)');
assertEqual(p.parse('x: 2001-01-23T10:30:00Z').result, { x: '2001-01-23T10:30:00Z' }, 'implicit datetime stays string');
const tsResult = p.parse('x: !!timestamp 2001-01-23').result;
assert(tsResult.x instanceof Date && tsResult.x.toISOString() === '2001-01-23T00:00:00.000Z', 'explicit !!timestamp resolves to Date');
// Date inside a mapping must survive (regression: resolveMerges turned it into {})
const nestedDate = p.parse('a:\n  b: 2001-01-23').result;
assert(nestedDate.a.b instanceof Date === false && nestedDate.a.b === '2001-01-23', 'nested implicit date stays string');

// ── DoS regression: multiline flow gathering must be linear ──
// (was O(n²): re-scanning the whole accumulated flow string per line hung
//  the batch parser on a few thousand lines. Now gathers incrementally.)
{
  const perf = new YamlSecurity({ maxNodes: 1000000000, maxInputBytes: 1000000000, maxExpansion: 1000000000 });
  const flow = 'a: [\n' + '  x,\n'.repeat(20000) + '  ]';
  const t0 = Date.now();
  const r = perf.parse(flow);
  const ms = Date.now() - t0;
  assert(r.ok, 'large multiline flow (20000 lines) parses');
  assert(r.result.a.length === 20000, 'multiline flow keeps all items');
  assert(ms < 3000, 'multiline flow parses in linear time (was O(n²) hang) — ' + ms + 'ms');
}
// malformed multiline flow (never closes) must error fast, not hang
{
  const bad = 'a: [\n' + '  x,\n'.repeat(20000) + '  1, 2';
  const t0 = Date.now();
  const r = p.parse(bad);
  const ms = Date.now() - t0;
  assert(!r.ok, 'unterminated multiline flow errors');
  assert(ms < 3000, 'unterminated multiline flow errors in linear time — ' + ms + 'ms');
}
// ── DoS regression: single-line flow seq item slicing must be linear ──
{
  const perf = new YamlSecurity({ maxNodes: 1000000000, maxInputBytes: 1000000000, maxExpansion: 1000000000 });
  const s = '[' + Array(50000).fill('1').join(',') + ']';
  const t0 = Date.now();
  const r = perf.parse(s);
  const ms = Date.now() - t0;
  assert(r.ok, 'large flow seq (50000 items) parses');
  assert(r.result.length === 50000, 'flow seq keeps all items');
  assert(ms < 3000, 'flow seq parses in linear time (was O(n²) remainder slicing) — ' + ms + 'ms');
}
// ── Regression: anchored sub-blocks are not triple-charged against maxNodes ──
// (1000 `key: &a` anchors each with a nested mapping = ~3 real nodes each;
//  previously each anchored value was tracked 3×, tripping a false
//  "possible bomb" at the default maxNodes=10000.)
{
  let s = '';
  for (let i = 0; i < 1000; i++) s += 'a' + i + ': &a' + i + '\n  k: v\n';
  s += 'use: *a999\n';
  const r = p.parse(s);
  assert(r.ok, '1000 anchored sub-blocks parse without a false "possible bomb"');
  assert(Object.keys(r.result).length === 1001, 'anchored doc keeps all keys');
}

// ── Summary ──
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
