import { YamlSecurity, parse, parseAll, dump, YAMLException, YamlType, Schema } from '../src/index.js';

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

// ── Timestamps (YAML 1.2: implicit = string, explicit !!timestamp = Date) ──
assertEqual(p.parse('x: 2001-01-23').result, { x: '2001-01-23' }, 'implicit date stays string (YAML 1.2 core)');
assertEqual(p.parse('x: 2001-01-23T10:30:00Z').result, { x: '2001-01-23T10:30:00Z' }, 'implicit datetime stays string');
const tsResult = p.parse('x: !!timestamp 2001-01-23').result;
assert(tsResult.x instanceof Date && tsResult.x.toISOString() === '2001-01-23T00:00:00.000Z', 'explicit !!timestamp resolves to Date');
// Date inside a mapping must survive (regression: resolveMerges turned it into {})
const nestedDate = p.parse('a:\n  b: 2001-01-23').result;
assert(nestedDate.a.b instanceof Date === false && nestedDate.a.b === '2001-01-23', 'nested implicit date stays string');

// ── Summary ──
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
