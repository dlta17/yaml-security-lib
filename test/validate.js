import {
  YamlSecurity, s, validate, validateYaml,
  createStream, createStreamValidator, parseStream,
  fromJSONSchema, toJSONSchema,
} from '../src/index.js';

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) { passed++; }
  else { failed++; console.error('FAIL:', msg); }
}

function errorsOf(r) { return r.errors.map((e) => e.path + ': ' + e.message); }

// ── Pure validate() ────────────────────────────────────────

{
  const user = s.object({
    name: s.string({ min: 1 }),
    age: s.int({ min: 0 }),
    tags: s.array(s.string()),
    role: s.optional(s.enum(['admin', 'user'])),
  });

  assert(validate({ name: 'ned', age: 30, tags: ['a'] }, user).ok, 'valid user ok');
  assert(!validate({ name: 'ned' }, user).ok, 'missing age+tags');
  assert(errorsOf(validate({ name: 'ned' }, user)).includes('$.age: missing required property "age"'), 'age required error path');
  assert(errorsOf(validate({ name: 'ned' }, user)).includes('$.tags: missing required property "tags"'), 'tags required error path');

  const bad = validate({ name: 1, age: -1, tags: ['a', 2], x: 1 }, user);
  assert(!bad.ok, 'bad user not ok');
  assert(errorsOf(bad).includes('$.name: expected string'), 'name type error');
  assert(errorsOf(bad).includes('$.age: must be >= 0'), 'age range error');
  assert(errorsOf(bad).includes('$.tags[1]: expected string'), 'array item path');
  assert(errorsOf(bad).includes('$.x: unexpected property "x"'), 'extra prop rejected');

  assert(validate({ name: 'a', age: 1, tags: [] }, user).ok, 'role absent ok');
  // optional+enum is still enforced when present
  const withRole = validate({ name: 'a', age: 1, role: 'root' }, user);
  assert(!withRole.ok, 'role present but wrong enum');
  assert(errorsOf(withRole).some((m) => m.includes('$.role')), 'present optional role validated');
}

// null / nullable / boolean / number
{
  assert(validate(null, s.null()).ok, 'null ok');
  assert(!validate(1, s.null()).ok, '1 not null');
  assert(validate(null, s.nullable(s.string())).ok, 'nullable null ok');
  assert(validate('x', s.nullable(s.string())).ok, 'nullable value ok');
  assert(!validate(5, s.nullable(s.string())).ok, 'nullable wrong type');
  assert(validate(true, s.bool()).ok, 'bool ok');
  assert(validate(2.5, s.number()).ok, 'number ok');
  assert(!validate(2, s.float({ multipleOf: 3 })).ok, 'multipleOf fails');
  assert(validate(9, s.float({ multipleOf: 3 })).ok, 'multipleOf passes');
  assert(validate(5, s.int({ exclusiveMin: 0, exclusiveMax: 10 })).ok, 'exclusive range ok');
  assert(!validate(0, s.int({ exclusiveMin: 0 })).ok, 'exclusiveMin fails');
}

// string patterns + ranges
{
  assert(!validate('ab', s.string({ min: 3 })).ok, 'minLength');
  assert(!validate('abcd', s.string({ max: 3 })).ok, 'maxLength');
  assert(validate('abc', s.string({ min: 2, max: 3 })).ok, 'length ok');
  assert(validate('abc-123', s.string({ pattern: '^[a-z]+-\\d+$' })).ok, 'pattern ok');
  assert(!validate('ABC', s.string({ pattern: '^[a-z]+$' })).ok, 'pattern fail');
}

// enum (deep) + const via enum
{
  assert(validate('a', s.enum(['a', 'b'])).ok, 'enum ok');
  assert(!validate('c', s.enum(['a', 'b'])).ok, 'enum fail');
  assert(validate({ a: [1] }, s.enum([{ a: [1] }, { b: 2 }])).ok, 'deep enum ok');
  assert(!validate({ a: [2] }, s.enum([{ a: [1] }])).ok, 'deep enum fail');
}

// timestamp
{
  assert(validate(new Date(), s.timestamp()).ok, 'Date ok');
  assert(validate('2024-01-01', s.timestamp()).ok, 'ISO date string ok');
  assert(validate('2024-01-01T10:00:00Z', s.timestamp()).ok, 'ISO datetime string ok');
  assert(!validate('not-a-date', s.timestamp()).ok, 'bad date fails');
}

// array / tuple
{
  assert(validate([1, 2, 3], s.array(s.int(), { minItems: 2, maxItems: 4 })).ok, 'array ok');
  assert(!validate([1], s.array(s.int(), { minItems: 2 })).ok, 'minItems');
  assert(!validate([1, 2, 3, 4, 5], s.array(s.int(), { maxItems: 4 })).ok, 'maxItems');
  assert(!validate([1, 'x'], s.array(s.int())).ok, 'item type');
  assert(validate([1, 'a'], s.tuple([s.int(), s.string()])).ok, 'tuple ok');
  assert(!validate([1], s.tuple([s.int(), s.string()])).ok, 'tuple length');
  assert(!validate([1, 2, 2], s.array(s.int(), { uniqueItems: true })).ok, 'uniqueItems fail');
  assert(validate([1, 2, 3], s.array(s.int(), { uniqueItems: true })).ok, 'uniqueItems ok');
}

// record / patternProperties
{
  const ports = s.record(s.int());
  assert(validate({ http: 80, https: 443 }, ports).ok, 'record ok');
  assert(!validate({ http: '80' }, ports).ok, 'record value type');
  assert(validate({ a1: 'x', a2: 'y' }, s.object({}, { patternProperties: { '^a': s.string() } })).ok, 'patternProperties ok');
  assert(!validate({ a1: 5 }, s.object({}, { patternProperties: { '^a': s.string() } })).ok, 'patternProperties fail');
}

// combinators
{
  assert(validate('x', s.oneOf([s.string(), s.int()])).ok, 'oneOf match');
  assert(!validate(true, s.oneOf([s.string(), s.int()])).ok, 'oneOf no match');
  assert(validate('x', s.anyOf([s.int(), s.string()])).ok, 'anyOf match');
  assert(!validate(true, s.anyOf([s.int(), s.string()])).ok, 'anyOf no match');
  assert(validate(5, s.allOf([s.int(), s.float({ min: 0 })])).ok, 'allOf match');
  assert(!validate(-1, s.allOf([s.int(), s.float({ min: 0 })])).ok, 'allOf fail');
  assert(validate(5, s.not(s.string())).ok, 'not pass');
  assert(!validate('x', s.not(s.string())).ok, 'not fail');
  const hasLen = s.custom((v) => typeof v === 'string' && v.length >= 3);
  assert(validate('hello', hasLen).ok, 'custom pass');
  assert(!validate('hi', hasLen).ok, 'custom fail');
  assert(errorsOf(validate('hi', hasLen)).some((m) => m.startsWith('$')), 'custom at root path');
}

// ── validateYaml ───────────────────────────────────────────

{
  const spec = s.object({ name: s.string(), age: s.int() });
  const ok = validateYaml('name: ned\nage: 30\n', spec);
  assert(ok.ok && ok.value.name === 'ned' && ok.value.age === 30, 'validateYaml ok');
  const bad = validateYaml('name: ned\nage: old\n', spec);
  assert(!bad.ok, 'validateYaml bad');
  assert(errorsOf(bad).includes('$.age: expected integer'), 'validateYaml age error');
  const throwCase = validateYaml('a: 1\nb: [\n', spec);
  assert(!throwCase.ok && throwCase.errors[0].path === '$', 'validateYaml parse error captured');
  // instance method
  const y = new YamlSecurity();
  assert(y.validateYaml('name: x\nage: 1\n', spec).ok, 'instance validateYaml');
  assert(y.validate({ name: 'x' }, spec).ok === false, 'instance validate');
}

// ── Incremental stream validator ───────────────────────────

function collectViolations(input, opts) {
  const sp = createStream(Object.assign({}, opts));
  const vs = [];
  sp.on('violation', (v) => vs.push(v.path + ': ' + v.message));
  try { sp.write(input); sp.end(); } catch (e) { /* abort path */ }
  return { vs, error: sp.error };
}

{
  const spec = s.object({ name: s.string(), age: s.int({ min: 0 }) });

  const good = collectViolations('name: a\nage: 5\n', { validate: spec });
  assert(good.vs.length === 0, 'stream good doc no violations');

  const bad = collectViolations('name: a\nage: -5\n', { validate: spec });
  assert(bad.vs.some((m) => m === '$.age: must be >= 0'), 'stream incremental age violation');

  const extra = collectViolations('name: a\nage: 5\nother: 1\n', { validate: spec });
  assert(extra.vs.some((m) => m === '$.other: unexpected property "other"'), 'stream extra prop violation');

  // disable-anchor mode (zero buffering) still validates incrementally
  const d = collectViolations('name: a\nage: -5\n', { validate: spec, anchors: 'disable' });
  assert(d.vs.some((m) => m === '$.age: must be >= 0'), 'disable mode incremental violation');
  assert(d.vs.filter((m) => m.startsWith('$.age')).length === 1, 'disable mode no duplicate age violations');

  // nested arrays/objects in the stream
  const nested = s.object({ list: s.array(s.object({ id: s.int() })) });
  const n1 = collectViolations('list:\n  - id: 1\n  - id: x\n', { validate: nested });
  assert(n1.vs.some((m) => m === '$.list[1].id: expected integer'), 'nested stream path');

  // required across a completed collection
  const n2 = collectViolations('list:\n  - id: 1\n', { validate: nested });
  assert(n2.vs.length === 0, 'nested doc valid');

  // abortOnError throws and emits an error event
  const sp = createStream({ validate: spec, abortOnError: true });
  let errEv = null;
  sp.on('error', (e) => { errEv = e.error; });
  try { sp.write('name: a\nage: -5\n'); } catch (e) {}
  try { sp.end(); } catch (e) {}
  assert(errEv !== null && /validation failed/.test(errEv.message), 'abortOnError emits error event');

  // full-doc authoritative validation via buffered root (combinators)
  const combo = collectViolations('x: 1\n', { validate: s.object({ x: s.oneOf([s.string(), s.bool()]) }) });
  assert(combo.vs.some((m) => m === '$.x: expected exactly one alternative to match (0 matched)'), 'stream oneOf authoritative at doc end');
}

// createStreamValidator direct (SAX state machine)
{
  const v = createStreamValidator(s.array(s.int()));
  v.documentStart();
  v.sequenceStart();
  v.scalar(1);
  v.scalar('x');
  v.sequenceEnd();
  const fresh = v.documentEnd(undefined);
  assert(fresh.some((e) => e.path === '$[1]' && e.message === 'expected integer'), 'direct SAX validator item error');
}

// ── parseStream with validation ────────────────────────────

{
  const spec = s.object({ name: s.string() });
  const docs = [];
  for await (const d of parseStream('---\nname: a\n---\nname: b\n', { validate: spec })) docs.push(d);
  assert(docs.length === 2, 'parseStream yields 2 docs');
  assert(docs.every((d) => d.ok === undefined) && docs[0].value.name === 'a', 'parseStream wrapped shape');

  const bad = [];
  for await (const d of parseStream('name: b\n', { validate: s.object({ name: s.int() }) })) bad.push(d);
  assert(bad[0].errors.length === 1 && bad[0].errors[0].path === '$.name', 'parseStream errors attached');

  const aborted = [];
  let thrown = null;
  try {
    for await (const d of parseStream('name: b\n', { validate: s.object({ name: s.int() }), abortOnError: true })) aborted.push(d);
  } catch (e) { thrown = e; }
  assert(thrown !== null && /validation failed/.test(thrown.message), 'parseStream abortOnError throws');
}

// ── JSON Schema bridge ─────────────────────────────────────

{
  const js = {
    type: 'object',
    properties: {
      n: { type: 'integer', minimum: 1 },
      ok: { type: 'boolean' },
      tags: { type: 'array', items: { type: 'string' }, minItems: 1 },
    },
    required: ['n'],
    additionalProperties: false,
  };
  const spec = fromJSONSchema(js);
  assert(validateYaml('n: 3\nok: true\n', spec).ok, 'json schema good');
  assert(!validateYaml('n: 0\nok: 1\nextra: 1\n', spec).ok, 'json schema bad');
  const jsErrors = validateYaml('n: 0\nok: 1\nextra: 1\n', spec).errors;
  assert(jsErrors.some((e) => e.path === '$.n' && e.message === 'must be >= 1'), 'json schema minimum');
  assert(jsErrors.some((e) => e.path === '$.ok' && e.message === 'expected boolean'), 'json schema boolean');
  assert(jsErrors.some((e) => e.path === '$.extra' && e.message === 'unexpected property "extra"'), 'json schema additionalProperties');

  // nullable via type array
  const n = fromJSONSchema({ type: ['string', 'null'] });
  assert(validate(null, n).ok && validate('x', n).ok && !validate(1, n).ok, 'json schema nullable type array');

  // $ref to local defs
  const ref = fromJSONSchema({
    $defs: { pos: { type: 'object', properties: { x: { type: 'number' }, y: { type: 'number' } }, required: ['x', 'y'] } },
    type: 'object',
    properties: { p: { $ref: '#/$defs/pos' } },
    required: ['p'],
  });
  assert(validateYaml('p:\n  x: 1\n  y: 2\n', ref).ok, 'json schema $ref good');
  assert(!validateYaml('p:\n  x: 1\n', ref).ok, 'json schema $ref required');

  // const + enum
  assert(validate('off', fromJSONSchema({ const: 'off' })).ok, 'const ok');
  assert(!validate('on', fromJSONSchema({ const: 'off' })).ok, 'const fail');
  assert(!validate('z', fromJSONSchema({ enum: ['a', 'b'] })).ok, 'js enum fail');

  // toJSONSchema round trip
  const out = toJSONSchema(s.object({ a: s.int({ min: 1 }), b: s.array(s.string(), { minItems: 1 }) }));
  assert(out.type === 'object' && out.properties.a.type === 'integer' && out.properties.a.minimum === 1, 'toJSONSchema object');
  assert(out.properties.b.items.type === 'string' && out.properties.b.minItems === 1, 'toJSONSchema array');
  assert(out.required.includes('a') && out.required.includes('b'), 'toJSONSchema required');
  assert(out.additionalProperties === false, 'toJSONSchema strict by default');

  const nullableRound = toJSONSchema(s.nullable(s.string()));
  assert(Array.isArray(nullableRound.type) && nullableRound.type.includes('null'), 'toJSONSchema nullable');
}

console.log('Validation suite: ' + passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
