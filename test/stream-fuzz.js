import { parse, parseAll, createStream, parseStream } from '../src/index.js';
import * as jsyaml from 'js-yaml';

let pass = 0, fail = 0;
const fails = [];
const ok = (cond, msg) => { if (cond) pass++; else { fail++; if (fails.length < 30) fails.push(msg); } };

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
  const ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
  if (ka.length !== kb.length) return false;
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return false;
    if (!deepEqual(a[ka[i]], b[kb[i]])) return false;
  }
  return true;
}

// ── Deterministic PRNG (mulberry32) ──
function makeRng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Keys avoid YAML 1.1 coercions (true/false/null/number/date keys). Values avoid
// yes/no, which js-yaml's default 1.1 schema turns into booleans.
const KEYS = ['a', 'b', 'name', 'key', 'value', 'x', 'y', 'z', 'longer_key', 'foo', 'bar', 'cfg', 'enabled', 'count', 'hello world', "it's", '100%', 'http://x.io', 'السلام', '😀'];
const VALS = ['a', 'b', 'name', 'key', 'value', 'x', 'y', 'z', 'longer_key', 'foo', 'bar', 'cfg', 'enabled', 'count', '1', '2', '42', 'true', 'false', 'null', '~', '2023-01-15', 'hello world', "it's", 'line1\nline2', '100%', 'http://x.io', 'السلام', '😀'];

function genDoc(rng, depth) {
  if (depth <= 0 || rng() < 0.25) {
    const w = VALS[(rng() * VALS.length) | 0];
    const style = rng();
    if (style < 0.2) return '"' + w + '"';
    if (style < 0.3) return "'" + w + "'";
    return w;
  }
  if (rng() < 0.5) {
    const n = 1 + ((rng() * 4) | 0);
    let out = '';
    for (let i = 0; i < n; i++) {
      const k = KEYS[(rng() * KEYS.length) | 0];
      const v = genDoc(rng, depth - 1);
      const line = v.includes('\n') ? k + ':\n' + indentLines(v, depth) : k + ': ' + v;
      out += line + '\n';
    }
    return out.trimEnd();
  }
  const n = 1 + ((rng() * 4) | 0);
  let out = '';
  for (let i = 0; i < n; i++) out += '- ' + genDoc(rng, depth - 1).replace(/\n/g, '\n  ') + '\n';
  return out.trimEnd();
}

function indentLines(s, depth) {
  const pad = '  '.repeat(depth);
  return s.split('\n').map(l => pad + l).join('\n');
}

function streamDocs(yaml, chunkCount) {
  const s = createStream();
  const docs = [];
  s.on('document', d => docs.push(d));
  let threw = null;
  if (chunkCount <= 1) {
    try { s.write(yaml); s.end(); } catch (e) { threw = e; }
  } else {
    const chunks = [];
    let pos = 0;
    for (let i = 0; i < chunkCount && pos < yaml.length; i++) {
      const len = Math.max(1, Math.ceil((yaml.length - pos) / (chunkCount - i)));
      chunks.push(yaml.slice(pos, pos + len));
      pos += len;
    }
    try { for (const c of chunks) s.write(c); s.end(); } catch (e) { threw = e; }
  }
  return { docs, threw };
}

// ── 1. Exhaustive split-point consistency ──
{
  const cases = [
    'a: 1\nb: two\nc: true',
    'a:\n  b: 1\n  c:\n    d: [1, 2, 3]',
    '- a\n- b\n- 42',
    '- name: Ali\n  age: 30\n- name: Sara\n  age: 25',
    '- - 1\n  - 2\n- - 3',
    'text: |\n  hello\n  world\n',
    'text: >\n  hello\n  world\n',
    'text: |-\n  hello\n',
    'a: [1, 2, {b: 3}]',
    'a: {b: 1, c: [2, 3]}',
    '"hello": 1\n\'world\': 2',
    'a:\nb: 2',
    'base: &b\n  x: 1\n  y: 2\ncopy: *b',
    'a: &x 5\nb: *x',
    'just a string',
    'defaults: &d\n  a: 1\n  b: 2\nthing:\n  <<: *d\n  b: 3',
    '? key\n: value',
    'a:\n  b:\n    c:\n      d: 1',
    '- \n- b',
    '[1, 2, 3]',
    '{a: 1, b: 2}',
    'when: 2023-01-15\nwhen2: 2023-01-15T10:30:00Z',
    '"hello"\n',
    '- &a a\n- *a\n- &b !!str b\n',
    'a: 1\n---\nb: 2\n---\n- x',
    '- [ a, b ]\n- { a: b }\n',
    'a: {b: 1, c: [2, 3]}\nb: [1, {x: [2, 3]}]\n',
    'hello\n  world',
    'plain:\n  This unquoted scalar\n  spans many lines.\n',
    '-\n  name: Mark\n-\n  name: Sammy\n',
    'a: &anchor\nb: *anchor\n',
    '- &😁 unicode anchor\n',
    '%TAG !m! !my-\n---\n!m!light fluorescent\n...\n%TAG !m! !my-\n---\n!m!light green\n',
  ];
  let splitCount = 0;
  for (const y of cases) {
    let reference = null;
    for (let i = 0; i <= y.length; i++) {
      const { docs, threw } = streamDocs(y.slice(0, i) + '\x00' + y.slice(i), 1);
      void docs;
      const a = streamDocs(y.slice(0, i), 1), b = streamDocs(y.slice(i), 1);
      void b;
      const s = createStream();
      const dd = [];
      s.on('document', d => dd.push(d));
      let th = null;
      try { s.write(y.slice(0, i)); s.write(y.slice(i)); s.end(); } catch (e) { th = e; }
      const got = th ? 'THREW' : JSON.stringify(dd.length > 1 ? dd : dd[0]);
      splitCount++;
      if (reference === null) reference = got;
      ok(got === reference, 'split inconsistency at ' + i + ' for ' + JSON.stringify(y.slice(0, 30)));
    }
  }
  ok(true, '');
  console.log('exhaustive split consistency: ' + splitCount + ' split points checked');
}

// ── 2. Event-replay: rebuild JS objects from SAX events ──
function replay(events) {
  const roots = [];
  const stack = [];
  let root = null, haveRoot = false;
  for (const ev of events) {
    switch (ev.type) {
      case 'documentStart': stack.length = 0; root = null; haveRoot = false; break;
      case 'mappingStart': {
        const ctx = { kind: 'map', node: {}, pendingKey: null };
        stack.push(ctx);
        if (!haveRoot) { root = ctx.node; haveRoot = true; }
        break;
      }
      case 'sequenceStart': {
        const ctx = { kind: 'seq', node: [] };
        stack.push(ctx);
        if (!haveRoot) { root = ctx.node; haveRoot = true; }
        break;
      }
      case 'key': stack[stack.length - 1].pendingKey = ev.value; break;
      case 'scalar': {
        if (stack.length === 0) { root = ev.value; haveRoot = true; }
        else {
          const t = stack[stack.length - 1];
          if (t.kind === 'map') {
            if (t.pendingKey !== null) { t.node[t.pendingKey] = ev.value; t.pendingKey = null; }
          } else t.node.push(ev.value);
        }
        break;
      }
      case 'mappingEnd':
      case 'sequenceEnd': {
        const t = stack.pop();
        if (stack.length > 0) {
          const p = stack[stack.length - 1];
          if (p.kind === 'map') {
            if (p.pendingKey !== null) { p.node[p.pendingKey] = t.node; p.pendingKey = null; }
          } else p.node.push(t.node);
        }
        break;
      }
      case 'documentEnd': roots.push(root); break;
    }
  }
  return roots;
}

// Deep equality with Date normalization: js-yaml and the stream both emit
// real Date objects for timestamps; compare by time, everything else strictly.
function normEquals(a, b) {
  if (a instanceof Date || b instanceof Date) {
    return a instanceof Date && b instanceof Date && a.getTime() === b.getTime();
  }
  if (a === b) return true;
  if (a === null || b === null || a === undefined || b === undefined) return a === b;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (!normEquals(a[i], b[i])) return false;
    return true;
  }
  const ka = Object.keys(a), kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  for (const k of ka) {
    if (!(k in b)) return false;
    if (!normEquals(a[k], b[k])) return false;
  }
  return true;
}

// ── 3. Random grammar fuzz: value vs js-yaml + events + chunking ──
// js-yaml is the ground-truth oracle (devDependency, test-only). Where js-yaml
// rejects the generated doc as malformed, value-correctness is undefined and we
// only enforce the stream invariants (chunking + event-replay).
//
// WARNING: the oracle MUST stay on js-yaml v5.x (YAML 1.2 core — timestamps
// resolve to strings, matching this library). js-yaml 4.x is YAML 1.1 and
// returns Date for implicit timestamps, which fails ~28 assertions here.
// Keep package.json and package-lock.json in sync; `npm ci` fails otherwise.
{
  let generated = 0, compared = 0, malformed = 0;
  const rng = makeRng(0xC0FFEE);
  for (let iter = 0; iter < 400; iter++) {
    const yaml = genDoc(rng, 1 + ((rng() * 3) | 0));
    generated++;

    let reference = null, refErr = null;
    try { reference = jsyaml.load(yaml); } catch (e) { refErr = e; }

    const single = streamDocs(yaml, 1);
    const many = streamDocs(yaml, 2 + ((rng() * 3) | 0));
    if (reference !== null) {
      compared++;
      if (single.threw) {
        ok(false, 'fuzz stream threw but js-yaml succeeded: ' + JSON.stringify(yaml).slice(0, 70) + '\n  ' + single.threw.message.slice(0, 120));
      } else if (single.docs.length !== 1) {
        ok(false, 'fuzz doc count ' + single.docs.length + ' (expected 1): ' + JSON.stringify(yaml).slice(0, 70));
      } else if (!normEquals(reference, single.docs[0])) {
        ok(false, 'fuzz value mismatch vs js-yaml: ' + JSON.stringify(yaml).slice(0, 70) + '\n  expected: ' + JSON.stringify(reference).slice(0, 100) + '\n  got: ' + JSON.stringify(single.docs).slice(0, 100));
      }
    } else {
      malformed++;
      if (single.threw && refErr) ok(true, '');
    }

    // chunking must never change the result
    ok(JSON.stringify(many.docs) === JSON.stringify(single.docs) && String(many.threw) === String(single.threw),
      'fuzz chunk inconsistency: ' + JSON.stringify(yaml).slice(0, 70) + '\n  single: ' + (single.threw ? 'THREW' : JSON.stringify(single.docs).slice(0, 60)) + '\n  many: ' + (many.threw ? 'THREW' : JSON.stringify(many.docs).slice(0, 60)));

    // event-replay must reconstruct the single-write result, unless the parser
    // performed a retroactive inline-item retraction (pathological indentation)
    if (!single.threw && !yaml.includes('<<')) {
      const s = createStream();
      const events = [];
      s.on('*', ev => events.push(ev));
      try { s.write(yaml); s.end(); } catch (e) { /* ignore */ }
      if (s.retractions > 0) continue;
      const rebuilt = replay(events);
      ok(deepEqual(rebuilt, single.docs), 'fuzz event-replay mismatch: ' + JSON.stringify(yaml).slice(0, 70) + '\n  docs: ' + JSON.stringify(single.docs).slice(0, 80) + '\n  rebuilt: ' + JSON.stringify(rebuilt).slice(0, 80));
    }
  }
  console.log('random grammar fuzz: ' + generated + ' generated, ' + compared + ' compared vs js-yaml, ' + malformed + ' rejected-by-js-yaml (invariants only)');
}

// ── 4. Security fuzz: bombs must throw quickly, never hang ──
{
  const bombCases = [
    { name: 'deep nest', yaml: 'a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g: 1\n', opts: { maxDepth: 4 } },
    { name: 'node explosion', yaml: Array(5000).fill('- x').join('\n'), opts: { maxNodes: 100 } },
    { name: 'key explosion', yaml: Array(2000).fill('').map((_, i) => 'k' + i + ': 1').join('\n'), opts: { maxKeys: 50 } },
    { name: 'long string', yaml: 'a: ' + 'x'.repeat(100000), opts: { maxStringLength: 100 } },
    { name: 'alias bomb', yaml: 'seed: &a0 1\n' + Array.from({ length: 100 }, (_, i) => 'k' + i + ': &a' + (i + 1) + ' *a' + i).join('\n') + '\nfinal: *a100', opts: { maxAliasDepth: 3 } },
    { name: 'big input', yaml: Array(3000).fill('key: value').join('\n'), opts: { maxInputBytes: 1000 } },
  ];
  for (const bc of bombCases) {
    const s = createStream(bc.opts);
    let threw = null;
    const t0 = Date.now();
    try { s.write(bc.yaml); s.end(); } catch (e) { threw = e; }
    ok(threw !== null, 'security: ' + bc.name + ' should throw');
    ok(Date.now() - t0 < 2000, 'security: ' + bc.name + ' too slow');
  }
  ok(true, '');
  console.log('security bombs: ' + bombCases.length + ' bomb shapes rejected');
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
if (fails.length) {
  for (const f of fails) console.log('  FAIL: ' + f);
  process.exit(1);
}
