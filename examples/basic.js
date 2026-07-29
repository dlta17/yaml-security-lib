import { YamlSecurity, YAMLException, setLimits } from '../src/index.js';

const parser = new YamlSecurity();

// ── 1. Parse YAML ──
const config = parser.parse(`
server:
  host: localhost
  port: 8080
  features:
    - ssl
    - cors
`);
console.log('1. Parse:', JSON.stringify(config.result, null, 2));

// ── 2. Error handling (never throws!) ──
const bad = parser.parse('x: 1\nx: 2');
console.log('2. Duplicate key caught:', bad.ok, bad.error);

// ── 3. Standalone scalars ──
console.log('3. Scalar:', parser.parse('hello').result);

// ── 4. Escape sequences in double-quoted strings ──
console.log('4. Escapes:', parser.parse('msg: "line1\\nline2\\ttab"').result);

// ── 5. Multi-document YAML ──
const docs = parser.parseAll('a: 1\n---\nb: 2\n---\nc: 3');
console.log('5. Multi-doc:', JSON.stringify(docs.result));

// ── 6. Folded block scalar ──
const folded = parser.parse(`
description: >
  This is a long
  text that gets
  folded into one paragraph
`);
console.log('6. Folded block:', JSON.stringify(folded.result.description));

// ── 7. Anchors & aliases ──
const anchored = parser.parse(`
defaults: &default
  timeout: 30
  retries: 3
server:
  <<: *default
  host: example.com
`);
console.log('7. Merge keys:', JSON.stringify(anchored.result));

// ── 8. Dump → YAML ──
const dumped = parser.dump({ name: 'test', values: [1, 2, 3] });
console.log('8. Dump:\n' + dumped.result);

// ── 9. parseToJSON ──
const json = parser.parseToJSON('x: 1\ny: 2');
console.log('9. parseToJSON:', json.result);

// ── 10. Config isolation ──
const strict = new YamlSecurity({ maxAliasDepth: 2 });
const chain = '&a 1\n&b *a\n&c *b\n&d *c\nkey: *d';
console.log('10. Strict (depth=2) rejects:', !strict.parse(chain).ok);
console.log('    Default (depth=10) allows:', parser.parse(chain).ok);

// ── 11. YAMLException ──
try {
  parser.parse('x: 1\nx: 2').ok; // caught
  throw new YAMLException('Manual test error');
} catch (e) {
  console.log('11. YAMLException:', e instanceof YAMLException, e.message);
}

// ── 12. setLimits (global) ──
setLimits({ maxAliasDepth: 5 });
const globalChain = '&a 1\n&b *a\n&c *b\n&d *c\n&e *d\n&f *e\n&g *f\nkey: *g';
console.log('12. Global limit:', !parser.parse(globalChain).ok);
setLimits(); // reset
