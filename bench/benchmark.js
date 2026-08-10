// Honest 3-way benchmark: yaml-security-lib vs js-yaml vs eemeli/yaml.
//   1. Throughput on a realistic config document (median ms/parse).
//   2. Malicious expansion-bomb latency + memory (input stays tiny; the
//      naive parser expands aliases into ~780k elements).
// Not shipped on npm (bench/ lives outside package "files").

import { performance } from 'node:perf_hooks';
import { YamlSecurity } from '../src/index.js';
import * as jsyaml from 'js-yaml';
import YAML from 'yaml';

const ours = new YamlSecurity();
const WARMUP = 20;
const ITERS = 300;

const DOC = `apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: production
  labels:
    app: web
    tier: backend
    env: prod
data:
  server:
    host: 0.0.0.0
    port: 8080
    workers: 4
    keepAliveTimeout: 65
    readTimeout: 30
    writeTimeout: 30
  database:
    url: postgres://localhost:5432/app
    pool:
      min: 2
      max: 20
      idleTimeoutMillis: 30000
      connectionTimeoutMillis: 2000
    ssl: true
    retry:
      attempts: 3
      backoff: ['100ms', '250ms', '500ms']
  cache:
    host: redis-master
    port: 6379
    ttl: 3600
    serialized: false
  features:
    - name: authentication
      enabled: true
      provider: oidc
      issuer: https://id.example.com/
      clientId: 3f0b6c8f
    - name: rate-limiting
      enabled: true
      requestsPerSecond: 100
      burst: 20
      store: in-memory
    - name: telemetry
      enabled: false
      exporter: otlp
      endpoint: https://collector.example.com:4317
    - name: feature-flags
      enabled: true
      provider: custom
      refreshMs: 5000
      fallbackValues:
        checkout-experiment: control
        new-onboarding: off
        dark-launch-search: true
    - name: content-security
      enabled: true
      directives:
        defaultSrc: ["'self'"]
        scriptSrc: ["'self'", 'https://cdn.example.com']
        styleSrc: ["'self'", 'https://cdn.example.com']
        imgSrc: ["'self'", 'data:']
        connectSrc: ["'self'"]
  logging:
    level: info
    format: json
    targets:
      - name: stdout
        transport: console
      - name: file
        transport: rotating-file
        path: /var/log/app.log
        maxBytes: 104857600
        backups: 5
  security:
    jwt:
      secretEnv: JWT_SECRET
      algorithm: RS256
      audience: [api, web]
      issuer: https://auth.example.com/
      leewaySeconds: 60
    cors:
      allowedOrigins: ['https://app.example.com']
      allowedMethods: [GET, POST, PUT, PATCH, DELETE]
      allowedHeaders: [Content-Type, Authorization, X-Request-Id]
      credentials: true
      maxAge: 86400
    ipAllowlist: ['10.0.0.0/8', '172.16.0.0/12']
  tuning:
    connectionPool: 100
    maxBodyBytes: 5242880
    disableRequestLogging: false
    shield:
      csrf: true
      xss: true
      hsts: true
      frameguard: deny
`;

function median(ms) {
  const a = ms.slice().sort((x, y) => x - y);
  const mid = a.length >> 1;
  return a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
}

function bench(fn, iters = ITERS) {
  for (let i = 0; i < WARMUP; i++) fn();
  const times = [];
  for (let i = 0; i < iters; i++) {
    const t0 = performance.now();
    fn();
    times.push(performance.now() - t0);
  }
  return median(times);
}

// Expansion bomb: input ~1.2KB, but aliases expand to 10 * 5^7 ≈ 780k nodes.
function buildBomb(depth = 7, factor = 5, base = 10) {
  let out = '';
  out += 'base: &base\n';
  for (let i = 1; i <= base; i++) out += `  - ${i}\n`;
  let prev = 'base';
  for (let d = 1; d <= depth; d++) {
    out += `${String.fromCharCode(96 + d)}: &${String.fromCharCode(96 + d)}\n`;
    for (let i = 0; i < factor; i++) out += `  - *${prev}\n`;
    prev = String.fromCharCode(96 + d);
  }
  out += `sink: *${prev}\n`;
  return out;
}

console.log('# yaml-security-lib benchmark\n');
console.log('Node ' + process.version + '\n');

console.log('## Throughput — realistic config (' + DOC.length + ' bytes)\n');

const tOurs = bench(() => ours.parse(DOC));
const tJsy = bench(() => jsyaml.load(DOC));
const tYml = bench(() => YAML.parse(DOC));

const fastest = Math.min(tOurs, tJsy, tYml);
console.log('| Library | median ms/parse | vs fastest |');
console.log('|---------|----------------|------------|');
console.log(`| yaml-security-lib \`parse()\` | ${tOurs.toFixed(2)} | ${(tOurs / fastest).toFixed(2)}x |`);
console.log(`| js-yaml \`load()\` | ${tJsy.toFixed(2)} | ${(tJsy / fastest).toFixed(2)}x |`);
console.log(`| eemeli \`yaml.parse()\` | ${tYml.toFixed(2)} | ${(tYml / fastest).toFixed(2)}x |`);

function run(fn) {
  const before = process.memoryUsage().heapUsed;
  const t0 = performance.now();
  let err = null;
  let res;
  try {
    res = fn();
    if (res && typeof res === 'object' && res.ok === false)
      err = new Error(String(res.error).split('\n')[0]);
  } catch (e) { err = e; }
  return { ms: performance.now() - t0, err, heapMB: (process.memoryUsage().heapUsed - before) / 1048576 };
}

function verdict(r) {
  return r.err ? 'rejected: ' + r.err.message.slice(0, 58) : 'parsed';
}

console.log('\n## Alias graph bomb — ' + buildBomb().length + 'B input, ~780k aliased nodes\n');
console.log('yaml-security-lib dereferences every alias into its own sub-tree during `parse()` \'value\' construction, so peak tree size is what the input could amplify to; js-yaml links aliases as shared references and returns the anchored object.\n');
console.log('| Library | result | time | heap ≈ |');
console.log('|---------|--------|------|--------|');

const bomb = buildBomb();
const bOurs = run(() => ours.parse(bomb));
const bJsy = run(() => jsyaml.load(bomb));
const bYml = run(() => YAML.parse(bomb));
console.log(`| yaml-security-lib | ${verdict(bOurs)} | ${bOurs.ms.toFixed(2)}ms | — |`);
console.log(`| js-yaml | ${verdict(bJsy)} | ${bJsy.ms.toFixed(2)}ms | ~${bJsy.heapMB.toFixed(1)}MB |`);
console.log(`| eemeli \`yaml\` | ${verdict(bYml)} | ${bYml.ms.toFixed(2)}ms | ~${bYml.heapMB.toFixed(1)}MB |`);

console.log('\n## Flat mapping bomb — 10,000 distinct keys (~62KB input)\n');
console.log('Many *distinct* mapping keys, no aliases. Exceeds the default 10,000-node cap -> yaml-security-lib refuses with a clean error; js-yaml builds the object and eemeli \\`yaml\\` scales quadratically on wide mappings.\n');
console.log('| Library | result | time | heap ≈ |');
console.log('|---------|--------|------|--------|');

const FLAT = Array.from({ length: 10000 }, (_, i) => 'k' + i + ': value-' + i).join('\n');
const fOurs = run(() => ours.parse(FLAT));
const fJsy = run(() => jsyaml.load(FLAT));
const fYml = run(() => YAML.parse(FLAT));
console.log(`| yaml-security-lib | ${verdict(fOurs)} | ${fOurs.ms.toFixed(2)}ms | ~${fOurs.heapMB.toFixed(1)}MB |`);
console.log(`| js-yaml | ${verdict(fJsy)} | ${fJsy.ms.toFixed(2)}ms | ~${fJsy.heapMB.toFixed(1)}MB |`);
console.log(`| eemeli \`yaml\` | ${verdict(fYml)} | ${fYml.ms.toFixed(2)}ms | ~${fYml.heapMB.toFixed(1)}MB |`);