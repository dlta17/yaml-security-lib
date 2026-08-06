// ────────────────────────────────────────────────────────
// YAML Security Lib — Safe YAML Parser & Dumper
// Zero dependencies. Works in Node ≥16 and modern browsers.
// ────────────────────────────────────────────────────────

import {
  s, string, int, number, float, bool, nullType, any, never,
  enumType, timestamp, array, tuple, object, record,
  optional, nullable, oneOf, anyOf, allOf, not, custom,
  validate, createStreamValidator, fromJSONSchema, toJSONSchema,
} from './validate.js';

// ── Configuration ────────────────────────────────────────

const DEFAULTS = {
  maxNodes: 10_000,
  maxAlias: 100,
  maxAliasDepth: 10,
  maxExpansion: 100_000,
  maxInputMB: 1,
  maxInputBytes: 1_048_576,  // 1MB
  maxStringLength: 0,         // 0 = unlimited
  maxKeys: 0,                 // 0 = unlimited
  maxDepth: 50,               // max nesting depth in block mappings
};

let _baseCfg = { ...DEFAULTS };

/**
 * Globally adjust parser limits for all instances.
 * Call with no arguments (or `{}`) to reset to defaults.
 * @param {{maxNodes?: number, maxAlias?: number, maxAliasDepth?: number, maxExpansion?: number, maxInputMB?: number, maxInputBytes?: number, maxStringLength?: number, maxKeys?: number, maxDepth?: number}} [opts]
 */
export function setLimits(opts) {
  if (!opts || Object.keys(opts).length === 0) { _baseCfg = { ...DEFAULTS }; return; }
  for (const key of ['maxNodes', 'maxAlias', 'maxAliasDepth', 'maxExpansion', 'maxInputBytes']) {
    if (opts[key] !== undefined) {
      const v = opts[key];
      if (typeof v !== 'number' || !Number.isFinite(v) || v < 1 || !Number.isInteger(v))
        throw new YAMLException('setLimits: ' + key + ' must be a positive integer');
      _baseCfg[key] = v;
    }
  }
  for (const key of ['maxStringLength', 'maxKeys', 'maxDepth']) {
    if (opts[key] !== undefined) {
      const v = opts[key];
      if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || !Number.isInteger(v))
        throw new YAMLException('setLimits: ' + key + ' must be a non-negative integer');
      _baseCfg[key] = v;
    }
  }
  if (opts.maxInputMB !== undefined) {
    const v = opts.maxInputMB;
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0.001)
      throw new YAMLException('setLimits: maxInputMB must be a positive number');
    _baseCfg.maxInputBytes = Math.round(v * 1_048_576);
  }
}

// ── Custom Error ─────────────────────────────────────────

/**
 * Error thrown by the parser/dumper on invalid YAML or security violations.
 * Contains optional `mark` with parsing location.
 */
export class YAMLException extends Error {
  /**
   * @param {string} msg
   * @param {{line: number, column: number, snippet: string}} [mark]
   */
  constructor(msg, mark) {
    super(msg);
    this.name = 'YAMLException';
    this.mark = mark || null;
  }
}

// ── Prototype Pollution Guard ────────────────────────────

function safeAssign(obj, key, value) {
  if (key === '__proto__' || key === 'constructor' || key === 'prototype')
    throw new YAMLException('Security: cannot set key "' + key + '" — prototype pollution blocked');
  obj[key] = value;
}

// ── YAML Escape Unescaping ───────────────────────────────

const ESC_MAP = {
  '0': '\x00', 'a': '\x07', 'b': '\x08', 't': '\t', 'n': '\n',
  'v': '\x0b', 'f': '\x0c', 'r': '\r', 'e': '\x1b',
  ' ': ' ',  '"': '"',  '/': '/', '\\': '\\', 'N': '\x85',
  '_': '\xa0', 'L': '\u2028', 'P': '\u2029', '\t': '\t',
};
function unescapeYaml(s) {
  return s.replace(/\\(x[\da-fA-F]{1,2}|u[\da-fA-F]{4}|U[\da-fA-F]{8}|.)/g, (m, seq) => {
    const ch = seq[0];
    if (ch === 'x') {
      if (seq.length < 2) throw new YAMLException('YAML: expected hexadecimal digits after \\x in double-quoted string');
      return String.fromCharCode(parseInt(seq.slice(1), 16));
    }
    if (ch === 'u') {
      if (seq.length < 5) throw new YAMLException('YAML: expected 4 hexadecimal digits after \\u in double-quoted string');
      return String.fromCharCode(parseInt(seq.slice(1), 16));
    }
    if (ch === 'U') {
      if (seq.length < 9) throw new YAMLException('YAML: expected 8 hexadecimal digits after \\U in double-quoted string');
      const cp = parseInt(seq.slice(1), 16);
      return cp > 0xFFFF ? String.fromCharCode(0xD800 + ((cp - 0x10000) >> 10), 0xDC00 + ((cp - 0x10000) & 0x3FF)) : String.fromCharCode(cp);
    }
    if (ESC_MAP[ch] !== undefined) return ESC_MAP[ch];
    throw new YAMLException('YAML: unknown escape sequence "\\' + ch + '" in double-quoted string');
  });
}

// ── Byte length (works in Node & browser) ────────────────

function byteLength(s) {
  if (typeof Buffer !== 'undefined') return Buffer.byteLength(s, 'utf8');
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(s).length;
  return s.length;
}

// ── Base64 decode (Node & browser) ───────────────────────

function decodeBase64(s) {
  if (typeof Buffer !== 'undefined') return Buffer.from(s, 'base64');
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// ── YAML 1.2 implicit type detection ─────────────────────

const TIMESTAMP_RE = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|([+-]\d{2})(?::?(\d{2}))?)?)?$/;
function parseTimestamp(s) {
  const m = s.match(TIMESTAMP_RE);
  if (!m) return null;
  const [, Y, M, D, h, mi, sec, ms, tzH, tzM] = m;
  const date = new Date(Date.UTC(+Y, +M - 1, +D, h|0, mi|0, sec|0, ms ? +ms.padEnd(3, '0').slice(0, 3) : 0));
  if (tzH) date.setUTCHours(date.getUTCHours() - (+tzH));
  if (tzM) date.setUTCMinutes(date.getUTCMinutes() - (+tzM * (tzH < 0 ? -1 : 1)));
  return isNaN(date.getTime()) ? null : date;
}

// ── Schema System ────────────────────────────────────────

/**
 * YAML type definition. Holds a tag, kind, construct/resolve functions,
 * and an optional instance class for mapping/sequence types.
 */
export class YamlType {
  /**
   * @param {string} tag  Full tag URI (e.g. 'tag:yaml.org,2002:str' or '!upper')
   * @param {object} [opts]
   * @param {'scalar'|'mapping'|'sequence'} [opts.kind='scalar']
   * @param {function} [opts.construct]  Transform parsed value (default identity)
   * @param {function} [opts.resolve]    Implicit detection predicate (default false)
   * @param {*}       [opts.instance]    Reserved for mapping/sequence type instances
   */
  constructor(tag, opts = {}) {
    this.tag = tag;
    this.kind = opts.kind || 'scalar';
    this.construct = opts.construct || ((v) => v);
    this.resolve = opts.resolve || (() => false);
    this.instance = opts.instance || undefined;
  }
}

/**
 * Schema registry of YAML types. Controls explicit tag lookup
 * and implicit type resolution order.
 */
export class Schema {
  constructor() {
    this._types = [];
    this._explicit = {};
    this._implicit = [];
  }

  /**
   * Register a type. Scalar types with no `instance` are added to
   * the implicit resolution chain in registration order.
   * @param {YamlType} type
   * @returns {Schema} this (chainable)
   */
  addType(type) {
    this._types.push(type);
    this._explicit[type.tag] = type;
    if (type.kind === 'scalar' && type.instance === undefined) {
      this._implicit.push(type);
    }
    return this;
  }

  /**
   * Remove a previously registered type by tag.
   * @param {string} tag
   * @returns {boolean} true if the type was found and removed
   */
  removeType(tag) {
    const idx = this._types.findIndex(t => t.tag === tag);
    if (idx < 0) return false;
    const [type] = this._types.splice(idx, 1);
    delete this._explicit[tag];
    const impIdx = this._implicit.indexOf(type);
    if (impIdx >= 0) this._implicit.splice(impIdx, 1);
    return true;
  }

  /**
   * Check whether a type with the given tag is registered.
   * @param {string} tag
   * @returns {boolean}
   */
  hasType(tag) {
    return tag in this._explicit;
  }

  /**
   * Return the YAML tag that best describes a JS value.
   * @param {*} val
   * @returns {string}
   */
  tagFor(val) {
    if (val === null || val === undefined) return 'tag:yaml.org,2002:null';
    if (typeof val === 'boolean') return 'tag:yaml.org,2002:bool';
    if (typeof val === 'number') return Number.isInteger(val) ? 'tag:yaml.org,2002:int' : 'tag:yaml.org,2002:float';
    if (typeof val === 'string') {
      for (const type of this._implicit) {
        if (type.resolve && type.resolve(val)) return type.tag;
      }
      return 'tag:yaml.org,2002:str';
    }
    if (val instanceof Date) return 'tag:yaml.org,2002:timestamp';
    if (val instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(val))) return 'tag:yaml.org,2002:binary';
    return 'tag:yaml.org,2002:str';
  }
}

const DEFAULT_SCHEMA = new Schema()
  .addType(new YamlType('tag:yaml.org,2002:null', {
    kind: 'scalar',
    construct: () => null,
    resolve: (v) => v === 'null' || v === '~',
  }))
  .addType(new YamlType('tag:yaml.org,2002:bool', {
    kind: 'scalar',
    construct: (v) => v === 'true',
    resolve: (v) => v === 'true' || v === 'false',
  }))
  .addType(new YamlType('tag:yaml.org,2002:int', {
    kind: 'scalar',
    construct: (v) => {
      if (/^0x[\da-fA-F]+$/.test(v)) return parseInt(v.slice(2), 16);
      if (/^0o[0-7]+$/.test(v)) return parseInt(v.slice(2), 8);
      if (/^0b[01]+$/.test(v)) return parseInt(v.slice(2), 2);
      const n = Number(v);
      return isNaN(n) || !Number.isFinite(n) ? v : Math.floor(n);
    },
    resolve: (v) => {
      if (/^0x[\da-fA-F]+$/.test(v)) return true;
      if (/^0o[0-7]+$/.test(v)) return true;
      if (/^0b[01]+$/.test(v)) return true;
      if (/^[+-]?[0-9]+$/.test(v) && !/^[+-]?0\d+/.test(v)) return true;
      return false;
    },
  }))
  .addType(new YamlType('tag:yaml.org,2002:float', {
    kind: 'scalar',
    construct: (v) => {
      if (/^[-+]?\.(inf|Inf|INF)$/.test(v)) return v.startsWith('-') ? -Infinity : Infinity;
      if (/^\.(nan|NaN|NAN)$/.test(v)) return NaN;
      const n = Number(v);
      return isNaN(n) || !Number.isFinite(n) ? v : n;
    },
    resolve: (v) => {
      if (/^[-+]?\.(inf|Inf|INF)$/.test(v)) return true;
      if (/^\.(nan|NaN|NAN)$/.test(v)) return true;
      if (/^[-+]?\.[0-9]+$/.test(v)) return true;
      if (/^[-+]?[0-9]+\.[0-9]*$/.test(v)) return true;
      if (/^[-+]?[0-9]+\.?[0-9]*(e|E)[-+]?[0-9]+$/.test(v)) return true;
      return false;
    },
  }))
  .addType(new YamlType('tag:yaml.org,2002:timestamp', {
    kind: 'scalar',
    construct: (v) => parseTimestamp(v) || v,
    resolve: (v) => parseTimestamp(v) !== null,
  }))
  .addType(new YamlType('tag:yaml.org,2002:binary', {
    kind: 'scalar',
    construct: (v) => decodeBase64(v),
    resolve: () => false,
  }))
  .addType(new YamlType('tag:yaml.org,2002:str', {
    kind: 'scalar',
    construct: (v) => String(v),
    resolve: () => true,
  }));

let _baseSchema = DEFAULT_SCHEMA;

// AST event kinds for the tree()/parseTree() collectors. Scalar styles follow
// the yaml-test-suite event format (plain/single/double/literal/folded).
const AST_PLAIN = 1, AST_SINGLE = 2, AST_DOUBLE = 3, AST_LITERAL = 4, AST_FOLDED = 5;
const AST_BLOCK = 0, AST_FLOW = 1;

// ── YAML Parser ──────────────────────────────────────────

function yamlToJS(yamlStr, cfg, _depth, _schema, _state, _tags) {
  if (_depth === undefined) _depth = 0;
  if (_schema === undefined) _schema = _baseSchema;
  if (_depth > 50) throw new YAMLException('YAML: recursion too deep (>50) — possible anchor bomb');
  if (byteLength(yamlStr) > cfg.maxInputBytes) {
    throw new YAMLException('YAML: input too large (>' + Math.round(cfg.maxInputBytes / 1048576 * 10) / 10 + 'MB)');
  }

  const state = _state || {};
  if (state.produced === undefined) state.produced = 0;
  if (state.aliasHits === undefined) state.aliasHits = 0;
  if (state.anchors === undefined) state.anchors = {};
  if (state.anchorDepths === undefined) state.anchorDepths = {};
  if (state.anchorSources === undefined) state.anchorSources = {};
  if (state.mergeOverrideKeys === undefined) state.mergeOverrideKeys = new Set();
  if (state.nodeWeights === undefined) state.nodeWeights = new WeakMap();
  if (state._astOn === undefined) state._astOn = false;
  if (state._astOn && !state._ast) state._ast = [];
  const { anchors, anchorDepths, anchorSources, mergeOverrideKeys, nodeWeights } = state;
  const astOn = state._astOn;
  const ast = state._ast;
  let currentLine = -1;
  let currentColumn = -1;

  const lines = yamlStr.split('\n');
  while (lines.length > 0 && lines[lines.length - 1].trim() === '' && false) lines.pop();

  // ── Process YAML directives & markers ──
  let docStartIdx = 0;
  const tags = Object.assign({}, _tags || {});
  let yamlDirectiveSeen = false;
  let sawDirective = false;
  let sawDocStart = false;
  while (docStartIdx < lines.length) {
    const raw = lines[docStartIdx];
    const trimmed = raw.trim();
    if (trimmed === '---' || trimmed.startsWith('--- ') || trimmed.startsWith('---\t') || trimmed === '...' || trimmed.startsWith('... ') || trimmed.startsWith('...\t')) {
      if (trimmed === '---') { sawDocStart = true; docStartIdx++; continue; }
      if ((trimmed.startsWith('--- ') || trimmed.startsWith('---\t')) && trimmed.length > 4) {
        const rest = trimmed.slice(4);
        // js-yaml sets allowCompact=false when content follows `--- ` on the
        // same line, so a block collection (mapping/sequence/explicit key) is
        // illegal there; only scalars, aliases, flow collections and their
        // tag/anchor properties are allowed.
        const restNoProp = rest.replace(/^![^\s]*[ \t]*/, '').replace(/^&[^\s]*[ \t]*/, '').replace(/^\*[^\s]*[ \t]*/, '');
        if (findKeySep(restNoProp) >= 0 || /^[-?][ \t]/.test(restNoProp) || restNoProp === '-' || restNoProp === '?')
          throw err('end of the stream or a document separator is expected');
        lines[docStartIdx] = raw.slice(0, raw.length - trimmed.length) + rest;
        sawDocStart = true;
        break;
      }
      if (trimmed === '...') { docStartIdx++; continue; }
      if ((trimmed.startsWith('... ') || trimmed.startsWith('...\t')) && trimmed.length > 4) {
        break;
      }
      docStartIdx++; continue;
    }
    if (trimmed.startsWith('%TAG')) {
      sawDirective = true;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 3) throw err('invalid %TAG directive: missing handle or prefix');
      if (!/^![^\s]*$/.test(parts[1])) throw err('invalid %TAG directive: bad handle');
      tags[parts[1]] = parts[2];
      docStartIdx++; continue;
    }
    if (/^%YAML($|\s)/.test(trimmed)) {
      sawDirective = true;
      if (yamlDirectiveSeen) throw err('duplicate %YAML directive');
      yamlDirectiveSeen = true;
      const rest = trimmed.slice(5).trim();
      const commentIdx = rest.search(/[ \t]#/);
      const version = commentIdx >= 0 ? rest.slice(0, commentIdx).trim() : rest;
      if (version !== '1.1' && version !== '1.2' && !/^1\.[0-9]+$/.test(version))
        throw err('invalid %YAML directive: bad version');
      docStartIdx++; continue;
    }
    if (trimmed.startsWith('%')) {
      sawDirective = true;
      docStartIdx++; continue;
    }
    if (trimmed === '' || trimmed.startsWith('#')) { docStartIdx++; continue; }
    break;
  }
  // A directive must be followed by a document: a stream that is only
  // directives/comments (no `---` and no content) is an error.
  if (sawDirective && !sawDocStart) {
    let hasContent = false;
    for (let i = docStartIdx; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t !== '' && !t.startsWith('#')) { hasContent = true; break; }
    }
    if (!hasContent) throw err('expected a document after the directive');
  }
  const contentLines = lines.slice(docStartIdx);

  function nodeWeight(node) {
    if (node === null || typeof node !== 'object') return 1;
    if (nodeWeights.has(node)) return nodeWeights.get(node);
    let w = 1;
    if (Array.isArray(node)) for (const item of node) w += nodeWeight(item);
    else for (const k of Object.keys(node)) w += nodeWeight(node[k]);
    nodeWeights.set(node, w);
    return w;
  }

  function track(node, weight) {
    if (typeof node === 'string' && cfg.maxStringLength > 0 && node.length > cfg.maxStringLength)
      throw err('string length exceeds limit (' + cfg.maxStringLength + ')');
    if (typeof node !== 'object' || node === null) {
      state.produced++;
      if (state.produced > cfg.maxNodes)
        throw err('nodes limit exceeded (possible bomb) — reached ' + state.produced);
      if (state.produced > cfg.maxExpansion)
        throw err('expansion limit exceeded (possible bomb) — reached ' + state.produced);
      return node;
    }
    if (weight === undefined) {
      weight = nodeWeight(node);
    }
    state.produced += weight;
    nodeWeights.set(node, weight);
    if (state.produced > cfg.maxNodes)
      throw err('nodes limit exceeded (possible bomb) — reached ' + state.produced);
    if (state.produced > cfg.maxExpansion)
      throw err('expansion limit exceeded (possible bomb) — reached ' + state.produced);
    return node;
  }

  function setAnchor(aname, value, sourceAnchor) {
    if (sourceAnchor) {
      let cur = sourceAnchor;
      while (cur) {
        if (cur === aname)
          throw new YAMLException('YAML: circular alias detected — "' + aname + '"');
        cur = anchorSources[cur];
      }
    }
    const depth = sourceAnchor ? (anchorDepths[sourceAnchor] || 0) + 1 : 0;
    if (depth > cfg.maxAliasDepth)
      throw new YAMLException('YAML: alias depth exceeds limit (' + cfg.maxAliasDepth + '), possible anchor bomb');
    anchors[aname] = value;
    anchorDepths[aname] = depth;
    if (sourceAnchor) anchorSources[aname] = sourceAnchor;
  }

  function resolveAlias(aname) {
    if (++state.aliasHits > cfg.maxAlias) throw new YAMLException('YAML: alias expansion limit exceeded (bomb)');
    const val = anchors[aname];
    if (val === undefined) return aname;
    return val;
  }

  // ── AST event collection ────────────────────────────────
  // Emits a flat event stream (structure + scalar styles) so the caller can
  // render a yaml-test-suite-style event tree or build a document AST.
  function aev(ev) { if (astOn && !state._astSuppress) ast.push(ev); }
  function aContainer(kind, style, anchor, tag) {
    aev({ t: 'c', k: kind, s: style, a: anchor || null, g: tag || null });
  }
  function aClose(kind) { aev({ t: 'x', k: kind }); }
  function aScalar(content, style, anchor, tag) {
    aev({ t: 'v', c: content, s: style, a: anchor || null, g: tag || null });
  }
  function aAlias(name) { aev({ t: 'al', n: name }); }
  function fullTagName(rawTag) {
    if (rawTag.startsWith('!<')) return rawTag.slice(2, -1);
    if (rawTag.startsWith('!!')) {
      const e = expandTag(rawTag);
      return e !== rawTag ? e : 'tag:yaml.org,2002:' + rawTag.slice(2);
    }
    return expandTag(rawTag);
  }
  function astStyleFromRaw(raw) {
    const t = String(raw).trimStart();
    if (t[0] === '"') return AST_DOUBLE;
    if (t[0] === "'") return AST_SINGLE;
    if (t[0] === '|') return AST_LITERAL;
    if (t[0] === '>') return AST_FOLDED;
    return AST_PLAIN;
  }
  // The string value of a scalar (no type resolution), matching the value the
  // yaml-test-suite records for scalar nodes in its event trees.
  function astScalarString(raw) {
    let t = String(raw).trim();
    if (t[0] === '"' || t[0] === "'") {
      const quote = t[0];
      let close = -1;
      let pos = 1;
      if (quote === '"') {
        while (pos < t.length) {
          if (t[pos] === '\\') { pos += 2; continue; }
          if (t[pos] === '"') { close = pos; break; }
          pos++;
        }
      } else {
        while (pos < t.length) {
          if (t[pos] === "'" && t[pos + 1] === "'") { pos += 2; continue; }
          if (t[pos] === "'") { close = pos; break; }
          pos++;
        }
      }
      if (close > 0) {
        const inner = t.slice(1, close);
        if (quote === '"') return unescapeYaml(foldFlowScalar(inner));
        return foldFlowScalar(inner).replace(/''/g, "'");
      }
    }
    let body = t.replace(/[ \t]#[^\n]*$/, '');
    if (body.includes('\n')) {
      const parts = body.split('\n');
      let out = '';
      let pendingBlank = 0;
      for (const line of parts) {
        if (line.trim() === '') { pendingBlank++; continue; }
        const c = line.trim();
        if (pendingBlank > 0) { out += '\n'.repeat(pendingBlank) + c; pendingBlank = 0; }
        else if (out !== '') out += ' ' + c;
        else out = c;
      }
      body = out;
    }
    return body.trim();
  }
  // Split leading node properties (anchor/tag) from a raw scalar token.
  function splitProps(raw) {
    let rest = String(raw).trim();
    let anchor = null;
    let tag = null;
    for (let guard = 0; guard < 4; guard++) {
      if (rest.startsWith('&')) {
        const m = rest.match(/^&([^\s,\[\]{}]+)([\s\S]*)/);
        if (!m) break;
        anchor = m[1];
        rest = m[2].trimStart();
        continue;
      }
      if (rest.startsWith('!')) {
        const m = rest.match(/^(!<[^>]*>|!!?[^\s,\[\]{}]*)([\s\S]*)/);
        if (!m) break;
        tag = fullTagName(m[1]);
        rest = m[2].trimStart();
        continue;
      }
      break;
    }
    return { anchor, tag, rest };
  }
  // Emit a scalar event from a raw token that may carry leading anchor/tag.
  function emitPropsScalar(raw) {
    const p = splitProps(raw);
    aScalar(astScalarString(p.rest), astStyleFromRaw(p.rest), p.anchor, p.tag);
  }

  function expandTag(rawTag) {
    if (rawTag.startsWith('!<')) return rawTag;
    const decodePct = s => s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    const named = /^!([^!]+)!([\s\S]*)$/.exec(rawTag);
    if (named) {
      const handle = '!' + named[1] + '!';
      if (!Object.prototype.hasOwnProperty.call(tags, handle))
        throw new YAMLException('YAML: undeclared tag handle "' + handle + '"');
      return tags[handle] + decodePct(named[2]);
    }
    for (const [handle, prefix] of Object.entries(tags)) {
      if (rawTag.startsWith(handle)) {
        const suffix = rawTag.slice(handle.length);
        if (suffix.length > 0) return prefix + decodePct(suffix);
      }
    }
    return rawTag;
  }

  // Validate a non-verbatim tag: its suffix must not contain flow indicator
  // characters (`[ ] { } ,`). Mirrors js-yaml's "tag suffix cannot contain
  // flow indicator characters".
  function checkTagSuffix(rawTag) {
    if (rawTag.startsWith('!<')) return;
    const suffix = rawTag.startsWith('!!') ? rawTag.slice(2) : rawTag.slice(1);
    if (/[,\[\]{}]/.test(suffix)) throw new YAMLException('YAML: tag suffix cannot contain flow indicator characters');
  }

  // True when a root line starts with a scalar tag that prefixes a same-line
  // implicit mapping key (`!!str a: b`, `!<...> foo :`). Such a tag belongs to
  // the KEY node, not to a root-level tagged container, so the root-tagged-node
  // branch must hand the content to the block parser instead.
  function isTagOnImplicitKey(content) {
    const m = content.match(/^(![^\s]+)[ \t]+([\s\S]*)$/);
    if (!m) return false;
    if (/^!!(seq|map|set|omap|pairs)\b/.test(m[1])) return false;
    const firstLine = m[2].split('\n')[0];
    if (firstLine.startsWith('[') || firstLine.startsWith('{')) return false;
    return findKeySep(firstLine) >= 0;
  }

  // Find the first `:` that acts as a key-value separator:
  // followed by space, tab, EOL, `#`, `}`, `]` — but not inside a quoted string
  function findKeySep(str, start) {
    let quote = null;
    let flowDepth = 0;
    for (let i = start || 0; i < str.length; i++) {
      const ch = str[i];
      if (quote) {
        if (quote === '"') {
          if (ch === '\\') { i++; continue; }
          if (ch === '"') quote = null;
        } else {
          if (ch === "'" && str[i + 1] === "'") { i++; continue; }
          if (ch === "'") quote = null;
        }
        continue;
      }
      if (ch === '"' || ch === "'") {
        // A quote only opens a quoted token at the start of the string or right
        // after a token delimiter; mid-token quotes (e.g. `bla"keks`) are literal.
        if (i === (start || 0) || /[\s,:\[\]{]/.test(str[i - 1])) quote = ch;
        continue;
      }
      if (ch === '[' || ch === '{') { flowDepth++; continue; }
      if (ch === ']' || ch === '}') { flowDepth = Math.max(0, flowDepth - 1); continue; }
      if (ch === '#' && (i === (start || 0) || str[i - 1] === ' ' || str[i - 1] === '\t')) return -1;
      if (ch === ':' && flowDepth === 0) {
        if (i + 1 >= str.length || str[i + 1] === ' ' || str[i + 1] === '\t' || str[i + 1] === '\n' || str[i + 1] === '\r' || str[i + 1] === '}' || str[i + 1] === ']') {
          // A `:` that is part of an anchor/alias-name token (`&a:` / `*a:`)
          // is not a key separator (YAML 1.1 anchor names may contain `:`).
          let t = i - 1;
          while (t >= 0 && !/[\s\[\]{},]/.test(str[t])) t--;
          if (/^[&*]/.test(str.slice(t + 1, i))) { i++; continue; }
          return i;
        }
      }
    }
    return -1;
  }

  // Detect a key-value separator inside a flow sequence item: the first `:`
  // at flow depth 0 (honoring quotes and comments). Returns -1 when the item
  // is a plain scalar (no separator, or a nested flow collection).
  function flowKeySep(s) {
    let quote = null;
    let depth = 0;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (quote) {
        if (quote === '"') {
          if (ch === '\\') { i++; continue; }
          if (ch === '"') quote = null;
        } else {
          if (ch === "'" && s[i + 1] === "'") { i++; continue; }
          if (ch === "'") quote = null;
        }
        continue;
      }
      if (ch === '"' || ch === "'") {
        if (i === 0 || /[\s,:\[\]{]/.test(s[i - 1])) quote = ch;
        continue;
      }
      if (ch === '#' && (i === 0 || /[\s\n]/.test(s[i - 1]))) {
        while (i < s.length && s[i] !== '\n') i++;
        continue;
      }
      if (ch === '[' || ch === '{') { depth++; continue; }
      if (ch === ']' || ch === '}') { if (depth === 0) return -1; depth--; continue; }
      if (ch === ',') { if (depth === 0) return -1; continue; }
      if (ch === ':' && depth === 0) {
        if (i + 1 >= s.length || s[i + 1] === ' ' || s[i + 1] === '\t' || s[i + 1] === '\n' || s[i + 1] === '\r' || s[i + 1] === '}' || s[i + 1] === ']' || s[i + 1] === ',')
          return i;
        // In flow context a `:` directly after a quoted token or a closed flow
        // collection is also a key separator (`"a":b`, `{a: b}:c`).
        if (s[i - 1] === '"' || s[i - 1] === "'" || s[i - 1] === ']' || s[i - 1] === '}')
          return i;
      }
    }
    return -1;
  }

  // End offset of a flow sequence item: the first `,`, `]` or `}` at depth 0,
  // honoring quotes, flow brackets and comments.
  function scanFlowItemEnd(s) {
    let quote = null;
    let depth = 0;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (quote) {
        if (quote === '"') {
          if (ch === '\\') { i++; continue; }
          if (ch === '"') quote = null;
        } else {
          if (ch === "'" && s[i + 1] === "'") { i++; continue; }
          if (ch === "'") quote = null;
        }
        continue;
      }
      if (ch === '"' || ch === "'") {
        if (i === 0 || /[\s,:\[\]{]/.test(s[i - 1])) quote = ch;
        continue;
      }
      if (ch === '#' && (i === 0 || /[\s\n]/.test(s[i - 1]))) {
        while (i < s.length && s[i] !== '\n') i++;
        continue;
      }
      if (ch === '[' || ch === '{') { depth++; continue; }
      if (ch === ']' || ch === '}') { if (depth === 0) return i; depth--; continue; }
      if (ch === ',') { if (depth === 0) return i; continue; }
    }
    return s.length;
  }

  function err(msg, col) {
    const loc = currentLine >= 0 ? ' at line ' + (currentLine + 1) : '';
    const colStr = col !== undefined && currentLine >= 0 ? ', column ' + col : (currentColumn >= 0 && currentLine >= 0 ? ', column ' + currentColumn : '');
    let snippet = '';
    if (currentLine >= 0 && currentLine < lines.length) {
      const src = lines[currentLine] || '';
      snippet = '\n\n  ' + src + '\n  ' + ' '.repeat(Math.max(0, col !== undefined ? col : currentColumn > 0 ? currentColumn : 0)) + '^';
    }
    const mark = currentLine >= 0 ? { line: currentLine + 1, column: (col !== undefined ? col : currentColumn) + 1, snippet } : null;
    return new YAMLException('YAML' + loc + colStr + ': ' + msg + snippet, mark);
  }

  function getIndent(line) {
    let i = 0;
    while (i < line.length && line[i] === ' ') i++;
    if (i < line.length && line[i] === '\t') {
      // Tabs are allowed as separation (never indentation). A leading tab is
      // tolerated only when followed by a flow collection or a comment; a tab
      // after at least one space counts as separation and is ignored.
      if (i === 0) {
        let j = 0;
        while (j < line.length && (line[j] === ' ' || line[j] === '\t')) j++;
        const c = j < line.length ? line[j] : '';
        if (c !== '[' && c !== '{' && c !== '#' && c !== '')
          throw err('Tab characters are not allowed for indentation in YAML 1.2', i);
      }
    }
    return i;
  }

  // Indentation depth for scalar-content lines: a leading tab counts as one
  // column so tab-looking indentation in scalar values still nests. Keys and
  // sequence items keep using the strict getIndent (tabs are rejected there).
  function contentIndent(line) {
    if (line[0] === '\t') return 1;
    let i = 0;
    while (i < line.length && line[i] === ' ') i++;
    return i;
  }

  function tagContentValue(content) {
    const c = content.trim();
    if (c === '') return null;
    if (c.startsWith('"')) {
      let close = -1, pos = 1;
      while (pos < c.length) {
        if (c[pos] === '\\') { pos += 2; continue; }
        if (c[pos] === '"') { close = pos; break; }
        pos++;
      }
      if (close > 0) return unescapeYaml(foldFlowScalar(c.slice(1, close)));
    }
    if (c.startsWith("'")) {
      let close = -1, pos = 1;
      while (pos < c.length) {
        if (c[pos] === "'" && pos + 1 < c.length && c[pos + 1] === "'") { pos += 2; continue; }
        if (c[pos] === "'") { close = pos; break; }
        pos++;
      }
      if (close > 0) return foldFlowScalar(c.slice(1, close)).replace(/''/g, "'");
    }
    if (c.startsWith('[') || c.startsWith('{')) {
      const fr = parseInlineFlow(c);
      if (fr.value !== undefined) return fr.value;
    }
    return c;
  }

  // Find the first real comment marker (`#` preceded by whitespace or at line
  // start) in a plain-scalar line, ignoring quotes. Returns the content before
  // it (trimmed of trailing whitespace) and whether a comment was found.
  function splitPlainComment(line) {
    for (let i = 0; i < line.length; i++) {
      if (line[i] === '#') {
        if (i === 0 || line[i - 1] === ' ' || line[i - 1] === '\t') {
          return { content: line.slice(0, i).replace(/[ \t]+$/, ''), commented: true };
        }
      }
    }
    return { content: line, commented: false };
  }

  // True when the line starts with a quote and the matching closing quote is on
  // the same line (a closed single-line quoted scalar).
  function quotedClosedOnLine(s) {
    const q = s[0];
    if (q !== '"' && q !== "'") return false;
    let i = 1;
    while (i < s.length) {
      if (q === '"') {
        if (s[i] === '\\') { i += 2; continue; }
        if (s[i] === '"') return true;
      } else {
        if (s[i] === "'" && s[i + 1] === "'") { i += 2; continue; }
        if (s[i] === "'") return true;
      }
      i++;
    }
    return false;
  }

  function parseScalar(s) {
    let trimmed = s.trim();

    // A plain scalar node cannot start with `%` (js-yaml canStartPlainScalar
    // rejects it), so a directive-form line at a node position is leftover.
    if (trimmed.startsWith('%')) throw err('unexpected content: a plain scalar cannot start with %');

    // Quoted scalar (possibly spanning several lines): fold inside the quotes.
    if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
      const quote = trimmed[0];
      let close = -1;
      let pos = 1;
      if (quote === '"') {
        while (pos < trimmed.length) {
          if (trimmed[pos] === '\\') { pos += 2; continue; }
          if (trimmed[pos] === '"') { close = pos; break; }
          pos++;
        }
        if (close > 0) {
          return unescapeYaml(foldFlowScalar(trimmed.slice(1, close)));
        }
        throw new YAMLException('YAML: double-quoted scalar is not closed');
      } else {
        while (pos < trimmed.length) {
          if (trimmed[pos] === "'" && trimmed[pos + 1] === "'") { pos += 2; continue; }
          if (trimmed[pos] === "'") { close = pos; break; }
          pos++;
        }
        if (close > 0) {
          return foldFlowScalar(trimmed.slice(1, close)).replace(/''/g, "'");
        }
        throw new YAMLException('YAML: single-quoted scalar is not closed');
      }
    }

    // Fold multi-line plain scalars (continuation lines starting with spaces)
    if (trimmed.includes('\n')) {
      const lines = trimmed.split('\n');
      let out = '';
      let pendingBlank = 0;
      for (const line of lines) {
        if (line.trim() === '') { pendingBlank++; continue; }
        const content = line.trim();
        if (pendingBlank > 0) {
          out += '\n'.repeat(pendingBlank) + content;
          pendingBlank = 0;
        } else if (out !== '') {
          out += ' ' + content;
        } else {
          out = content;
        }
      }
      trimmed = out;
    }

    const tagMatch = trimmed.match(/^(![^\s]+)/);
    if (tagMatch) {
      const rawTag = tagMatch[1];
      checkTagSuffix(rawTag);
      const tagVal = trimmed.slice(tagMatch[0].length).replace(/[ \t]#[^\n]*$/, '').trim();
      let fullTag;

      if (rawTag.startsWith('!!')) {
        const expanded = expandTag(rawTag);
        fullTag = expanded !== rawTag ? expanded : 'tag:yaml.org,2002:' + rawTag.slice(2);
      } else {
        fullTag = expandTag(rawTag);
      }

      const quotedTagVal = tagVal.startsWith('"') || tagVal.startsWith("'");
      const scalarVal = quotedTagVal ? parseScalar(tagVal) : tagVal;

      const type = _schema._explicit[fullTag];
      if (type && !(quotedTagVal && rawTag === '!!binary')) return type.construct(scalarVal);
      if (quotedTagVal) return scalarVal;

      if (rawTag.startsWith('!!')) {
        // unknown !! tag — fall through to implicit
      } else {
        // Unknown ! (or non-specific) tag: the content after the tag is the value.
        if (tagVal === '') return null;
        if (tagVal.startsWith('"') || tagVal.startsWith("'")) return parseScalar(tagVal);
        if (tagVal.startsWith('[') || tagVal.startsWith('{')) {
          const fr = parseInlineFlow(tagVal);
          return fr.value !== undefined ? fr.value : parseScalar(tagVal);
        }
        return tagVal;
      }
    }

    let val = trimmed;

    if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
      return unescapeYaml(val.slice(1, -1));
    }
    if (val.startsWith("'") && val.endsWith("'") && val.length >= 2) {
      return val.slice(1, -1);
    }

    for (const type of _schema._implicit) {
      if (type.resolve && type.resolve(val)) {
        if (type.tag === 'tag:yaml.org,2002:timestamp') continue;
        return type.construct(val);
      }
    }
    return val;
  }

  function parseInlineFlow(str, _flowDepth, _line, _inValue, _blockValue, _allowKeySep, _astAnchor, _astTag) {
    if (_flowDepth === undefined) _flowDepth = 0;
    if (_flowDepth > 100) throw new YAMLException('YAML: flow nesting too deep (>100)');
    const s = str.trim();
    const offset = str.length - s.length;
    if (s.startsWith('[')) {
      aContainer('seq', AST_FLOW, _astAnchor, _astTag);
      const items = [];
      let i = 1;
      let afterComma = true;
      let itemStart = -1;
      while (i < s.length) {
        const c = s[i];
        if (c === ']') {
          const w = items.reduce((s, item) => s + nodeWeight(item), 1);
          aClose('seq');
          return { value: track(items, w), endPos: i + 1 };
        }
        if (c === ' ' || c === '\n' || c === '\t') { i++; continue; }
        if (c === ',') {
          if (afterComma) throw new YAMLException('YAML: unexpected comma in flow sequence');
          afterComma = true;
          itemStart = -1;
          i++;
          continue;
        }
        if (c === '#') {
          const lineStartOk = /^[ \t]*$/.test(s.slice((s.lastIndexOf('\n', i - 1)) + 1, i));
          const prev = i > 0 ? s[i - 1] : '';
          if (!lineStartOk && prev !== ' ' && prev !== '\t' && prev !== '\n')
            throw new YAMLException('YAML: invalid comment in flow sequence');
          while (i < s.length && s[i] !== '\n') i++;
          continue;
        }
        if (c === ':') {
          // A `:` that follows a completed item on a different line cannot be
          // an implicit-key separator in a flow sequence.
          if (itemStart >= 0 && s.slice(itemStart, i).indexOf('\n') >= 0)
            throw new YAMLException('YAML: missed comma between flow collection entries');
        }
        // A document separator (`---` / `...`) at the start of a line inside a
        // flow collection is invalid (mirrors js-yaml's "missed comma" error).
        if (s.startsWith('---', i) || s.startsWith('...', i)) {
          const prevNL = s.lastIndexOf('\n', i - 1);
          const before = prevNL < 0 ? s.slice(0, i) : s.slice(prevNL + 1, i);
          if (/^[ \t]*$/.test(before))
            throw new YAMLException('YAML: missed comma between flow collection entries');
        }
        const sub = s.slice(i);
        if (itemStart < 0) itemStart = i;
        if (/^\?([ \t]|$)/.test(sub)) {
          // Explicit key (`? foo\n bar : baz`): gather the item to its
          // terminator and parse it as a flow mapping with a foldable key.
          const e = scanFlowItemEnd(sub);
          const fr = parseInlineFlow('{' + sub.slice(0, e) + '}');
          if (fr.value !== undefined) {
            items.push(fr.value);
            i += e;
            afterComma = false;
            continue;
          }
        }
        const sep = flowKeySep(sub);
        if (sep >= 0) {
          // An implicit pair in a flow sequence is only valid when the `:`
          // separator is on the same line as the key (YAML simple key rule).
          if (sub.slice(0, sep).indexOf('\n') >= 0)
            throw new YAMLException('YAML: missed comma between flow collection entries');
          const e = scanFlowItemEnd(sub);
          const fr = parseInlineFlow('{' + sub.slice(0, e) + '}');
          if (fr.value && typeof fr.value === 'object') {
            items.push(fr.value);
            i += e;
            afterComma = false;
            continue;
          }
        }
        const r = parseInlineFlow(sub, _flowDepth + 1, _line);
        items.push(r.value);
        i += r.endPos;
        afterComma = false;
      }
      throw new YAMLException('YAML: unexpected end of the stream within a flow sequence');
    }
    if (s.startsWith('{')) {
      aContainer('map', AST_FLOW, _astAnchor, _astTag);
      const obj = {};
      const seenKeys = new Set();
      let i = 1;
      let needComma = false;
      while (i < s.length) {
        const c = s[i];
        if (c === '}') {
          const w = Object.values(obj).reduce((s, item) => s + nodeWeight(item), 1);
          aClose('map');
          return { value: track(obj, w), endPos: i + 1 };
        }
        if (c === ',') {
          if (!needComma) throw new YAMLException('YAML: unexpected comma in flow mapping');
          needComma = false; i++; continue;
        }
        if (c === ' ' || c === '\n' || c === '\t') { i++; continue; }
        if (c === '#') {
          const lineStartOk = /^[ \t]*$/.test(s.slice((s.lastIndexOf('\n', i - 1)) + 1, i));
          const prev = i > 0 ? s[i - 1] : '';
          if (!lineStartOk && prev !== ' ' && prev !== '\t' && prev !== '\n')
            throw new YAMLException('YAML: invalid comment in flow mapping');
          while (i < s.length && s[i] !== '\n') i++;
          continue;
        }
        if (needComma && findKeySep(s.slice(i)) >= 0)
          throw new YAMLException('YAML: missing separating comma in flow mapping');
        if (s.startsWith('---', i) || s.startsWith('...', i)) {
          const prevNL = s.lastIndexOf('\n', i - 1);
          const before = prevNL < 0 ? s.slice(0, i) : s.slice(prevNL + 1, i);
          if (/^[ \t]*$/.test(before))
            throw new YAMLException('YAML: missed comma between flow collection entries');
        }
        let key;
        if (s[i] === '"' || s[i] === "'") {
          if (_line !== undefined) currentColumn = (_line.length - s.length) + offset + i;
          const quote = s[i];
          let close = -1;
          let pos = i + 1;
          if (quote === '"') {
            while (pos < s.length) {
              if (s[pos] === '\\') { pos += 2; continue; }
              if (s[pos] === '"') { close = pos; break; }
              pos++;
            }
          } else {
            while (pos < s.length) {
              if (s[pos] === "'" && pos + 1 < s.length && s[pos + 1] === "'") { pos += 2; continue; }
              if (s[pos] === "'") { close = pos; break; }
              pos++;
            }
          }
          if (close < 0) {
            throw new YAMLException('YAML: unexpected end of the stream within a flow mapping');
          }
          key = s.slice(i + 1, close);
          if (quote === '"') key = unescapeYaml(key);
          key = key.replace(/[ \t]*\n[ \t]*/g, ' ');
          aScalar(astScalarString(s.slice(i, close + 1)), quote === '"' ? AST_DOUBLE : AST_SINGLE);
          i = close + 1;
        } else {
          const fks = flowKeySep(s.slice(i));
          let j;
          if (fks >= 0) j = i + fks;
          else { j = i; while (j < s.length && s[j] !== ',' && s[j] !== '}') j++; }
          let rawKeyTok = s.slice(i, j).trim();
          if (/^\?[ \t\n\r]*$/.test(rawKeyTok)) rawKeyTok = '';
          else if (/^\?[ \t\n\r]/.test(rawKeyTok)) rawKeyTok = rawKeyTok.replace(/^\?[ \t\n\r]*/, '');
          const anchorMatch = /^&([^\s,\[\]{}]+)(?:\s+(.*))?$/.exec(rawKeyTok);
          const anchorName = anchorMatch ? anchorMatch[1] : null;
          const keyToken = anchorName ? (anchorMatch[2] || '') : rawKeyTok;
          if (/^\*[^\s]+$/.test(keyToken)) {
            const aname = keyToken.slice(1);
            aAlias(aname);
            key = track(resolveAlias(aname));
          } else if (/^[\[{]/.test(keyToken)) {
            const kr = parseInlineFlow(keyToken, _flowDepth + 1, _line, false, true, true, anchorName);
            if (kr.endPos === keyToken.length && kr.value !== undefined) {
              key = kr.value;
              if (anchorName) setAnchor(anchorName, track(key));
            } else {
              emitPropsScalar(rawKeyTok);
              key = rawKeyTok;
              key = key.replace(/[ \t]*\n[ \t]*/g, ' ');
              if (key.startsWith('!')) key = parseScalar(key);
            }
          } else if (/^![^\s]/.test(rawKeyTok)) {
            const tname = rawKeyTok.startsWith('!<') ? rawKeyTok.slice(2, -1) : rawKeyTok.startsWith('!!') ? fullTagName(rawKeyTok) : expandTag(rawKeyTok);
            aScalar('', AST_PLAIN, null, tname);
            key = '';
          } else {
            emitPropsScalar(rawKeyTok);
            key = rawKeyTok;
            key = key.replace(/[ \t]*\n[ \t]*/g, ' ');
            if (key.startsWith('!')) key = parseScalar(key);
            if (key.startsWith('&')) {
              const km = key.match(/^&([^\s,\[\]{}]+)\s*(.*)/);
              if (km) {
                const restKey = km[2].trim();
            if (restKey !== '') {
              key = restKey;
              const ktm = key.match(/^(![^\s]+)[ \t]+(.*)$/);
              if (ktm) { checkTagSuffix(ktm[1]); key = ktm[2].trim() === '' ? '' : ktm[2].trim(); }
              if ((key.startsWith('"') && key.endsWith('"') && key.length >= 2)) key = unescapeYaml(key.slice(1, -1));
              else if ((key.startsWith("'") && key.endsWith("'") && key.length >= 2)) key = key.slice(1, -1).replace(/''/g, "'");
              setAnchor(km[1], track(key));
            } else {
                  key = '';
                }
              }
            }
          }
          i = j;
        }
        if (cfg.maxKeys > 0 && seenKeys.size >= cfg.maxKeys)
          throw new YAMLException('YAML: inline mapping keys limit exceeded (' + cfg.maxKeys + ')');
        if (typeof key === 'string' && seenKeys.has(key)) throw new YAMLException('YAML: Duplicate key: "' + key + '"');
        seenKeys.add(key);
        while (i < s.length) {
          const cc = s[i];
          if (cc === ' ' || cc === '\t' || cc === '\n' || cc === '\r') { i++; continue; }
          if (cc === '#') { while (i < s.length && s[i] !== '\n') i++; continue; }
          break;
        }
        if (i < s.length && s[i] === ':') i++;
        while (i < s.length) {
          const cc = s[i];
          if (cc === ' ' || cc === '\t' || cc === '\n' || cc === '\r') { i++; continue; }
          if (cc === '#') { while (i < s.length && s[i] !== '\n') i++; continue; }
          break;
        }
        if (i >= s.length || s[i] === ',' || s[i] === '}') {
          aScalar('', AST_PLAIN);
          safeAssign(obj, key, null);
          needComma = true;
          continue;
        }
        const r = parseInlineFlow(s.slice(i), _flowDepth + 1, _line, true);
        const val = r.value;
        if (typeof val === 'string' && val.startsWith('&')) {
          const aname = val.slice(1).split(/[ ,\]}]/)[0];
          const rest = val.slice(aname.length + 1).trim();
          const rr = parseInlineFlow(rest, _flowDepth + 1, _line);
          const anchored = track(rr.value);
          const srcAnchor = rest.startsWith('*') ? rest.slice(1).split(/[ ,}\]]/)[0] : null;
          setAnchor(aname, anchored, srcAnchor);
          safeAssign(obj, key, anchored);
          i += aname.length + 1 + rr.endPos;
          needComma = true;
        } else if (typeof val === 'string' && val.startsWith('*')) {
          const aname = val.slice(1);
          safeAssign(obj, key, track(resolveAlias(aname)));
          i += val.length;
          needComma = true;
        } else {
          safeAssign(obj, key, val);
          i += r.endPos;
          needComma = true;
        }
      }
      throw new YAMLException('YAML: unexpected end of the stream within a flow mapping');
    }
    if (s.startsWith('&')) {
      // The anchor name ends only at whitespace/EOL or a flow indicator
      // (`,`, `[`, `]`, `{`, `}`) — mirroring js-yaml's readAnchorProperty.
      const nameEnd = s.slice(1).search(/[ \t\n\r,\[\]{}]/);
      if (nameEnd < 0) {
        const aname = s.slice(1);
        setAnchor(aname, track(null));
        return { value: null, endPos: s.length };
      }
      const aname = s.slice(1, 1 + nameEnd);
      const afterName = s.slice(1 + nameEnd);
      const rest = afterName.trim();
      const wsLen = afterName.length - rest.length;
      // An anchor directly attached to an alias is invalid.
      if (rest.startsWith('*'))
        throw new YAMLException('YAML: alias node should not have any properties');
      const r = rest ? parseInlineFlow(rest, _flowDepth + 1, _line, false, false, false, aname, _astTag) : { value: null, endPos: 0 };
      if (!rest) aScalar('', AST_PLAIN, aname, _astTag);
      const val = track(r.value !== undefined ? r.value : rest);
      const restTrimmed = rest.trim();
      const srcAnchor = restTrimmed.startsWith('*') ? restTrimmed.slice(1).split(/[ ,}\]]/)[0] : null;
      setAnchor(aname, val, srcAnchor);
      return { value: val, endPos: 1 + aname.length + wsLen + r.endPos };
    }
    if (s.startsWith('*')) {
      const aname = s.slice(1).split(/[ ,}\]]/)[0];
      aAlias(aname);
      return { value: track(resolveAlias(aname)), endPos: aname.length + 1 };
    }
    const verbatimTag = s.match(/^(!<[^>]*>)(\s*)/);
    const tagPrefix = verbatimTag || s.match(/^(![^\s,[\]{}]*)\s+/);
    if (tagPrefix) {
      const rawTag = tagPrefix[1];
      checkTagSuffix(rawTag);
      const rest = verbatimTag ? s.slice(tagPrefix[1].length) : s.slice(tagPrefix[0].length);
      const trimmedRest = rest.trim();
      const terminator = trimmedRest === '' || trimmedRest.startsWith('}') || trimmedRest.startsWith(']') || trimmedRest.startsWith(',');
      let fullTag;
      if (rawTag.startsWith('!<')) fullTag = rawTag.slice(2, -1);
      else if (rawTag.startsWith('!!')) {
        const expanded = expandTag(rawTag);
        fullTag = expanded !== rawTag ? expanded : 'tag:yaml.org,2002:' + rawTag.slice(2);
      } else {
        fullTag = expandTag(rawTag);
      }
      const r = terminator ? { value: '', endPos: 0 } : parseInlineFlow(rest, _flowDepth + 1, _line, false, false, false, _astAnchor, fullTag);
      let val = r.value;
      if (val === undefined) {
        val = parseScalar(rest);
        if (val !== undefined) emitPropsScalar(rest);
      }
      const type = _schema._explicit[fullTag];
      if (!type) {
        if (rawTag.startsWith('!!')) {
          // Unknown !! tag: use resolved val (backward compat)
        } else {
          // Unknown ! tag: the content after the tag is the value (unresolved).
          const rawContent = s.slice(tagPrefix[0].length, tagPrefix[0].length + r.endPos);
          const cval = rest.startsWith('&') || rest.startsWith('*') ? val : tagContentValue(rawContent);
          return { value: track(cval === undefined ? parseScalar(rest) : cval), endPos: tagPrefix[0].length + r.endPos };
        }
      } else {
        if (!(rawTag === '!!binary' && /^["']/.test(rest.trimStart())))
          val = type.construct(String(val));
      }
      return { value: track(val), endPos: tagPrefix[0].length + r.endPos };
    }
    if (s.startsWith('"')) {
      let close = -1;
      let pos = 1;
      while (pos < s.length) {
        if (s[pos] === '\\') { pos += 2; continue; }
        if (s[pos] === '"') { close = pos; break; }
        pos++;
      }
      if (close > 0) {
        const inner = s.slice(1, close);
        aScalar(unescapeYaml(foldFlowScalar(inner)), AST_DOUBLE, _astAnchor, _astTag);
        return { value: track(unescapeYaml(foldFlowScalar(inner))), endPos: close + 1 };
      }
    }
    if (s.startsWith("'")) {
      let close = -1;
      let pos = 1;
      while (pos < s.length) {
        if (s[pos] === "'" && pos + 1 < s.length && s[pos + 1] === "'") { pos += 2; continue; }
        if (s[pos] === "'") { close = pos; break; }
        pos++;
      }
      if (close > 0) {
        const sv = foldFlowScalar(s.slice(1, close)).replace(/''/g, "'");
        aScalar(sv, AST_SINGLE, _astAnchor, _astTag);
        return { value: track(sv), endPos: close + 1 };
      }
    }
    // A plain scalar in flow context cannot begin with `-` or `?` when the
    // following character is whitespace, end-of-input or a flow indicator.
    if (s[0] === '-' || s[0] === '?') {
      const following = s[1];
      if (following === undefined || following === ']' || following === '}' || following === ',' || following === '[' || following === '{' || following === ' ' || following === '\t' || following === '\n' || following === '\r')
        throw new YAMLException('YAML: missed comma between flow collection entries');
    }
    let end = _blockValue ? -1 : s.search(/[,})\]]/);
    let commentStart = s.search(/\n[ \t]*#/);
    const sameLineComment = s.search(/(^|[ \t])#[^\n]*/);
    if (sameLineComment >= 0 && (commentStart < 0 || sameLineComment < commentStart)) commentStart = sameLineComment;
    if (commentStart >= 0 && (end < 0 || commentStart < end)) end = commentStart;
    if (end < 0) {
      if (_inValue && s.indexOf('\n') >= 0 && findKeySep(s) >= 0)
        throw new YAMLException('YAML: missing separating comma in flow mapping');
      if (_blockValue && findKeySep(s) >= 0 && !_allowKeySep)
        throw new YAMLException('YAML: bad indentation of a mapping entry');
      const bare = s.trim();
      if (/^![^\s]+$/.test(bare)) aScalar('', AST_PLAIN, _astAnchor, fullTagName(bare));
      else aScalar(astScalarString(s), AST_PLAIN, _astAnchor, _astTag);
      return { value: track(parseScalar(s)), endPos: s.length };
    }
    if (end === 0) {
      const bare = s.trim();
      if (/^![^\s]+$/.test(bare)) aScalar('', AST_PLAIN, _astAnchor, fullTagName(bare));
      else aScalar(astScalarString(s), AST_PLAIN, _astAnchor, _astTag);
      return { value: track(parseScalar(s)), endPos: s.length };
    }
    let raw = s.slice(0, end);
    if (_inValue && raw.indexOf('\n') >= 0 && findKeySep(raw) >= 0)
      throw new YAMLException('YAML: missing separating comma in flow mapping');
    if (raw.endsWith(' ')) raw = raw.trimEnd();
    if (/^![^\s]+$/.test(raw)) aScalar('', AST_PLAIN, _astAnchor, fullTagName(raw));
    else aScalar(astScalarString(raw), AST_PLAIN, _astAnchor, _astTag);
    return { value: track(parseScalar(raw)), endPos: end };
  }

  function parseInlineValue(str, allowKeySep, anchor, tag) {
    const r = parseInlineFlow(str, 0, 0, false, true, allowKeySep, anchor, tag);
    if (r.value !== undefined) return r.value;
    emitPropsScalar(str);
    return track(parseScalar(str));
  }

  // Extract a block scalar (| or >) starting at index `start` in `sourceLines`.
  // The indicator line (e.g. `|2-`) may carry an explicit indentation digit and
  // Parse a block scalar header (e.g. `|`, `|2-`, `|-2`, `|+2`, `>1-`) into
  // { style, ind, chomp }. Returns null when the header is invalid. The
  // indentation digit and chomping indicator may appear in either order.
  function parseBSHeader(h) {
    const m = h.match(/^(\||>)([0-9+\-]*)$/);
    if (!m) return null;
    const tail = m[2];
    const style = m[1];
    if (tail === '') return { style, ind: '', chomp: '' };
    if (/^[0-9]+$/.test(tail)) {
      if (tail.length > 1 || tail === '0') return null;
      return { style, ind: tail, chomp: '' };
    }
    if (/^[\-+]$/.test(tail)) return { style, ind: '', chomp: tail };
    const a = tail.match(/^(\d)([\-+])$/);
    if (a) return { style, ind: a[1], chomp: a[2] };
    const b = tail.match(/^([\-+])(\d)$/);
    if (b) return { style, ind: b[2], chomp: b[1] };
    return null;
  }

  // Port of js-yaml's getBlockValue(): given the raw content region (lines
  // with indentation intact) plus contentIndent and chomping, folds or keeps
  // the block scalar content exactly like the reference implementation.
  function blockValueFromRegion(region, contentIndent, chomping, folded) {
    const textIndent = contentIndent < 0 ? 0 : contentIndent;
    const lines = region === '' ? [] : (region.endsWith('\n') ? region.slice(0, -1) : region).split('\n');
    let result = '';
    let didReadContent = false;
    let emptyLines = 0;
    let atMoreIndented = false;
    for (const line of lines) {
      let column = 0;
      while (column < textIndent && line.charCodeAt(column) === 32) column++;
      if (contentIndent < 0 || column >= line.length) { emptyLines++; continue; }
      const content = line.slice(textIndent);
      const first = content.charCodeAt(0);
      if (folded) {
        if (first === 32 || first === 9) {
          atMoreIndented = true;
          result += '\n'.repeat(didReadContent ? 1 + emptyLines : emptyLines);
        } else if (atMoreIndented) {
          atMoreIndented = false;
          result += '\n'.repeat(emptyLines + 1);
        } else if (emptyLines === 0) {
          if (didReadContent) result += ' ';
        } else result += '\n'.repeat(emptyLines);
      } else {
        result += '\n'.repeat(didReadContent ? 1 + emptyLines : emptyLines);
      }
      result += content;
      didReadContent = true;
      emptyLines = 0;
    }
    if (chomping === 3) result += '\n'.repeat(didReadContent ? 1 + emptyLines : emptyLines);
    else if (chomping !== 2) { if (didReadContent) result += '\n'; }
    return result;
  }

  // Port of js-yaml's flow-scalar folding (skipFoldedBreaks/foldedBreaks).
  function foldedBreaks(count) {
    if (count === 1) return ' ';
    return '\n'.repeat(count - 1);
  }
  function skipFoldedBreaksRaw(input, position, end) {
    let breaks = 0;
    while (position < end) {
      const ch = input.charCodeAt(position);
      if (ch === 10) { breaks++; position++; }
      else if (ch === 13) { breaks++; position++; if (input.charCodeAt(position) === 10) position++; }
      else if (ch === 32 || ch === 9) position++;
      else break;
    }
    return { position, breaks };
  }
  function foldFlowScalar(input) {
    let result = '';
    let position = 0;
    let captureStart = 0;
    let captureEnd = 0;
    const end = input.length;
    while (position < end) {
      const ch = input.charCodeAt(position);
      if (ch === 92) {
        const escaped = input.charCodeAt(position + 1);
        if (escaped === 10 || escaped === 13) {
          // Line continuation: the backslash and the line break (plus the
          // following separation whitespace) are removed entirely.
          result += input.slice(captureStart, position);
          position = skipFoldedBreaksRaw(input, position + 1, end).position;
        } else {
          // Preserve the backslash and the escaped char so unescapeYaml can
          // translate the escape sequence afterwards.
          result += input.slice(captureStart, position + 2);
          position += 2;
        }
        captureStart = captureEnd = position;
      } else if (ch === 10 || ch === 13) {
        result += input.slice(captureStart, captureEnd);
        const fold = skipFoldedBreaksRaw(input, position, end);
        result += foldedBreaks(fold.breaks);
        position = captureStart = captureEnd = fold.position;
      } else {
        position++;
        if (ch !== 32 && ch !== 9) captureEnd = position;
      }
    }
    return result + input.slice(captureStart, end);
  }

  // True when the flow construct at the start of `s` is closed (quotes matched,
  // brackets balanced) so no continuation lines are needed.
  function flowClosed(s) {
    let quote = null;
    let depth = 0;
    for (let k = 0; k < s.length; k++) {
      const ch = s[k];
      if (quote) {
        if (quote === '"') {
          if (ch === '\\') { k++; continue; }
          if (ch === '"') quote = null;
        } else {
          if (ch === "'" && s[k + 1] === "'") { k++; continue; }
          if (ch === "'") quote = null;
        }
        continue;
      }
      if (ch === '"' || ch === "'") { quote = ch; continue; }
      if (ch === '[' || ch === '{') depth++;
      else if (ch === ']' || ch === '}') { depth--; if (depth < 0) return true; }
    }
    if (quote) return false;
    return depth <= 0;
  }

  // Index just past the closing quote/bracket of a complete quoted scalar or
  // flow collection that starts at `s[0]`, or -1 when `s` does not begin with a
  // quote/bracket or is not fully closed.
  function closedValueEnd(s) {
    if (!/^["'\[\{]/.test(s)) return -1;
    let quote = null;
    let depth = 0;
    for (let k = 0; k < s.length; k++) {
      const ch = s[k];
      if (quote) {
        if (quote === '"') {
          if (ch === '\\') { k++; continue; }
          if (ch === '"') { quote = null; if (depth === 0) return k + 1; }
        } else {
          if (ch === "'" && s[k + 1] === "'") { k++; continue; }
          if (ch === "'") { quote = null; if (depth === 0) return k + 1; }
        }
        continue;
      }
      if (ch === '"' || ch === "'") { quote = ch; continue; }
      if (ch === '[' || ch === '{') depth++;
      else if (ch === ']' || ch === '}') { depth--; if (depth === 0) return k + 1; }
    }
    return -1;
  }

  // Assemble an unclosed flow value together with its continuation lines.
  function gatherFlowValue(valStr, ls, i, keyIndent) {
    let joined = valStr;
    let idx = i + 1;
    while (idx < ls.length && !flowClosed(joined)) {
      const l = ls[idx];
      const t = l.trim();
      if (t === '') { joined += '\n' + l; idx++; continue; }
      let lindent = 0;
      while (lindent < l.length && l[lindent] === ' ') lindent++;
      if (lindent > keyIndent) { joined += '\n' + l; idx++; continue; }
      break;
    }
    return { full: joined, next: idx - 1 };
  }

  // Extract a block scalar (| or >) starting at index `start` in `sourceLines`.
  // The indicator line (e.g. `|2-`) may carry an explicit indentation digit and
  // chomping modifier. Returns { text, next } where next is the index after the
  // consumed content, or null if no block content follows.
  function extractBlockScalar(indicator, sourceLines, start, baseIndent, keyIndent, rootMode) {
    const m = parseBSHeader(indicator);
    const style = m.style;
    const chomp = m.chomp;
    const detectedIndent = m.ind !== '';
    const parentIndent = rootMode ? 0 : baseIndent + 1;
    let contentIndent = detectedIndent ? baseIndent + parseInt(m.ind, 10) : -1;
    if (detectedIndent && contentIndent === 0)
      throw err('block scalar explicit indentation indicator cannot be 0');

    // Region extraction mirrors js-yaml's readBlockScalar(): content indent is
    // detected from the first non-empty line more indented than the parent;
    // whitespace-only lines never terminate the block.
    let maxLeadingIndent = 0;
    let region = '';
    let i = start;
    while (i < sourceLines.length) {
      const line = sourceLines[i];
      // The final empty element produced by splitting a trailing line break is
      // not content; js-yaml's valueEnd stops right after the last consumed
      // line break, so it is never included in the region.
      if (line === '' && i === sourceLines.length - 1) break;
      let column = 0;
      while (column < line.length && line[column] === ' ') column++;
      const wsOnly = line.trim() === '';
      const tabAtCol = column < line.length && line[column] === '\t';
      if (wsOnly && !tabAtCol) {
        if (!detectedIndent && contentIndent === -1) maxLeadingIndent = Math.max(maxLeadingIndent, column);
        region += line + '\n';
        i++;
        continue;
      }
      // A tab within the indentation region (before the parent indent) is an
      // error (mirrors js-yaml: "tab characters must not be used in
      // indentation"). A tab at or past the parent indent makes the line
      // content, so it never falls into the blank-line branch above.
      if (tabAtCol && column < parentIndent)
        throw err('Tab characters are not allowed for indentation in YAML 1.2', column);
      if (contentIndent === -1) {
        if (column < maxLeadingIndent)
          throw err('bad indentation of a mapping entry');
        if (column < parentIndent) break;
        contentIndent = column;
      }
      if (column < contentIndent) break;
      region += line + '\n';
      i++;
    }

    const text = blockValueFromRegion(region, contentIndent, chomp === '-' ? 2 : chomp === '+' ? 3 : 1, style === '>');
    return { text, next: i };
  }

  // Pre-scan for anchors at all levels
  let _anchoring = false;
  const bsStack = [];
  const bsHeaderRe = /:\s*(\||>)[0-9+\-]*\s*$|^\s*-\s+(\||>)[0-9+\-]*\s*$/;
  const rootIsBlockScalar = contentLines.length > 0 && /^(\||>)[0-9+\-]*$/.test(contentLines[0].trim());
  let preFlowOpen = null;
  for (let i = 0; i < contentLines.length; i++) {
    currentLine = i;
    const line = contentLines[i];
    const trimmed = line.trim();
    if (preFlowOpen !== null) {
      preFlowOpen = flowClosed(preFlowOpen + '\n' + line) ? null : preFlowOpen + '\n' + line;
      continue;
    }
    let ind;
    try { ind = getIndent(line); }
    catch (e) { continue; } // a line starting with a tab is scalar continuation content
    if (trimmed !== '') {
      if (rootIsBlockScalar && i > 0) continue;
      while (bsStack.length > 0 && ind <= bsStack[bsStack.length - 1]) bsStack.pop();
      if (bsStack.length > 0) continue; // inside a block scalar — anchors there are plain text
      if (bsHeaderRe.test(line)) bsStack.push(ind);
      let flowProbe = trimmed;
      const cidx = findKeySep(line);
      if (cidx >= 0) flowProbe = line.slice(cidx + 1).trim();
      if ((flowProbe.startsWith('"') || flowProbe.startsWith("'") || flowProbe.startsWith('[') || flowProbe.startsWith('{')) && !flowClosed(flowProbe)) {
        preFlowOpen = flowProbe;
        continue;
      }
    }
    if (trimmed.startsWith('&') && trimmed.includes(' ')) {
      if (_anchoring) continue; // guard re-entrancy
      _anchoring = true;
      state._astSuppress = (state._astSuppress || 0) + 1;
      try {
        const space = trimmed.indexOf(' ');
        const aname = trimmed.slice(1, space);
        const rest = trimmed.slice(space + 1);
        if (anchors[aname] !== undefined) { _anchoring = false; state._astSuppress--; continue; }
        if (rest.startsWith('*')) {
          const srcAnchor = rest.slice(1).trim();
          const val = track(resolveAlias(srcAnchor));
          setAnchor(aname, val, srcAnchor);
        } else if (rest.startsWith('[') || rest.startsWith('{')) {
          if (flowClosed(rest)) {
            const flowResult = parseInlineFlow(rest);
            setAnchor(aname, flowResult.value !== undefined ? flowResult.value : track(parseScalar(rest)));
          }
        } else if (rest.includes(':')) {
          const indent = getIndent(line);
          const dummy = rest + '\n' + contentLines.slice(i + 1)
            .filter(l => getIndent(l) > indent)
            .map(l => l.slice(indent))
            .join('\n');
          setAnchor(aname, track(yamlToJS(dummy, cfg, _depth + 1, _schema, state, tags)));
        } else {
          setAnchor(aname, track(parseScalar(rest)));
        }
      } catch (e) {
        // Best-effort pre-scan: the line is not an anchor declaration (e.g. it
        // is a mapping entry with an anchor on the key). The real parse
        // registers the anchor, so a failure here is safe to skip — except for
        // safety-limit errors (anchor bomb / circular alias), which must
        // propagate even from the pre-scan.
        if (e && /(bomb|limit|circular)/i.test(e.message || '')) { state._astSuppress--; throw e; }
      }
      state._astSuppress--;
      _anchoring = false;
    }
  }
  _anchoring = false;

  function parseBlock(startIdx, baseIndent, sourceLines, blockDepth, stopAtQuestionKey, endLimit, astAnchor, astTag) {
    if (blockDepth === undefined) blockDepth = 0;
    if (cfg.maxDepth > 0 && blockDepth > cfg.maxDepth)
      throw err('nesting depth exceeds limit (' + cfg.maxDepth + ')');
    const ls = sourceLines || contentLines;
    const result = {};
    const seenKeys = new Set();
    function addKey(key) {
      if (cfg.maxKeys > 0 && seenKeys.size >= cfg.maxKeys)
        throw err('mapping keys limit exceeded (' + cfg.maxKeys + ')');
      if (seenKeys.has(key) && key !== '') throw err('Duplicate key: "' + key + '"');
      seenKeys.add(key);
    }
    let astOpened = null;
    const openAstBlock = (kind) => {
      if (astOpened === null) { aContainer(kind, AST_BLOCK, astAnchor, astTag); astOpened = kind; }
    };
    const seq = [];
    let inSeq = false;
    let i = startIdx;
    let lastInlineKey;
    let lastInlineKeyIndent = -1;
    let lastInlineScalar;
    let lastInlineInterrupted = false;
    let lastInlineCommented = false;
    let lastKeyIndent = -1;
    let seqDashIndent = -1;

    while (i < (endLimit === undefined ? ls.length : endLimit)) {
      currentLine = i;
      const line = ls[i];
      const indent = getIndent(line);
      const trimmed = line.trim();
      if (trimmed === '' || trimmed.startsWith('#')) { if (trimmed.startsWith('#') && lastInlineScalar !== undefined) lastInlineInterrupted = true; i++; continue; }
      if (indent < baseIndent) break;
      if (trimmed === '...' || trimmed.startsWith('... ') || trimmed.startsWith('...\t')) {
        if (trimmed === '...') break;
        throw err('unexpected content after a document end marker');
      }
      if (stopAtQuestionKey && indent === baseIndent && (trimmed.startsWith('? ') || trimmed === '?')) break;

      if (trimmed.startsWith('- ') || trimmed.startsWith('-\t') || trimmed === '-') {
        if (line[indent] === '\t')
          throw err('Tab characters are not allowed for indentation in YAML 1.2', indent);
        inSeq = true;
        openAstBlock('seq');
        if (seq.length > 0 && indent !== seqDashIndent)
          throw err('bad indentation of a sequence entry');
        if (seq.length === 0 && lastKeyIndent >= 0 && indent !== lastKeyIndent)
          throw err('bad indentation of a sequence entry');
        seqDashIndent = indent;
        lastInlineScalar = undefined;
        lastInlineInterrupted = false;
        lastInlineCommented = false;
        const dashContent = trimmed === '-' ? '' : trimmed.slice(2);
        const subIndent = indent + 1;

        const itemLines = [];
        let j = i + 1;
        while (j < ls.length) {
          const t = ls[j].trim();
          if (t === '') { itemLines.push(ls[j]); j++; continue; }
          const nindent = getIndent(ls[j]);
          if (nindent < subIndent) break;
          if (t.startsWith('#')) { itemLines.push(ls[j]); j++; continue; }
          const nt = ls[j].trimStart();
          if ((nt === '-' || nt.startsWith('- ')) && nindent === indent) break;
          itemLines.push(ls[j]);
          j++;
        }
        while (itemLines.length > 0 && itemLines[itemLines.length - 1].trim() === '') itemLines.pop();

        const bsH = parseBSHeader(dashContent.replace(/\s*#.*$/, '').trim());
        if (bsH) {
          const afterInd = dashContent.replace(/^(\||>)([0-9+\-]*)/, '');
          if (afterInd !== '') {
            if (!/^[ \t]/.test(afterInd))
              throw err('a line break is expected after the block scalar indicator');
            const trimmedAfter = afterInd.trim();
            if (trimmedAfter !== '' && !trimmedAfter.startsWith('#'))
              throw err('a line break is expected after the block scalar indicator');
          }
          const bs = extractBlockScalar(dashContent.replace(/\s*#.*$/, '').trim(), ls, i + 1, indent, indent);
          aScalar(bs.text, dashContent.trim().startsWith('|') ? AST_LITERAL : AST_FOLDED);
          seq.push(track(bs.text));
          i = bs.next;
          continue;
        }

        if (dashContent.trim() === '' || dashContent.trim().startsWith('#')) {
          // An empty dash with deeper content: the indented block is the item.
          const contentItems = itemLines.filter(l => l.trim() !== '' && !l.trim().startsWith('#'));
          if (contentItems.length > 0) {
            let dd = -1;
            for (const il of itemLines) {
              if (il.trim() === '' || il.trim().startsWith('#')) continue;
              const gi = getIndent(il);
              if (dd === -1 || gi < dd) dd = gi;
            }
            const itemYaml = itemLines.map(l => l.slice(dd)).join('\n');
            seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1, _schema, state, tags)));
          } else {
            aScalar('', AST_PLAIN);
            seq.push(track(null));
          }
          i = j - 1;
        } else {
        const sepWs = trimmed.slice(1).match(/^[ \t]*/)[0];
        const afterSep = trimmed.slice(1 + sepWs.length);
        if (sepWs.indexOf('\t') >= 0) {
          // A tab in the dash-to-content separation makes a following
          // sequence-entry dash illegal (mirrors js-yaml: "bad indentation of
          // a sequence entry"); `-\t-1` stays a plain scalar.
          if (afterSep === '-' || afterSep.startsWith('- ') || afterSep.startsWith('-\t'))
            throw err('bad indentation of a sequence entry');
        }
        const colonIdxItem = findKeySep(dashContent);
        const isMappingItem = colonIdxItem >= 0 && ((dashContent[colonIdxItem + 1] === ' ' || dashContent[colonIdxItem + 1] === '\t' || colonIdxItem === dashContent.length - 1) || itemLines.length > 0);
        let itemDedent;
        if (isMappingItem || dashContent.trimStart().startsWith('-')) {
          // Keys of a mapping item (or a nested sequence) sit at indent+2;
          // deeper lines are their values.
          itemDedent = indent + 2;
        } else {
          // Non-mapping continuation: dedent to the shallowest content line.
          itemDedent = subIndent;
          for (const il of itemLines) {
            if (il.trim() === '') continue;
            const gi = getIndent(il);
            if (itemDedent === subIndent || gi < itemDedent) itemDedent = gi;
          }
        }
        // A block structure item (mapping or nested sequence) pins its content
        // to indent+2; any content line between the dash and that level is a
        // mis-indented sequence entry (mirrors js-yaml: "bad indentation of a
        // sequence entry").
        if (isMappingItem || dashContent.trimStart().startsWith('-')) {
          for (const il of itemLines) {
            if (il.trim() === '' || il.trim().startsWith('#')) continue;
            const gi = getIndent(il);
            if (gi < indent + 2) throw err('bad indentation of a sequence entry');
          }
        }
        const dashAnchorMatch = dashContent.match(/^&([^\s,\[\]{}]+)(\s+.*)?$/);
        if (dashAnchorMatch) {
          const rest = dashAnchorMatch[2] ? dashAnchorMatch[2].trim() : '';
          let value;
          if (rest === '') {
            aScalar('', AST_PLAIN, dashAnchorMatch[1]);
            value = track(null);
          } else if (rest.startsWith('*')) {
            const an = rest.slice(1).trim();
            aAlias(an);
            const av = resolveAlias(an);
            value = track(av === undefined ? rest : av);
          } else value = track(parseInlineValue(rest, false, dashAnchorMatch[1]));
          setAnchor(dashAnchorMatch[1], value);
          seq.push(value);
        } else if (dashContent.startsWith('*')) {
          const an = dashContent.slice(1).replace(/[ \t]#.*$/, '').trim();
          aAlias(an);
          const av = resolveAlias(an);
          seq.push(track(av === undefined ? dashContent : av));
        } else if (dashContent.trimStart().startsWith('-')) {
          const itemYaml = [dashContent, ...itemLines.map(l => l.slice(itemDedent))].join('\n');
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1, _schema, state, tags)));
        } else if (isMappingItem) {
          const itemYaml = [dashContent, ...itemLines.map(l => l.slice(itemDedent))].join('\n');
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1, _schema, state, tags)));
        } else if (itemLines.length === 0) {
          const cveItem = closedValueEnd(dashContent);
          if (cveItem >= 0 && dashContent.slice(cveItem) !== '' && !/^[ \t]+#/.test(dashContent.slice(cveItem))) {
            throw err('unexpected content after a closed ' + (dashContent[0] === '"' || dashContent[0] === "'" ? 'quoted value' : 'flow collection'));
          }
          const bareTag = dashContent.trim().replace(/[ \t]#[^\n]*$/, '').trim();
          if (/^![^\s]+$/.test(bareTag)) {
            // A bare tag sequence item is an empty scalar with that tag.
            checkTagSuffix(bareTag);
            let v = null;
            const tn = bareTag.replace(/^!!/, 'tag:yaml.org,2002:');
            if (tn === 'tag:yaml.org,2002:seq') v = [];
            else if (tn === 'tag:yaml.org,2002:map') v = {};
            else if (tn === 'tag:yaml.org,2002:str') v = '';
            aScalar('', AST_PLAIN, null, fullTagName(bareTag));
            seq.push(track(v));
          } else {
            seq.push(track(parseInlineValue(dashContent)));
          }
        } else {
          const itemYaml = [dashContent, ...itemLines.map(l => l.slice(itemDedent))].join('\n');
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1, _schema, state, tags)));
        }
        }
        i = j - 1;
      } else {
        let colonIdx = -1;
        let key;
        let rawKey;
        let keyAstDone = false;
        openAstBlock('map');
        const afterIndent = line.slice(indent);
        // A non-sequence line at the sequence indent after sequence entries is
        // a new document node, which is illegal (js-yaml: "end of the stream
        // or a document separator is expected").
        if (inSeq && seq.length > 0 && indent === seqDashIndent)
          throw err('end of the stream or a document separator is expected');
        if (afterIndent.startsWith('"')) {
          let close = -1;
          let pos = 1;
          while (pos < afterIndent.length) {
            if (afterIndent[pos] === '\\') { pos += 2; continue; }
            if (afterIndent[pos] === '"') { close = pos; break; }
            pos++;
          }
          if (close > 0) { colonIdx = indent + afterIndent.indexOf(':', close); key = unescapeYaml(afterIndent.slice(1, close)); rawKey = afterIndent.slice(0, close + 1); }
        } else if (afterIndent.startsWith("'")) {
          let close = -1;
          let pos = 1;
          while (pos < afterIndent.length) {
            if (afterIndent[pos] === "'" && pos + 1 < afterIndent.length && afterIndent[pos + 1] === "'") { pos += 2; continue; }
            if (afterIndent[pos] === "'") { close = pos; break; }
            pos++;
          }
          if (close > 0) { colonIdx = indent + afterIndent.indexOf(':', close); key = afterIndent.slice(1, close).replace(/''/g, "'"); rawKey = afterIndent.slice(0, close + 1); }
        }
        let valStr;
        let explicitValueMode = false;
        // Explicit key syntax: ? key \n : value  (check BEFORE colon detection)
        if (afterIndent.startsWith('? ') || afterIndent.startsWith('?\t') || trimmed === '?') {
          if (lastKeyIndent >= 0 && indent !== lastKeyIndent)
            throw err('bad indentation of a mapping entry');
          lastKeyIndent = indent;
          lastInlineScalar = undefined;
          const keyStart = (trimmed === '?' ? '' : afterIndent.slice(2)).replace(/\s*#.*$/, '');

          // Gather the key (may span several lines) and locate the ':' value line.
          const keyLines = [];
          let vi = i + 1;
          while (vi < ls.length) {
            const t = ls[vi].trim();
            const ki = getIndent(ls[vi]);
            if (t === '' || t.startsWith('#')) { keyLines.push(ls[vi]); vi++; continue; }
            if (ki === indent && t.startsWith(':')) break;
            if (ki === indent && t.startsWith('?')) break;
            if (ki === indent && findKeySep(t) >= 0) break;
            if (ki < indent) break;
            keyLines.push(ls[vi]);
            vi++;
          }

          // Assemble the key node from keyStart (+ continuation lines).
          const keyStartTrim = keyStart.trim();
          // A tab in the key's separation space makes a same-line mapping entry
          // or a block-indicator key illegal (mirrors js-yaml's firstTabInLine
          // checks); `?\tkey` and `?\t-1` remain valid keys.
          if ((keyStart.indexOf('\t') >= 0 || /^\?[ \t]*\t/.test(afterIndent)) &&
              (findKeySep(keyStartTrim) >= 0 || /^[-?:]( |$)/.test(keyStartTrim)))
            throw err('bad indentation of a mapping entry');
          let keyNode;
          const hasContinuation = keyLines.some(l => l.trim() !== '' && !l.trim().startsWith('#'));
          if (findKeySep(keyStartTrim) >= 0) {
            let mm = Infinity;
            for (const l of keyLines) { if (l.trim() === '' || l.trim().startsWith('#')) continue; mm = Math.min(mm, getIndent(l)); }
            const ded = mm === Infinity ? 0 : mm;
            const keyContent = [keyStart, ...keyLines.map(l => l === '' ? l : l.slice(ded))].join('\n').trim();
            keyNode = yamlToJS(keyContent, cfg, _depth + 1, _schema, state, tags);
            keyAstDone = true;
          } else if (keyStartTrim !== '' && !/^[-\[{&*>!|]/.test(keyStartTrim) && !hasContinuation) {
            keyNode = keyStartTrim;
            rawKey = keyStartTrim;
            emitPropsScalar(keyStartTrim);
            keyAstDone = true;
          } else if (keyStartTrim.startsWith('|') || keyStartTrim.startsWith('>')) {
            const kb = extractBlockScalar(keyStartTrim, ls, i + 1, indent, indent);
            keyNode = kb.text;
            aScalar(kb.text, keyStartTrim.startsWith('|') ? AST_LITERAL : AST_FOLDED);
            keyAstDone = true;
          } else {
            const content = [keyStart, ...keyLines].filter(l => l.trim() !== '' && !l.trim().startsWith('#'));
            const joined = content.join('\n').trim();
            if (joined === '') keyNode = null;
            else if (joined.startsWith('-')) {
              let mm = Infinity;
              for (const l of keyLines) { if (l.trim() === '' || l.trim().startsWith('#')) continue; mm = Math.min(mm, getIndent(l)); }
              const ded = mm === Infinity ? 0 : mm;
              const keyContent = [keyStart, ...keyLines.map(l => l === '' ? l : l.slice(ded))].join('\n').trim();
              keyNode = yamlToJS(keyContent, cfg, _depth + 1, _schema, state, tags);
              keyAstDone = true;
            }
            else if (joined.startsWith('[') || joined.startsWith('{')) {
              const fr = parseInlineFlow(joined);
              keyNode = fr.value !== undefined ? fr.value : parseScalar(joined);
              keyAstDone = true;
            } else { keyNode = parseScalar(joined); emitPropsScalar(joined); keyAstDone = true; }
          }
          if (typeof keyNode === 'string' && keyNode.startsWith('"') && keyNode.endsWith('"') && keyNode.length >= 2)
            keyNode = unescapeYaml(keyNode.slice(1, -1));
          else if (typeof keyNode === 'string' && keyNode.startsWith("'") && keyNode.endsWith("'") && keyNode.length >= 2)
            keyNode = keyNode.slice(1, -1).replace(/''/g, "'");
          key = typeof keyNode === 'string' ? keyNode : JSON.stringify(keyNode);

          if (vi >= ls.length || !ls[vi].trim().startsWith(':')) {
            // Key with no value (e.g. in !!set)
            aScalar('', AST_PLAIN);
            addKey(key);
            safeAssign(result, key, track(null));
            i = vi;
            continue;
          }
          const colonTrim = ls[vi].trim();
          if (colonTrim.startsWith(':\t')) {
            // A tab right after the explicit-key value separator only permits a
            // scalar (plain/quoted/block) value; any mapping/sequence/flow
            // value is illegal (mirrors js-yaml's firstTabInLine behaviour).
            const vc = colonTrim.slice(1).trimStart();
            if (vc !== '' && (findKeySep(vc) >= 0 || /^[-?:]( |$)/.test(vc) || vc.startsWith('[') || vc.startsWith('{')))
              throw err('bad indentation of a mapping entry');
          }
          valStr = colonTrim === ':' ? '' : colonTrim.slice(1).trim();
          explicitValueMode = true;
          i = vi; // the ':' line — shared value handling below starts content at i+1
        } else {
          if (colonIdx < 0) colonIdx = findKeySep(line, indent);
          if (colonIdx < 0) {
            // Anchor definition (&name or &name value) — registered by the pre-scan.
            // Not allowed between sequence items.
            if (/^&[^\s,\[\]{}]+(\s|$)/.test(trimmed)) {
              if (inSeq && seq.length > 0) throw err('anchor cannot appear between sequence items');
              const aRest = trimmed.replace(/^&[^\s,\[\]{}]+/, '').trim();
              // An anchor directly in front of a block sequence entry on the
              // same line is illegal (js-yaml: "end of the stream or a
              // document separator is expected").
              if (aRest === '-' || aRest.startsWith('- '))
                throw err('end of the stream or a document separator is expected');
              // A bare anchor line after a mapping entry would become a
              // multiline implicit key, which js-yaml rejects.
              if (Object.keys(result).length > 0 || lastKeyIndent >= 0 || (inSeq && seq.length > 0))
                throw err('can not read a block mapping entry; a multiline key may not be an implicit key');
              i++; continue;
            }
            // A plain line with no key separator is only legal as a continuation of the
            // previous inline plain-scalar value (no comment/blank interrupting).
            if (lastInlineScalar !== undefined && !lastInlineInterrupted && getIndent(line) > lastInlineKeyIndent) {
              // A comment on the initial value line cuts the scalar short; any
              // deeper content line is then illegal (js-yaml: "bad indentation
              // of a mapping entry").
              if (lastInlineCommented) throw err('bad indentation of a mapping entry');
              let n = i + 1;
              let commentedLine = false;
              const cont = [];
              const firstSC = splitPlainComment(line);
              if (firstSC.commented) commentedLine = true;
              cont.push(firstSC.content);
              if (!firstSC.commented) {
                while (n < ls.length) {
                  const t = ls[n].trim();
                  if (t === '') { cont.push(ls[n]); n++; continue; }
                  const ni = getIndent(ls[n]);
                  if (ni <= lastInlineKeyIndent) break;
                  if (t.startsWith('#')) { lastInlineInterrupted = true; break; }
                  if (findKeySep(ls[n].slice(ni)) >= 0) throw err('bad indentation of a mapping entry');
                  const sc = splitPlainComment(ls[n]);
                  cont.push(sc.content);
                  n++;
                  if (sc.commented) { commentedLine = true; break; }
                }
              }
              if (commentedLine) {
                // After the scalar was cut short by a comment, any remaining
                // content line at a deeper indent is illegal.
                while (n < ls.length) {
                  const t = ls[n].trim();
                  const ni = getIndent(ls[n]);
                  if (t === '' || t.startsWith('#')) { n++; continue; }
                  if (ni > lastInlineKeyIndent) throw err('bad indentation of a mapping entry');
                  break;
                }
              }
              const joined = String(lastInlineScalar) + '\n' + cont.join('\n');
              safeAssign(result, lastInlineKey, track(parseScalar(joined)));
              if (astOn && !state._astSuppress && ast.length > 0 && ast[ast.length - 1].t === 'v')
                ast.pop();
              aScalar(astScalarString(joined), astStyleFromRaw(joined));
              lastInlineScalar = undefined;
              lastInlineKey = undefined;
              i = n;
              continue;
            }
            throw err('unexpected content: expected a mapping key or sequence item');
          }
          if (key === undefined) { rawKey = line.slice(indent, colonIdx).trim(); key = rawKey; }
          const keyTagM = key.match(/^(![^\s]+)[ \t]+(.*)$/);
          if (keyTagM) { checkTagSuffix(keyTagM[1]); key = keyTagM[2].trim() === '' ? '' : keyTagM[2].trim(); }
          else if (/^![^\s]+$/.test(key)) { checkTagSuffix(key); key = ''; }
          valStr = line.slice(colonIdx + 1).trim();
          if (!keyAstDone) {
            // A flow collection key at block level, e.g. `&key [ &item a, b, c ]: value`
            // or `{first: Sammy, last: Sosa}: v` — parse it as a flow node.
            const km = key.match(/^&([^\s,\[\]{}]+)[ \t]+(.*)$/);
            const keyAnchorName = km ? km[1] : null;
            const keyToken = (km ? km[2] : key).trim();
            if ((keyToken.startsWith('[') || keyToken.startsWith('{')) && keyToken.length > 1) {
              const kr = parseInlineFlow(keyToken, 0, currentLine, false, true, true, keyAnchorName);
              if (kr.endPos === keyToken.length && kr.value !== undefined) {
                key = kr.value;
                if (keyAnchorName) setAnchor(keyAnchorName, track(key));
                keyAstDone = true;
              }
            }
          }
        }
        if (line[indent] === '\t')
          throw err('Tab characters are not allowed for indentation in YAML 1.2', indent);
        currentColumn = colonIdx >= 0 ? colonIdx + 1 : 0;

        // Resolve alias keys (*name) to their anchored value
        if (typeof key === 'string' && key.startsWith('*')) {
          const k = resolveAlias(key.slice(1).trim());
          if (k === undefined) { /* unknown anchor — keep literal */ }
          else if (typeof k === 'string') key = k;
          else if (k !== null && (typeof k === 'number' || typeof k === 'boolean')) key = String(k);
        } else if (typeof key === 'string' && key.startsWith('&')) {
          // &anchor in front of a key (e.g. &anchor 'key' : val) — strip it, anchor the key
          const km = key.match(/^&([^\s,\[\]{}]+)\s*(.*)/);
          if (km) {
            const restKey = km[2].trim();
            // An anchor directly attached to an alias is invalid.
            if (restKey.startsWith('*'))
              throw err('alias node should not have any properties');
            if (restKey !== '') {
              key = restKey;
              const ktm = key.match(/^(![^\s]+)[ \t]+(.*)$/);
              if (ktm) { checkTagSuffix(ktm[1]); key = ktm[2].trim() === '' ? '' : ktm[2].trim(); }
              if ((key.startsWith('"') && key.endsWith('"') && key.length >= 2)) key = unescapeYaml(key.slice(1, -1));
              else if ((key.startsWith("'") && key.endsWith("'") && key.length >= 2)) key = key.slice(1, -1).replace(/''/g, "'");
              setAnchor(km[1], track(key));
            }
          }
        }

        if (!keyAstDone) {
          const rawK = (rawKey !== undefined ? rawKey : String(key)).trim();
          if (rawK.startsWith('*')) aAlias(rawK.slice(1).replace(/[ \t].*$/, ''));
          else emitPropsScalar(rawK);
        }

        // Track merge keys to catch override attempts
        if (key === '<<') {
          mergeOverrideKeys.clear();
          for (const existingKey of seenKeys) mergeOverrideKeys.add(existingKey);
        }

        // Mapping keys at one block level must share the same indentation
        if (lastKeyIndent >= 0 && indent !== lastKeyIndent)
          throw err('bad indentation of a mapping entry');
        lastKeyIndent = indent;

        // Support explicit block scalar indent indicators (|1, |2, >1, >2, etc.)
        const valForBlock = valStr.replace(/^![^\s]+\s*/, '');
        const bsBody = valForBlock.replace(/\s*#.*$/, '').trim();
        const bsHeader = parseBSHeader(bsBody);
        if (valForBlock.startsWith('|') || valForBlock.startsWith('>')) {
          if (!bsHeader)
            throw err('a line break is expected after the block scalar indicator');
          // After the indicator/indicators the line must end, or have whitespace
          // before an optional comment. A bare `#` or other content is an error
          // (mirrors js-yaml: "a line break is expected").
          const afterInd = valForBlock.replace(/^(\||>)([0-9+\-]*)/, '');
          if (afterInd !== '') {
            if (!/^[ \t]/.test(afterInd))
              throw err('a line break is expected after the block scalar indicator');
            const trimmedAfter = afterInd.trim();
            if (trimmedAfter !== '' && !trimmedAfter.startsWith('#'))
              throw err('a line break is expected after the block scalar indicator');
          }
          lastInlineScalar = undefined;
          const bs = extractBlockScalar(bsBody, ls, i + 1, indent, indent);
          const bsTagMatch = valStr.match(/^(!<[^>]*>|!!?[^\s,\[\]{}]*)/);
          const bsTag = bsTagMatch ? bsTagMatch[1] : null;
          aScalar(bs.text, valForBlock.startsWith('|') ? AST_LITERAL : AST_FOLDED, undefined,
            bsTag ? fullTagName(bsTag) : null);
          addKey(key);
          safeAssign(result, key, track(bs.text));
          i = bs.next;
          continue;
        }

        const anchorMatch = valStr.match(/^&([^\s,\[\]{}]+)\s*(.*)/);
        if (anchorMatch && anchorMatch[2].trim() !== '' && !anchorMatch[2].trim().startsWith('#')) {
          lastInlineScalar = undefined;
          const aname = anchorMatch[1];
          const rest = anchorMatch[2].trim();
          addKey(key);
          safeAssign(result, key, track(parseInlineValue(valStr)));
          i++;
          continue;
        }
        if (anchorMatch) {
          lastInlineScalar = undefined;
          setAnchor(anchorMatch[1], null);
        }

        // An anchor directly attached to an alias is invalid in YAML
        // (mirrors js-yaml: "alias node should not have any properties").
        // The anchor token is read greedily (it may contain `*`/`:`), and a
        // following `*` only starts an alias after whitespace.
        {
          const am = valStr.match(/^&([^\s,\[\]{}]+)([ \t]*)(.*)$/);
          if (am && am[3].startsWith('*'))
            throw err('alias node should not have any properties');
        }

        if (valStr === '' || valStr.startsWith('#') || /^![^\s]+(\s+#[^\n]*)?$/.test(valStr.trim()) || /^&[^\s,\[\]{}]+(\s+#[^\n]*)?$/.test(valStr.trim())) {
          const bareTagName = valStr.trim() === '' || valStr.trim().startsWith('#') ? null : (valStr.trim().match(/^(![^\s]+)/) || [])[1] || null;
          const bareAnchorName = (valStr.trim().match(/^&([^\s,\[\]{}]+)/) || [])[1] || null;
          if (bareTagName) checkTagSuffix(bareTagName);
          lastInlineScalar = undefined;
          let nextNonBlank = i + 1;
          while (nextNonBlank < ls.length && (ls[nextNonBlank].trim() === '' || ls[nextNonBlank].trim().startsWith('#'))) nextNonBlank++;
          if (nextNonBlank >= ls.length || (contentIndent(ls[nextNonBlank]) < (explicitValueMode ? indent : indent + 1) && !ls[nextNonBlank].trim().startsWith('-'))) {
            addKey(key);
            let emptyVal = null;
            if (bareTagName) {
              const tn = bareTagName.replace(/^!!/, 'tag:yaml.org,2002:');
              if (tn === 'tag:yaml.org,2002:seq') emptyVal = [];
              else if (tn === 'tag:yaml.org,2002:map') emptyVal = {};
              else if (tn === 'tag:yaml.org,2002:str') emptyVal = '';
            }
            aScalar('', AST_PLAIN, bareAnchorName, bareTagName ? fullTagName(bareTagName) : null);
            safeAssign(result, key, track(emptyVal));
            i++;
            continue;
          }
          // Bare anchor/tag lines at a deeper indent, followed by a compact
          // block value at the key's own indent (e.g. `seq:\n &anchor\n- a` or
          // `key: &anchor\n !!map\n  a: b`), attach those properties to the
          // block value that follows.
          let valueBlockStart = nextNonBlank;
          let valueAnchor = null;
          let valueTag = null;
          {
            let c = nextNonBlank;
            let scanned = true;
            while (scanned && c < ls.length) {
              scanned = false;
              while (c < ls.length && (ls[c].trim() === '' || ls[c].trim().startsWith('#'))) c++;
              const propLine = c < ls.length ? ls[c].trim().replace(/[ \t]#[^\n]*$/, '') : '';
              if (propLine !== '' && /^&[^\s,\[\]{}]+$/.test(propLine)) { valueAnchor = propLine.slice(1); c++; scanned = true; }
              else if (propLine !== '' && /^![^\s]+$/.test(propLine)) { valueTag = propLine; checkTagSuffix(valueTag); c++; scanned = true; }
            }
            if (c < ls.length && getIndent(ls[c]) >= indent) valueBlockStart = c;
          }
          // A second anchor on the same value node written as `&name content`
          // on the first content line (`key: &a\n  &b v`) is rejected, mirroring
          // js-yaml's "bad indentation of a mapping entry".
          if (bareAnchorName && valueBlockStart < ls.length) {
            const fm = ls[valueBlockStart].trim().match(/^&([^\s,\[\]{}]+)(\s+.*)?$/);
            const fr = fm ? (fm[2] || '').trim() : null;
            if (fm && fr !== '' && !fr.startsWith('#') && !blockColonIn(fr))
              throw err('bad indentation of a mapping entry');
          }
          // A standalone block-scalar indicator (`|2`, `>-`, `>1`, ...) on the
          // first content line makes the whole value that block scalar, even
          // when a tag/anchor line precedes it (`folded:\n  !foo\n >1\n value`).
          if (valueBlockStart < ls.length && /^(\||>)[0-9+\-]*$/.test(ls[valueBlockStart].trim())) {
            const bs = extractBlockScalar(ls[valueBlockStart].trim(), ls, valueBlockStart + 1, indent, indent);
            aScalar(bs.text, ls[valueBlockStart].trim().startsWith('|') ? AST_LITERAL : AST_FOLDED, valueAnchor || bareAnchorName,
              valueTag ? (valueTag.startsWith('!!') ? fullTagName(valueTag) : expandTag(valueTag)) : null);
            addKey(key);
            const bsv = track(bs.text);
            if (valueAnchor) setAnchor(valueAnchor, bsv);
            if (bareAnchorName) setAnchor(bareAnchorName, bsv);
            safeAssign(result, key, bsv);
            i = bs.next;
            continue;
          }
          if (valueTag) {
            const tn = valueTag.replace(/^!!/, 'tag:yaml.org,2002:');
            if (tn !== 'tag:yaml.org,2002:seq' && tn !== 'tag:yaml.org,2002:map') valueTag = null;
          }
          // A single node cannot carry both an anchor on the key's value
          // position and another on the block value line (`key: &a\n  &b v`).
          if (bareAnchorName && valueAnchor)
            throw err('the node has two anchors');
          // The block indent is derived from the first content line so that
          // tab-indented scalar values (tabs-as-separation) still nest.
          const nestedBase = explicitValueMode ? indent : contentIndent(ls[valueBlockStart]);
          // blockEnd: first line not nested under this key (blanks/comments skipped).
          // A `-` at the key's own indent continues a compact nested sequence;
          // any other line at that indent starts a sibling entry.
          let blockEnd = valueBlockStart;
          while (blockEnd < ls.length) {
            const t = ls[blockEnd].trim();
            if (t === '' || t.startsWith('#')) { blockEnd++; continue; }
            if (explicitValueMode && getIndent(ls[blockEnd]) === indent && (t.startsWith('? ') || t === '?' || t.startsWith(': '))) break;
            if (getIndent(ls[blockEnd]) === indent && !t.startsWith('-')) break;
            if (contentIndent(ls[blockEnd]) >= nestedBase) { blockEnd++; continue; }
            if (getIndent(ls[blockEnd]) === indent && t.startsWith('-')) { blockEnd++; continue; }
            break;
          }
          // If the nested block is a plain scalar (no keys/seq/block-scalar), it is the value
          const blockContentLines = ls.slice(valueBlockStart, blockEnd).filter(l => !l.trim().startsWith('#'));
          let isFlowBlock = false;
          if (blockContentLines.length > 0) {
            const firstRel = blockContentLines[0].slice(nestedBase).replace(/^&[^\s,\[\]{}]+[ \t]*/, '').replace(/^![^\s]+[ \t]*/, '').trim();
            isFlowBlock = firstRel.startsWith('[') || firstRel.startsWith('{');
          }
          let isScalarBlock = !isFlowBlock;
          for (let p = valueBlockStart; p < blockEnd && isScalarBlock; p++) {
            const t = ls[p].trim();
            if (t === '' || t.startsWith('#')) continue;
            let rel = ls[p].slice(nestedBase).trim();
            if (/^&[^\s,\[\]{}]+[ \t]*/.test(rel)) {
              rel = rel.replace(/^&[^\s,\[\]{}]+[ \t]*/, '');
              if (rel === '') continue;
            }
            rel = rel.replace(/^![^\s]+[ \t]*/, '');
            if (findKeySep(rel) >= 0 || rel === '-' || rel.startsWith('- ') || /^(\||>)[0-9+\-]*$/.test(rel) || rel.startsWith('? ') || rel.startsWith('&')) { isScalarBlock = false; break; }
          }
          if (isFlowBlock) {
            const rawParts = blockContentLines;
            const firstProps = splitProps(rawParts[0].slice(nestedBase));
            const flowText = [firstProps.rest, ...rawParts.slice(1).map(l => l.slice(nestedBase).replace(/^&[^\s,\[\]{}]+[ \t]*/, '').replace(/^![^\s]+[ \t]*/, ''))]
              .join('\n');
            const inlineAnchor = firstProps.anchor;
            const blockAnchor = inlineAnchor && !valueAnchor && !bareAnchorName ? inlineAnchor : (valueAnchor || bareAnchorName);
            const blockTag = firstProps.tag ||
              (valueTag || bareTagName ? (valueTag || bareTagName).startsWith('!!') ? fullTagName(valueTag || bareTagName) : expandTag(valueTag || bareTagName) : null);
            addKey(key);
            const fv = parseInlineFlow(flowText);
            let fval = fv.value !== undefined ? fv.value : parseScalar(flowText);
            if (blockTag && typeof fval === 'string') {
              const type = _schema._explicit[blockTag];
              if (type) fval = type.construct(fval);
            }
            const tracked = track(fval);
            if (blockAnchor) setAnchor(blockAnchor, tracked);
            safeAssign(result, key, tracked);
            i = blockEnd - 1;
          } else if (isScalarBlock) {
            const rawParts = ls.slice(valueBlockStart, blockEnd).filter(l => !l.trim().startsWith('#'));
            const firstProps = splitProps(rawParts[0].slice(nestedBase));
            const folded = [firstProps.rest, ...rawParts.slice(1).map(l => l.slice(nestedBase).replace(/^&[^\s,\[\]{}]+[ \t]*/, ''))]
              .join('\n');
            const inlineAnchor = firstProps.anchor;
            const blockAnchor = inlineAnchor && !valueAnchor && !bareAnchorName ? inlineAnchor : (valueAnchor || bareAnchorName);
            const blockTag = firstProps.tag ||
              (valueTag || bareTagName ? (valueTag || bareTagName).startsWith('!!') ? fullTagName(valueTag || bareTagName) : expandTag(valueTag || bareTagName) : null);
            addKey(key);
            const foldedTrim = folded.trim();
            let sval;
            const contentCount = ls.slice(valueBlockStart, blockEnd)
              .filter(l => l.trim() !== '' && !l.trim().startsWith('#')).length;
            if (contentCount === 1 && /^\*[^\s]+[ \t]*$/.test(foldedTrim)) {
              aAlias(foldedTrim.slice(1).replace(/[ \t#].*$/, '').trim());
              sval = track(resolveAlias(foldedTrim.slice(1).replace(/[ \t#].*$/, '').trim()));
            } else {
              aScalar(astScalarString(folded), astStyleFromRaw(folded), blockAnchor, blockTag);
              sval = track(parseScalar(folded));
            }
            if (blockAnchor) setAnchor(blockAnchor, sval);
            safeAssign(result, key, sval);
            i = blockEnd - 1;
          } else {
            const blockTagName = valueTag || bareTagName;
            const sub = parseBlock(valueBlockStart, nestedBase, ls, blockDepth + 1, explicitValueMode, blockEnd,
              valueAnchor || bareAnchorName, blockTagName ? (blockTagName.startsWith('!!') ? fullTagName(blockTagName) : expandTag(blockTagName)) : null);
            addKey(key);
            if (valueAnchor) setAnchor(valueAnchor, track(sub));
            if (bareAnchorName) setAnchor(bareAnchorName, track(sub));
            safeAssign(result, key, track(sub));
            i = blockEnd - 1;
          }
        } else {
          let val = valStr;
          let consumed = i;
          // In explicit-key mode (`? key\n: value`) the value may be a compact
          // block collection starting inline on the `:` line (js-yaml accepts
          // `: - one\n  - two`). Build the block and parse it as a block node.
          if (explicitValueMode && (valStr === '-' || valStr.startsWith('- ') || valStr.startsWith('-\t'))) {
            const colonAt = ls[i].indexOf(':');
            const valRaw = colonAt >= 0 ? ls[i].slice(colonAt + 1) : valStr;
            const dashAt = valRaw.indexOf('-');
            const dashCol = colonAt + 1 + (dashAt < 0 ? 0 : dashAt);
            const blockLines = [valStr];
            let k = i + 1;
            while (k < ls.length) {
              const t = ls[k].trim();
              if (t === '' || t.startsWith('#')) { blockLines.push(''); k++; continue; }
              const ki = getIndent(ls[k]);
              if (ki === indent && !t.startsWith('-')) break;
              if (ki < dashCol) break;
              blockLines.push(ki === indent ? t : ls[k].slice(dashCol));
              k++;
            }
            addKey(key);
            safeAssign(result, key, track(yamlToJS(blockLines.join('\n'), cfg, _depth + 1, _schema, state, tags)));
            i = k;
            continue;
          }
          if (explicitValueMode && findKeySep(valStr) >= 0) {
            const colonAt = ls[i].indexOf(':');
            const valRaw = colonAt >= 0 ? ls[i].slice(colonAt + 1) : valStr;
            const blockLines = [valRaw.trim()];
            let k = i + 1;
            while (k < ls.length) {
              const t = ls[k].trim();
              if (t === '' || t.startsWith('#')) { blockLines.push(''); k++; continue; }
              const ki = getIndent(ls[k]);
              if (ki <= indent) break;
              blockLines.push(ls[k].slice(indent + 2));
              k++;
            }
            addKey(key);
            safeAssign(result, key, track(yamlToJS(blockLines.join('\n'), cfg, _depth + 1, _schema, state, tags)));
            i = k;
            continue;
          }
          if (flowClosed(valStr) === false && (valStr.startsWith('"') || valStr.startsWith("'") || valStr.startsWith('[') || valStr.startsWith('{') || (valStr.replace(/^![^\s]+[ \t]*/, '') !== valStr && /^["'\[\{]/.test(valStr.replace(/^![^\s]+[ \t]*/, ''))))) {
            const g = gatherFlowValue(valStr, ls, i, indent);
            val = g.full;
            consumed = g.next;
          }
          const cve = closedValueEnd(valStr);
          if (cve >= 0 && valStr.slice(cve) !== '' && !/^[ \t]+#/.test(valStr.slice(cve))) {
            throw err('unexpected content after a closed ' + (valStr[0] === '"' || valStr[0] === "'" ? 'quoted value' : 'flow collection'));
          }
          const parsed = parseInlineValue(val, explicitValueMode);
          lastInlineScalar = (parsed === null || typeof parsed === 'string' || typeof parsed === 'number' || typeof parsed === 'boolean') && !/^[\s"'\[\]{}*&!|>]/.test(valStr) && !/^(\||>)[0-9+\-]*$/.test(valStr) ? parsed : undefined;
          lastInlineKey = key;
          lastInlineKeyIndent = indent;
          lastInlineInterrupted = false;
          lastInlineCommented = typeof parsed === 'string' && splitPlainComment(valStr).commented && lastInlineScalar !== undefined;
          addKey(key);
          safeAssign(result, key, track(parsed));
          i = consumed;
        }
      }
      i++;
    }

    if (inSeq) {
      const w = seq.reduce((s, item) => s + nodeWeight(item), 1);
      if (astOpened === 'seq') aClose('seq');
      return track(seq, w);
    }
    if (astOpened === 'map') aClose('map');
    return track(result);
  }

  const topContent = contentLines.join('\n').trim();
  const top = yamlStr.trim();
  const rootHeader = contentLines.length > 0 ? contentLines[0].trim() : '';
  const rootAnchorRest = rootHeader.startsWith('&') ? rootHeader.replace(/^&[^\s,\[\]{}]+/, '').trim() : null;
  const rootIsKeyAnchor = rootAnchorRest !== null && blockColonIn(rootAnchorRest);
  const rootIsPlainAnchorScalar = rootAnchorRest !== null && !rootIsKeyAnchor && rootAnchorRest !== '' && !rootAnchorRest.startsWith('!') && !/^["'\[\{]/.test(rootAnchorRest) && !/^(\||>)[0-9+\-]*$/.test(rootAnchorRest) && rootAnchorRest.indexOf(':') < 0;
  const rootAnchorHasSibling = (() => {
    if (rootAnchorRest === null || contentLines.length < 2) return false;
    const ai = getIndent(contentLines[0]);
    for (let k = 1; k < contentLines.length; k++) {
      const t = contentLines[k].trim();
      if (t === '' || t.startsWith('#')) continue;
      return getIndent(contentLines[k]) <= ai;
    }
    return false;
  })();
  let result;
  if (/^(\||>)[0-9+\-]*$/.test(rootHeader)) {
    const bs = extractBlockScalar(rootHeader, contentLines, 1, 0, 0, true);
    aScalar(bs.text, rootHeader.startsWith('|') ? AST_LITERAL : AST_FOLDED);
    result = track(bs.text);
  } else if ((rootHeader.startsWith('&') && !rootIsKeyAnchor && !(rootIsPlainAnchorScalar && rootAnchorHasSibling)) || (/^!/.test(rootHeader) && contentLines.length > 1 && /^((&[^\s,\[\]{}]+|![^\s]+)[ \t]+)*((&[^\s,\[\]{}]+|![^\s]+))?([ \t]+#.*)?$/.test(rootHeader))) {
    // Root node with leading anchor/tag property lines. Consume a run of
    // `&name`/`!tag` tokens from the leading lines; the leftover is the node.
    let rootAnchor = null;
    let rootTag = null;
    let rootTagFull = null;
    const splitProps = (s) => {
      let out = s;
      const toks = [];
      for (;;) {
        const m = out.match(/^(&[^\s,\[\]{}]+|![^\s]+)/);
        if (!m) break;
        const tok = m[1];
        const after = out.slice(tok.length);
        if (after !== '' && !/^[ \t]/.test(after)) break;
        toks.push(tok);
        out = after.replace(/^[ \t]+/, '');
      }
      if (/^[ \t]*#/.test(out)) out = '';
      return { leftover: out, toks };
    };
    const applyProps = (toks) => {
      for (const tok of toks) {
        if (tok.startsWith('&')) {
          if (rootAnchor) throw err('the node has two anchors');
          rootAnchor = tok.slice(1);
        } else {
          if (rootTag) throw err('the node has two tags');
          checkTagSuffix(tok);
          if (tok.startsWith('!!')) {
            const expanded = expandTag(tok);
            rootTagFull = expanded !== tok ? expanded : 'tag:yaml.org,2002:' + tok.slice(2);
          } else {
            const verbatim = /^!<(.*)>$/.exec(tok);
            rootTagFull = verbatim ? verbatim[1] : expandTag(tok);
          }
          rootTag = tok;
        }
      }
    };
    const sp = splitProps(rootHeader);
    applyProps(sp.toks);
    if (sp.leftover !== '' && /^[-?]([ \t]|$)/.test(sp.leftover.trim()))
      throw err('end of the stream or a document separator is expected');
    let restLines;
    if (sp.leftover !== '') {
      restLines = [sp.leftover].concat(contentLines.slice(1));
    } else {
      let idx = 1;
      for (;;) {
        while (idx < contentLines.length) {
          const t = contentLines[idx].trim();
          if (t === '' || t.startsWith('#')) { idx++; continue; }
          break;
        }
        if (idx >= contentLines.length) { restLines = []; break; }
        const probe = splitProps(contentLines[idx].trim());
        if (probe.leftover !== '') {
          if (findKeySep(probe.leftover) >= 0 || /^[-?]([ \t]|$)/.test(probe.leftover.trim())) {
            // The line is a mapping/sequence entry; its property tokens belong
            // to the entry (e.g. `&key [ &item a, b, c ]: value`), not the root.
            restLines = contentLines.slice(idx);
          } else {
            applyProps(probe.toks);
            restLines = [probe.leftover].concat(contentLines.slice(idx + 1));
          }
          break;
        }
        applyProps(probe.toks);
        idx++;
      }
    }
    const rest = restLines.join('\n').trim();
    let value;
    if (rest === '') {
      value = null;
      if (rootTagFull === 'tag:yaml.org,2002:seq') value = [];
      else if (rootTagFull === 'tag:yaml.org,2002:map') value = {};
      else if (rootTagFull === 'tag:yaml.org,2002:str') value = '';
      aScalar('', AST_PLAIN, rootAnchor, rootTagFull);
    } else if (rest.startsWith('[') || rest.startsWith('{')) {
      let closePos = -1;
      let flowDepth = 0;
      let inQuote = null;
      for (let p = 0; p < rest.length && closePos < 0; p++) {
        const ch = rest[p];
        if (inQuote) {
          if (ch === '\\' && inQuote === '"') { p++; continue; }
          if (ch === inQuote) { if (inQuote === "'" && rest[p + 1] === "'") { p++; continue; } inQuote = null; }
          continue;
        }
        if (ch === '"' || ch === "'") { inQuote = ch; continue; }
        if (ch === '[' || ch === '{') flowDepth++;
        else if (ch === ']' || ch === '}') { flowDepth--; if (flowDepth === 0) closePos = p; }
      }
      const frTrail = closePos >= 0 ? rest.slice(closePos + 1).trim() : '';
      if (frTrail.startsWith(':')) {
        // A flow collection used as a block mapping key (`[a, b]: v`).
        value = parseBlock(0, 0, restLines, undefined, undefined, undefined, rootAnchor, rootTagFull);
      } else {
        const fr = parseInlineFlow(rest, 0, 0, false, false, false, rootAnchor, rootTagFull);
        value = fr.value !== undefined ? fr.value : parseScalar(rest);
      }
    } else if (rest.startsWith('"') || rest.startsWith("'")) {
      aScalar(astScalarString(rest), astStyleFromRaw(rest), rootAnchor, rootTagFull);
      value = parseScalar(rest);
    } else {
      const firstRest = restLines[0].trim();
      const looksBlock = /^[-?]([ \t]|$)/.test(firstRest) || findKeySep(rest) >= 0;
      if (looksBlock) {
        value = parseBlock(0, 0, restLines, undefined, undefined, undefined, rootAnchor, rootTagFull);
      } else {
        aScalar(astScalarString(rest), AST_PLAIN, rootAnchor, rootTagFull);
        value = parseScalar(rest);
      }
    }
    if (rootTagFull) {
      const type = _schema._explicit[rootTagFull];
      if (type && typeof value === 'string') value = type.construct(value);
    }
    if (rootAnchor) setAnchor(rootAnchor, value);
    result = track(value);
  } else if (topContent.startsWith('[') || topContent.startsWith('{')) {
    let closePos = -1;
    let flowDepth = 0;
    let inQuote = null;
    for (let p = 0; p < topContent.length && closePos < 0; p++) {
      const ch = topContent[p];
      if (inQuote) {
        if (ch === '\\' && inQuote === '"') { p++; continue; }
        if (ch === inQuote) { if (inQuote === "'" && topContent[p + 1] === "'") { p++; continue; } inQuote = null; }
        continue;
      }
      if (ch === '"' || ch === "'") { inQuote = ch; continue; }
      if (ch === '[' || ch === '{') flowDepth++;
      else if (ch === ']' || ch === '}') { flowDepth--; if (flowDepth === 0) closePos = p; }
    }
    const flowTrail = closePos >= 0 ? topContent.slice(closePos + 1).trim() : '';
    if (flowTrail.startsWith(':')) {
      result = parseBlock(0, 0);
    } else {
      const r = parseInlineFlow(topContent);
      const trailRaw = topContent.slice(r.endPos);
      const trail = trailRaw.trim();
      let trailValid = true;
      if (trail !== '' && trail !== '...') {
        const hashPosInTrail = trailRaw.indexOf('#');
        const trailIsComment = trail.startsWith('#') && hashPosInTrail >= 0;
        if (trailIsComment) {
          const hashPos = r.endPos + hashPosInTrail;
          const pc = hashPos > 0 ? topContent[hashPos - 1] : '';
          if (pc !== ' ' && pc !== '\t' && pc !== '\n') trailValid = false;
        } else {
          trailValid = false;
        }
      }
      if (!trailValid)
        throw new YAMLException('YAML: unexpected content after a closed flow collection');
      result = r.value !== undefined ? track(r.value) : track(parseScalar(topContent));
    }
  } else if (topContent === '' || topContent === '---' || topContent === '...') {
    result = null;
  } else if (/^!([^\s]*)/.test(topContent) && !isTagOnImplicitKey(topContent)) {
    // Root-level tagged node: strip the tag and parse the remaining content.
    const tm = topContent.match(/^(![^\s]*)[ \t]*(.*)$/s);
    const rawTag = tm[1];
    checkTagSuffix(rawTag);
    let fullTag;
    if (rawTag.startsWith('!!')) {
      const expanded = expandTag(rawTag);
      fullTag = expanded !== rawTag ? expanded : 'tag:yaml.org,2002:' + rawTag.slice(2);
    } else {
      const verbatim = /^!<(.*)>$/.exec(rawTag);
      fullTag = verbatim ? verbatim[1] : expandTag(rawTag);
    }
    let content = tm[2].trim();
    // Comments on the tag's own line (e.g. `!!map # note`) are not content.
    const tagNl = content.indexOf('\n');
    if (tagNl >= 0) {
      const first = content.slice(0, tagNl);
      if (first.trim().startsWith('#')) content = content.slice(tagNl + 1);
      else content = first.replace(/[ \t]#[^\n]*$/, '') + content.slice(tagNl);
    } else if (content.startsWith('#')) {
      content = '';
    } else {
      content = content.replace(/[ \t]#[^\n]*$/, '');
    }
    content = content.trim();
    if (findKeySep(content) >= 0 || /^[-?]([ \t]|$)/.test(content.trim()) || /^-[ \t]/m.test(content)) {
      // A tagged block collection: parse it as a block node carrying the tag.
      result = track(parseBlock(0, 0, content.split('\n'), undefined, undefined, undefined, null, fullTag));
    } else {
      let taggedVal;
      if (content.startsWith('[') || content.startsWith('{')) {
        const fr = parseInlineFlow(content, 0, 0, false, false, false, null, fullTag);
        taggedVal = fr.value !== undefined ? fr.value : parseScalar(content);
      } else if (content === '') {
        aScalar('', AST_PLAIN, null, fullTag);
        taggedVal = null;
      } else {
        // A multiline tagged scalar: js-yaml folds plain-scalar continuations
        // but rejects document markers, key-value lines and (after a closed
        // quoted scalar) any directive-form or further content line.
        const tagLines = content.split('\n');
        const firstTagLine = tagLines[0].trim();
        if (tagLines.length > 1 && !firstTagLine.startsWith('[') && !firstTagLine.startsWith('{')) {
          const closedQuote = /^"|^'/.test(firstTagLine) && quotedClosedOnLine(firstTagLine);
          let contEnd = tagLines.length;
          for (let ti = 1; ti < tagLines.length; ti++) {
            const tl = tagLines[ti];
            const tt = tl.trim();
            if (tt === '' || tt.startsWith('#')) continue;
            if (tt === '...' || tt.startsWith('... ')) { contEnd = ti; break; }
            if (/^(---|\.\.\.)([ \t]|$)/.test(tl))
              throw err('expected a single document in the stream, but found more');
            if (closedQuote)
              throw err('end of the stream or a document separator is expected');
          }
          for (let ti = contEnd + 1; ti < tagLines.length; ti++) {
            const t = tagLines[ti].trim();
            if (t === '' || t.startsWith('#')) continue;
            throw err('expected a single document in the stream, but found more');
          }
          content = tagLines.slice(0, contEnd).join('\n').trim();
        }
        taggedVal = parseScalar(content.replace(/[ \t]#[^\n]*$/, '').trim());
        aScalar(astScalarString(content), astStyleFromRaw(content), null, fullTag);
      }
      const type = _schema._explicit[fullTag];
      if (type && typeof taggedVal === 'string') {
        result = type.construct(taggedVal);
      } else {
        result = taggedVal;
      }
    }
  } else if (findKeySep(topContent) < 0 && contentLines[0].trim() !== '-' && !topContent.startsWith('- ') && !topContent.startsWith('-\t') && !topContent.startsWith('&') && !topContent.startsWith('*') && !topContent.startsWith('?')) {
    // A document-end marker on its own line ends the (root scalar) document.
    let scalarLines = contentLines;
    let afterDocEnd = [];
    for (let i = 1; i < scalarLines.length; i++) {
      const tt = scalarLines[i].trim();
      if (tt === '...' || tt.startsWith('... ')) { afterDocEnd = scalarLines.slice(i + 1); scalarLines = scalarLines.slice(0, i); break; }
      // A document-start marker at column 0 inside a multiline quoted scalar
      // is rejected ("unexpected end of the document"); in a plain scalar it
      // starts a second document.
      if (/^(---|\.\.\.)([ \t]|$)/.test(scalarLines[i])) {
        const firstT = contentLines[0].trim();
        if (firstT.startsWith('"') || firstT.startsWith("'"))
          throw err('unexpected end of the document within a ' + (firstT[0] === '"' ? 'double' : 'single') + ' quoted scalar');
        throw err('expected a single document in the stream, but found more');
      }
    }
    // A comment cuts the root plain scalar short; any further content line is
    // then a second document node, which is illegal (js-yaml: "end of the
    // stream or a document separator is expected").
    let rootScalarEnd = -1;
    const rootParts = [];
    for (let k = 0; k < scalarLines.length; k++) {
      const sc = splitPlainComment(scalarLines[k]);
      rootParts.push(sc.content);
      rootScalarEnd = k;
      if (sc.commented) break;
    }
    for (let k = rootScalarEnd + 1; k < scalarLines.length; k++) {
      const t = scalarLines[k].trim();
      if (t === '' || t.startsWith('#')) continue;
      throw err('end of the stream or a document separator is expected');
    }
    for (const t of afterDocEnd) {
      if (t.trim() !== '' && !t.trim().startsWith('#'))
        throw err('expected a single document in the stream, but found more');
    }
    result = track(parseScalar(rootParts.join('\n')));
    aScalar(astScalarString(rootParts.join('\n')), astStyleFromRaw(rootParts.join('\n')));
  } else {
    result = parseBlock(0, 0);
  }

  // Resolve merge keys (<<: *anchor)
  function resolveMerges(v) {
    if (Array.isArray(v)) return v.map(resolveMerges);
    if (v instanceof Date || v instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(v))) return v;
    if (v && typeof v === 'object') {
      const merged = {};
      const sources = v['<<'];
      if (sources !== undefined) {
        const list = Array.isArray(sources) ? sources : [sources];
        for (const src of list) {
          if (src && typeof src === 'object' && !Array.isArray(src)) {
            for (const sk of Object.keys(src)) {
              if (!(sk in merged) && sk !== '<<') {
                if (mergeOverrideKeys.has(sk))
                  throw new YAMLException('Merge key << overwrites existing key "' + sk + '"');
                safeAssign(merged, sk, resolveMerges(src[sk]));
              }
            }
          }
        }
      }
      for (const k of Object.keys(v)) {
        if (k !== '<<') {
          safeAssign(merged, k, resolveMerges(v[k]));
        }
      }
      return merged;
    }
    return v;
  }
  return resolveMerges(result);
}

// ── YAML Multi-Document ─────────────────────────────────

// True if a `:` (outside quotes/flow) acts as a block key separator.
function blockColonIn(str) {
  let quote = null;
  let flow = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (quote) {
      if (quote === '"' && c === '\\') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '[' || c === '{') flow++;
    else if (c === ']' || c === '}') flow = Math.max(0, flow - 1);
    else if (c === ':' && flow === 0) {
      const next = str[i + 1];
      if (next === undefined || next === ' ' || next === '\t' || next === ']' || next === '}') return true;
    }
  }
  return false;
}

function parseAllYaml(yamlStr, cfg, _schema, _state) {
  if (byteLength(yamlStr) > cfg.maxInputBytes)
    throw new YAMLException('YAML: input too large (>' + Math.round(cfg.maxInputBytes / 1048576 * 10) / 10 + 'MB)');
  const docs = [];
  const lines = yamlStr.split('\n');
  let current = [];
  let seenDocStart = false;
  let pendingStart = false;
  let sawDirective = false;
  let yamlDirectiveSeen = false;
  let pendingTags = null;
  let curExplicitStart = false;
  let curExplicitEnd = false;
  const flush = () => {
    const hasReal = current.some(l => l.trim() !== '' && !l.trim().startsWith('#'));
    if (hasReal || pendingStart) {
      if (_state && _state._astOn) {
        _state._ast.push({ t: 'doc', s: curExplicitStart, e: curExplicitEnd, empty: !hasReal });
      }
      let docVal;
      if (hasReal) docVal = yamlToJS(current.join('\n'), cfg, 0, _schema, _state, pendingTags || {});
      else docVal = null;
      if (_state && _state._astOn) {
        if (!hasReal) _state._ast.push({ t: 'v', c: '', s: AST_PLAIN, a: null, g: null });
        _state._ast.push({ t: 'docEnd', e: curExplicitEnd });
      }
      docs.push(docVal);
      pendingTags = null;
    }
    current = [];
    curExplicitStart = false;
    curExplicitEnd = false;
  };
  const checkDirective = (line) => {
    const trimmed = line.trim();
    sawDirective = true;
    if (/^%YAML($|\s)/.test(trimmed)) {
      if (yamlDirectiveSeen) throw new YAMLException('YAML: duplicate %YAML directive');
      yamlDirectiveSeen = true;
      const rest = trimmed.slice(5).trim();
      if (!/^(1\.[0-9]+)(\s+1\.[0-9]+)?(\s+#.*)?$/.test(rest))
        throw new YAMLException('YAML: invalid %YAML directive: bad version');
    } else if (/^%TAG($|\s)/.test(trimmed)) {
      const parts = trimmed.split(/\s+/);
      if (parts.length < 3) throw new YAMLException('YAML: invalid %TAG directive: missing handle or prefix');
      if (!/^![^\s]*$/.test(parts[1])) throw new YAMLException('YAML: invalid %TAG directive: bad handle');
      pendingTags = pendingTags || {};
      pendingTags[parts[1]] = parts[2];
    }
  };
  const requireDocAfterDirective = () => {
    if (sawDirective && !seenDocStart && current.length === 0)
      throw new YAMLException('YAML: directives end mark is expected');
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const mStart = line.match(/^---([ \t].*)?$/);
    const mEnd = line.match(/^\.\.\.([ \t].*)?$/);
    if (mStart) {
      flush();
      pendingStart = true;
      seenDocStart = true;
      sawDirective = false;
      curExplicitStart = true;
      const rest = mStart[1] ? mStart[1].trim() : '';
      if (rest !== '') {
        const restNoProp = rest.replace(/^![^\s]*[ \t]*/, '').replace(/^&[^\s]*[ \t]*/, '').replace(/^\*[^\s]*[ \t]*/, '');
        if (/^[-?]([ \t]|$)/.test(restNoProp) || blockColonIn(restNoProp))
          throw new YAMLException('YAML: end of the stream or a document separator is expected');
        current.push(rest);
      }
      continue;
    }
    if (mEnd) {
      if (sawDirective && !seenDocStart) throw new YAMLException('YAML: directives end mark is expected');
      const trail = mEnd[1] ? mEnd[1].trim() : '';
      if (trail !== '' && !trail.startsWith('#'))
        throw new YAMLException('YAML: end of the stream or a document separator is expected');
      curExplicitEnd = true;
      flush();
      pendingStart = false;
      seenDocStart = true;
      sawDirective = false;
      yamlDirectiveSeen = false;
      continue;
    }
    if (trimmed.startsWith('%')) {
      if (current.every(l => l.trim() === '' || l.trim().startsWith('#'))) {
        checkDirective(line);
        continue;
      }
    }
    if (current.length === 0) {
      if (trimmed === '') continue;
      if (trimmed.startsWith('#') && !seenDocStart) continue;
    }
    current.push(line);
  }
  requireDocAfterDirective();
  flush();
  return docs;
}

// ── YAML Dumper ─────────────────────────────────────────

function yamlDump(value, opts = {}) {
  const indent = opts.indent !== undefined ? opts.indent : 2;
  const flowLevel = opts.flowLevel !== undefined ? opts.flowLevel : 6;
  const sortKeys = opts.sortKeys === true;
  const lineWidth = opts.lineWidth !== undefined ? opts.lineWidth : 0;
  const forceQuotes = opts.forceQuotes || false;
  const quotingType = opts.quotingType === 'double' ? 'double' : 'single';
  const visited = new Set();
  function needsQuotes(s) {
    if (typeof s !== 'string') return false;
    if (forceQuotes) return true;
    if (s === '' || s === 'null' || s === 'true' || s === 'false' || s === 'yes' || s === 'no' || s === 'on' || s === 'off') return true;
    if (/^[ \t]|^[#!&*?\-:>|\[\]{}%@`]|[,\[\]{}<>"\n]|^$|^\d+(\.\d+)?$/.test(s)) return true;
    if (s.includes(': ') || s.includes(' #') || s.startsWith(':') || s.endsWith(':') || s.endsWith(' ') || s.endsWith('\t')) return true;
    return false;
  }
  function quote(s) {
    if (needsQuotes(s)) {
      if (quotingType === 'double') return '"' + s.replace(/[\\"]/g, '\\$&').replace(/\n/g, '\\n').replace(/\t/g, '\\t') + '"';
      if (s.includes("'")) return '"' + s.replace(/[\\"]/g, '\\$&') + '"';
      return "'" + s.replace(/'/g, "''") + "'";
    }
    return s;
  }
  function wrapLine(prefix, content) {
    if (lineWidth <= 0 || prefix.length + content.length <= lineWidth) return prefix + content;
    return prefix + content.replace(RegExp('(.{' + (lineWidth - prefix.length) + '})', 'g'), '$1\n' + ' '.repeat(prefix.length));
  }
  function _dump(v, depth) {
    if (typeof v === 'object' && v !== null) {
      if (visited.has(v)) throw new YAMLException('YAML dump: circular reference detected');
      visited.add(v);
    }
    const sp = depth > 0 ? ' '.repeat(indent * depth) : '';
    let result;
    if (v === null || v === undefined) result = 'null';
    else if (typeof v === 'boolean') result = v ? 'true' : 'false';
    else if (typeof v === 'number') result = isNaN(v) ? 'null' : String(v);
    else if (typeof v === 'bigint') result = v.toString();
    else if (typeof v === 'string') result = quote(v);
    else if (v instanceof Date) result = v.toISOString();
    else if (v instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(v))) {
      const b64 = typeof Buffer !== 'undefined' ? Buffer.from(v).toString('base64') : btoa(String.fromCharCode(...v));
      result = '!!binary ' + b64;
    }
    else if (Array.isArray(v)) {
      if (v.length === 0) result = '[]';
      else if (depth >= flowLevel) result = '[' + v.map(item => _dump(item, depth + 1)).join(', ') + ']';
      else result = v.map(item => sp + '- ' + _dump(item, depth + 1).trimStart()).join('\n');
    } else if (typeof v === 'object') {
      let keys = Object.keys(v);
      if (sortKeys) keys = keys.sort();
      if (keys.length === 0) result = '{}';
      else if (depth >= flowLevel) result = '{' + keys.map(k => quote(k) + ': ' + _dump(v[k], depth + 1)).join(', ') + '}';
      else result = keys.map(k => {
        const vv = v[k];
        const isScalar = vv === null || vv === undefined || typeof vv !== 'object' || vv instanceof Date || vv instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(vv));
        if (isScalar) return sp + quote(k) + ': ' + _dump(vv, depth + 1);
        const val = _dump(vv, depth + 1);
        if (val.startsWith('{') && val.endsWith('}') || val.startsWith('[') && val.endsWith(']')) return sp + quote(k) + ': ' + val;
        return sp + quote(k) + ':\n' + val;
      }).join('\n');
    } else result = String(v);
    if (typeof v === 'object' && v !== null) visited.delete(v);
    return result;
  }
  return _dump(value, 0);
}

// ── YAML Document AST ─────────────────────────────────────

const AST_STYLE_CHARS = { 1: ':', 2: "'", 3: '"', 4: '|', 5: '>' };

// Escape scalar content the way the yaml-test-suite event dumper does:
// backslash, tab, CR, LF and backspace are written with a `\` prefix.
function escapeTreeContent(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/\t/g, '\\t')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\x08/g, '\\b');
}

/**
 * Render the flat AST event stream collected by the parser into a
 * yaml-test-suite-style event tree (one node per line).
 * @param {Array<{t:string}>} events
 * @returns {string}
 */
export function renderTree(events) {
  const out = ['+STR'];
  for (const ev of events) {
    if (ev.t === 'doc') {
      out.push('+DOC' + (ev.s ? ' ---' : ''));
    } else if (ev.t === 'docEnd') {
      out.push('-DOC' + (ev.e ? ' ...' : ''));
    } else if (ev.t === 'c') {
      let line = ev.k === 'map' ? '+MAP' : '+SEQ';
      if (ev.s === AST_FLOW) line += ev.k === 'map' ? ' {}' : ' []';
      if (ev.a) line += ' &' + ev.a;
      if (ev.g) line += ' <' + ev.g + '>';
      out.push(line);
    } else if (ev.t === 'x') {
      out.push(ev.k === 'map' ? '-MAP' : '-SEQ');
    } else if (ev.t === 'al') {
      out.push('=ALI *' + ev.n);
    } else if (ev.t === 'v') {
      let line = '=VAL';
      if (ev.a) line += ' &' + ev.a;
      if (ev.g) line += ' <' + ev.g + '>';
      line += ' ' + (AST_STYLE_CHARS[ev.s] || ':') + escapeTreeContent(ev.c);
      out.push(line);
    }
  }
  out.push('-STR');
  return out.join('\n');
}

// Map scalar style ids to human-readable style names for the assembled AST.
const AST_STYLE_NAMES = { 1: 'plain', 2: 'single', 3: 'double', 4: 'literal', 5: 'folded' };

/**
 * Assemble the flat AST event stream into a nested document AST.
 * @param {Array<{t:string}>} events
 * @returns {Array<{type: string}>} One node per document in the stream.
 */
export function assembleAST(events) {
  const docs = [];
  const stack = [];
  let curDoc = null;
  // Each frame tracks whether the next node in a mapping is a key (expectKey).
  function pushFrame(node) {
    stack.push({ kind: node.type === 'mapping' ? 'map' : 'seq', node, expectKey: node.type === 'mapping', pendingKey: null });
  }
  function attachNode(node) {
    if (stack.length === 0) {
      if (curDoc) curDoc.node = node;
      return;
    }
    const top = stack[stack.length - 1];
    if (top.kind === 'seq') {
      top.node.items.push(node);
    } else if (top.expectKey) {
      top.pendingKey = node;
      top.expectKey = false;
    } else {
      top.node.items.push({ key: top.pendingKey, value: node });
      top.pendingKey = null;
      top.expectKey = true;
    }
  }
  for (const ev of events) {
    if (ev.t === 'doc') {
      curDoc = { type: 'document', explicitStart: !!ev.s, explicitEnd: !!ev.e, node: null };
      docs.push(curDoc);
      continue;
    }
    if (!curDoc) continue;
    if (ev.t === 'docEnd') continue;
    if (ev.t === 'c') {
      const node = {
        type: ev.k === 'map' ? 'mapping' : 'sequence',
        flow: ev.s === AST_FLOW,
        anchor: ev.a,
        tag: ev.g,
        items: [],
      };
      attachNode(node);
      pushFrame(node);
    } else if (ev.t === 'x') {
      stack.pop();
    } else if (ev.t === 'v') {
      attachNode({ type: 'scalar', style: AST_STYLE_NAMES[ev.s] || 'plain', anchor: ev.a, tag: ev.g, value: ev.c });
    } else if (ev.t === 'al') {
      attachNode({ type: 'alias', name: ev.n });
    }
  }
  return docs;
}

// Shared schema resolution used by the standalone parse-family APIs.
function resolveSchemaFor(opts) {
  if (opts.schema instanceof Schema) return opts.schema;
  if (Array.isArray(opts.types)) {
    const schema = new Schema();
    for (const t of _baseSchema._types) schema.addType(t);
    for (const t of opts.types) schema.addType(t);
    return schema;
  }
  return _baseSchema;
}

/**
 * Parse YAML and render a yaml-test-suite-style event tree (a string).
 * @param {string} yamlStr
 * @param {{schema?: Schema, types?: YamlType[]}} [opts]
 * @returns {string} The event tree (throws on error)
 */
export function tree(yamlStr, opts = {}) {
  const schema = resolveSchemaFor(opts);
  const state = { _astOn: true, _ast: [] };
  parseAllYaml(yamlStr, { ..._baseCfg }, schema, state);
  return renderTree(state._ast);
}

/**
 * Parse YAML into a nested document AST.
 * @param {string} yamlStr
 * @param {{schema?: Schema, types?: YamlType[]}} [opts]
 * @returns {Array<{type: string}>} One AST node per document (throws on error)
 */
export function parseTree(yamlStr, opts = {}) {
  const schema = resolveSchemaFor(opts);
  const state = { _astOn: true, _ast: [] };
  parseAllYaml(yamlStr, { ..._baseCfg }, schema, state);
  return assembleAST(state._ast);
}

// ── Standalone API ───────────────────────────────────────

/**
 * Parse a YAML string into a JS value.
 * @param {string} yamlStr
 * @param {{schema?: Schema, types?: YamlType[]}} [opts]
 * @returns {*} Parsed value (throws on error)
 */
export function parse(yamlStr, opts = {}) {
  let schema = _baseSchema;
  if (opts.schema instanceof Schema) schema = opts.schema;
  else if (Array.isArray(opts.types)) {
    schema = new Schema();
    for (const t of _baseSchema._types) schema.addType(t);
    for (const t of opts.types) schema.addType(t);
  }
  return yamlToJS(yamlStr, { ..._baseCfg }, 0, schema);
}

/**
 * Parse a multi-document YAML string.
 * @param {string} yamlStr
 * @param {{schema?: Schema, types?: YamlType[]}} [opts]
 * @returns {any[]} Array of parsed documents (throws on error)
 */
export function parseAll(yamlStr, opts = {}) {
  let schema = _baseSchema;
  if (opts.schema instanceof Schema) schema = opts.schema;
  else if (Array.isArray(opts.types)) {
    schema = new Schema();
    for (const t of _baseSchema._types) schema.addType(t);
    for (const t of opts.types) schema.addType(t);
  }
  return parseAllYaml(yamlStr, { ..._baseCfg }, schema);
}

/**
 * Serialize a JS value to YAML.
 * @param {*} value
 * @param {DumpOptions} [opts]
 * @returns {string} YAML string
 */
export function dump(value, opts) {
  return yamlDump(value, opts);
}

/**
 * Parse a YAML string and validate it against a schema spec.
 * Returns `{ ok, value, errors }` — never throws.
 * @param {string} yamlStr
 * @param {*} spec
 * @param {{schema?: Schema, types?: YamlType[]}} [opts]
 */
export function validateYaml(yamlStr, spec, opts = {}) {
  try {
    const value = yamlToJS(yamlStr, { ..._baseCfg }, 0, resolveSchemaFor(opts));
    const r = validate(value, spec);
    return { ok: r.ok, value, errors: r.errors };
  } catch (e) {
    return { ok: false, value: undefined, errors: [{ path: '$', message: e.message, value: undefined }] };
  }
}

// ── Public API Class ──────────────────────────────────────

/**
 * Safe YAML parser / dumper with error-safe API.
 * All parse/dump methods return `{ ok, result }` or `{ ok, error }` — never throw.
 */
export class YamlSecurity {
  /**
   * @param {{maxAliasDepth?: number, maxNodes?: number, maxExpansion?: number, maxStringLength?: number, maxKeys?: number, maxDepth?: number}} [opts]
   */
  constructor(opts) {
    this._overrides = opts ? { ...opts } : {};
    this._schema = DEFAULT_SCHEMA;
  }

  /**
   * Replace the schema used for parsing on this instance.
   * Call with no arguments to reset to DEFAULT_SCHEMA.
   * @param {Schema} [schema]
   */
  setSchema(schema) {
    if (schema === undefined) { this._schema = DEFAULT_SCHEMA; return; }
    if (!(schema instanceof Schema)) throw new YAMLException('setSchema: expected a Schema instance');
    this._schema = schema;
  }

  _getCfg() {
    const cfg = { ..._baseCfg };
    const ov = this._overrides;
    if (ov.maxAliasDepth !== undefined) cfg.maxAliasDepth = ov.maxAliasDepth;
    if (ov.maxNodes !== undefined) cfg.maxNodes = ov.maxNodes;
    if (ov.maxExpansion !== undefined) cfg.maxExpansion = ov.maxExpansion;
    if (ov.maxStringLength !== undefined) cfg.maxStringLength = ov.maxStringLength;
    if (ov.maxKeys !== undefined) cfg.maxKeys = ov.maxKeys;
    if (ov.maxDepth !== undefined) cfg.maxDepth = ov.maxDepth;
    return cfg;
  }

  /**
   * Parse a YAML string. Always returns `{ ok, result }` or `{ ok, error }`.
   * @param {string} yamlStr
   * @returns {{ok: boolean, result?: any, error?: string}}
   */
  parse(yamlStr) {
    try {
      const result = yamlToJS(yamlStr, this._getCfg(), 0, this._schema);
      return { ok: true, result };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  /**
   * Parse multi-document YAML. Accepts optional per-call schema/type overrides.
   * @param {string} yamlStr
   * @param {{schema?: Schema, types?: YamlType[]}} [opts]  Per-call schema override
   * @returns {{ok: boolean, result?: any[], error?: string}}
   */
  parseAll(yamlStr, opts) {
    try {
      let schema = this._schema;
      if (opts) {
        if (opts.schema instanceof Schema) schema = opts.schema;
        else if (Array.isArray(opts.types)) {
          schema = new Schema();
          for (const t of this._schema._types) schema.addType(t);
          for (const t of opts.types) schema.addType(t);
        }
      }
      const docs = parseAllYaml(yamlStr, this._getCfg(), schema);
      return { ok: true, result: docs };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  /**
   * Parse YAML and render a yaml-test-suite-style event tree. Always returns
   * `{ ok, result }` or `{ ok, error }` — never throws.
   * @param {string} yamlStr
   * @returns {{ok: boolean, result?: string, error?: string}}
   */
  tree(yamlStr) {
    try {
      const state = { _astOn: true, _ast: [] };
      parseAllYaml(yamlStr, this._getCfg(), this._schema, state);
      return { ok: true, result: renderTree(state._ast) };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  /**
   * Parse YAML into a nested document AST. Always returns `{ ok, result }` or
   * `{ ok, error }` — never throws.
   * @param {string} yamlStr
   * @returns {{ok: boolean, result?: any, error?: string}}
   */
  parseTree(yamlStr) {
    try {
      const state = { _astOn: true, _ast: [] };
      parseAllYaml(yamlStr, this._getCfg(), this._schema, state);
      return { ok: true, result: assembleAST(state._ast) };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  /**
   * Serialize a JS value to YAML. Always returns `{ ok, result }` or `{ ok, error }`.
   * @param {*} value
   * @param {DumpOptions} [opts]
   * @returns {{ok: boolean, result?: string, error?: string}}
   */
  dump(value, opts) {
    try {
      const result = yamlDump(value, opts);
      return { ok: true, result };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  /**
   * Parse YAML and return pretty-printed JSON.
   * @param {string} yamlStr
   * @returns {{ok: boolean, result?: string, error?: string}}
   */
  parseToJSON(yamlStr) {
    const r = this.parse(yamlStr);
    if (!r.ok) return r;
    return { ok: true, result: JSON.stringify(r.result, null, 2) };
  }

  /**
   * Validate a JS value against a schema spec.
   * @param {*} value
   * @param {*} spec
   * @returns {{ok: boolean, errors: Array<{path: string, message: string, value: any}>}}
   */
  validate(value, spec) {
    return validate(value, spec);
  }

  /**
   * Parse a YAML string and validate it against a schema spec.
   * @param {string} yamlStr
   * @param {*} spec
   * @returns {{ok: boolean, value: any, errors: Array<{path: string, message: string, value: any}>}}
   */
  validateYaml(yamlStr, spec) {
    return validateYaml(yamlStr, spec);
  }

  /**
   * Create a SAX-style streaming YAML parser bound to this instance's schema.
   * @param {{maxNodes?: number, maxAlias?: number, maxAliasDepth?: number, maxExpansion?: number, maxInputMB?: number, maxInputBytes?: number, maxStringLength?: number, maxKeys?: number, maxDepth?: number, anchors?: 'buffer'|'disable', validate?: any, abortOnError?: boolean}} [opts]
   * @returns {StreamParser}
   */
  createStream(opts) {
    return createStream(Object.assign({}, opts, { schema: this._schema }));
  }

  /**
   * Stream-parse YAML documents (single or multi-doc). Accepts a string or
   * any (async) iterable of chunks and yields each document as it completes.
   * When `opts.validate` is set, yields `{ value, errors }` per document.
   * @param {string|Iterable<string>|AsyncIterable<string>} input
   * @param {{maxNodes?: number, maxAlias?: number, maxAliasDepth?: number, maxExpansion?: number, maxInputMB?: number, maxInputBytes?: number, maxStringLength?: number, maxKeys?: number, maxDepth?: number, anchors?: 'buffer'|'disable', validate?: any, abortOnError?: boolean}} [opts]
   * @yields {*}
   */
  parseStream(input, opts) {
    return parseStream(input, Object.assign({}, opts, { schema: this._schema }));
  }
}

// ── Streaming Parser (SAX-style events) ───────────────────

const STREAM_EVENT_TYPES = Object.freeze([
  'documentStart', 'mappingStart', 'sequenceStart', 'key', 'scalar',
  'mappingEnd', 'sequenceEnd', 'documentEnd',
]);

function findKeySepTop(str, start) {
  for (let i = start || 0; i < str.length; i++) {
    if (str[i] === '#') {
      if (i === (start || 0) || str[i - 1] === ' ' || str[i - 1] === '\t') return -1;
      continue;
    }
    if (str[i] === ':') {
      if (i + 1 >= str.length || str[i + 1] === ' ' || str[i + 1] === '\t' || str[i + 1] === '}' || str[i + 1] === ']')
        return i;
    }
  }
  return -1;
}

const DEFAULT_TAG_MAP = { '!': '!', '!!': 'tag:yaml.org,2002:' };

function expandTagTop(rawTag, tagMap) {
  for (const handle of Object.keys(tagMap)) {
    if (rawTag.startsWith(handle)) {
      const suffix = rawTag.slice(handle.length);
      if (suffix.length > 0) return tagMap[handle] + suffix;
    }
  }
  return rawTag;
}

function resolveScalarTop(s, schema, tagMap) {
  const trimmed = s.replace(/[ \t]#[^\n]*$/, '').trim();
  const tagMatch = trimmed.match(/^(![^\s]+)/);
  if (tagMatch) {
    const rawTag = tagMatch[1];
    const tagVal = trimmed.slice(tagMatch[0].length).trim();
    let fullTag;
    if (rawTag.startsWith('!!')) {
      const expanded = expandTagTop(rawTag, tagMap);
      fullTag = expanded !== rawTag ? expanded : 'tag:yaml.org,2002:' + rawTag.slice(2);
    } else {
      fullTag = expandTagTop(rawTag, tagMap);
    }
    const type = schema._explicit[fullTag];
    if (type) return type.construct(tagVal);
    if (!rawTag.startsWith('!!')) return tagVal;
  }
  let val = trimmed;
  if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) return unescapeYaml(val.slice(1, -1));
  if (val.startsWith("'") && val.endsWith("'") && val.length >= 2) return val.slice(1, -1);
  val = val.replace(/[ \t]#[^\n]*$/, '');
  for (const type of schema._implicit) {
    if (type.resolve && type.resolve(val)) {
      if (type.tag === 'tag:yaml.org,2002:timestamp') continue;
      return type.construct(val);
    }
  }
  return val;
}

class StreamParser {
  constructor(opts = {}) {
    const limitKeys = ['maxNodes', 'maxAlias', 'maxAliasDepth', 'maxExpansion', 'maxInputMB', 'maxInputBytes', 'maxStringLength', 'maxKeys', 'maxDepth'];
    const cfg = getBaseConfig();
    for (const k of limitKeys) if (opts[k] !== undefined) cfg[k] = opts[k];
    if (opts.maxInputMB !== undefined) cfg.maxInputBytes = Math.round(opts.maxInputMB * 1048576);
    this.cfg = cfg;
    this.schema = opts.schema instanceof Schema ? opts.schema : DEFAULT_SCHEMA;
    this.anchorMode = opts.anchors === 'disable' ? 'disable' : 'buffer';
    this.buffered = this.anchorMode === 'buffer';

    this.validator = opts.validate !== undefined ? createStreamValidator(opts.validate) : null;
    this.abortOnValidation = !!opts.abortOnError && this.validator !== null;

    this.buffer = '';
    this.bytes = 0;
    this.lineNo = 0;
    this.ended = false;
    this.error = null;
    this.handlers = {};

    this.stack = [];
    this.docStarted = false;
    this.docClosed = false;
    this.root = undefined;
    this.rootMode = undefined;
    this._rootScalarLines = null;
    this._topFlow = null;

    this.anchors = new Map();
    this.anchorDepths = new Map();
    this.anchorSources = new Map();
    this.aliasHits = 0;
    this.produced = 0;
    this.tagMap = { ...DEFAULT_TAG_MAP };

    this.pendingScalar = null;
    this.pendingExplicitKey = null;
    this.pendingBlock = null;
    this.pendingFlow = null;
    this.retractions = 0;
  }

  // ── Public API ──────────────────────────────────────────

  on(type, cb) {
    if (typeof cb !== 'function') return this;
    (this.handlers[type] = this.handlers[type] || []).push(cb);
    return this;
  }

  off(type, cb) {
    const hs = this.handlers[type];
    if (hs) {
      const i = hs.indexOf(cb);
      if (i >= 0) hs.splice(i, 1);
    }
    return this;
  }

  write(chunk) {
    if (this.ended && this.error) throw this.error;
    if (this.ended) throw new YAMLException('stream already ended');
    try {
      if (typeof chunk !== 'string') chunk = String(chunk);
      this.bytes += byteLength(chunk);
      if (this.cfg.maxInputBytes > 0 && this.bytes > this.cfg.maxInputBytes)
        throw new YAMLException('input size exceeds limit (' + this.cfg.maxInputBytes + ' bytes)');
      this.buffer += chunk;
      let idx;
      while ((idx = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, idx);
        this.buffer = this.buffer.slice(idx + 1);
        this._feedLine(line);
      }
    } catch (e) {
      throw this._handleError(e);
    }
    return this;
  }

  end() {
    if (this.ended) return this;
    try {
      if (this.pendingBlock) this._finishBlock();
      if (this.buffer.length > 0) { this._feedLine(this.buffer); this.buffer = ''; }
      if (this.docStarted && !this.docClosed) this._closeDocument();
      if (!this.docStarted) {
        this._emit('documentStart');
        this.docStarted = true;
        this.docClosed = false;
        this._closeDocument();
      }
      this.ended = true;
      this._emit('end');
    } catch (e) {
      throw this._handleError(e);
    }
    return this;
  }

  abort(err) {
    if (this.ended) return;
    throw this._handleError(err instanceof Error ? err : new YAMLException(String(err)));
  }

  async *[Symbol.asyncIterator]() {
    const q = [];
    let waker = null;
    let closed = false;
    const onEv = (ev) => {
      if (waker) { const w = waker; waker = null; w(ev); }
      else q.push(ev);
    };
    const onEnd = () => { closed = true; if (waker) { const w = waker; waker = null; w(null); } };
    this.on('*', onEv);
    this.on('end', onEnd);
    try {
      while (true) {
        let ev;
        if (q.length) {
          ev = q.shift();
        } else if (closed) {
          if (this.error) throw this.error;
          break;
        } else {
          ev = await new Promise((res) => { waker = res; });
        }
        if (ev === null || ev === undefined) break;
        if (ev.type === 'end') break;
        if (ev.type === 'error') throw ev.error;
        yield ev;
      }
    } finally {
      this.off('*', onEv);
      this.off('end', onEnd);
    }
  }

  // ── Event plumbing ──────────────────────────────────────

  _emit(type, payload) {
    const ev = payload === undefined ? { type } : { type, ...payload };
    if (this.validator) this._feedValidator(type, payload, ev);
    const hs = this.handlers[type];
    if (hs) for (const cb of hs) cb(ev);
    const ws = this.handlers['*'];
    if (ws) for (const cb of ws) cb(ev);
    if (type === 'documentEnd' && this.buffered) {
      const dhs = this.handlers['document'];
      if (dhs) {
        const doc = this.root === undefined ? null : this.root;
        for (const cb of dhs) cb(doc);
      }
    }
  }

  // Feed SAX events into the incremental schema validator (if configured) and
  // forward any newly found violations as `violation` events. When
  // `abortOnError` is set, the first violation throws and aborts the stream.
  _feedValidator(type, payload, ev) {
    const v = this.validator;
    if (type === 'documentStart') v.documentStart();
    else if (type === 'mappingStart') v.mappingStart();
    else if (type === 'sequenceStart') v.sequenceStart();
    else if (type === 'mappingEnd') v.mappingEnd();
    else if (type === 'sequenceEnd') v.sequenceEnd();
    else if (type === 'key') v.key(payload.value);
    else if (type === 'scalar') v.scalar(payload.value);
    else if (type === 'documentEnd') {
      const newVs = v.documentEnd(this.root);
      for (const vi of newVs) this._emitViolation(vi);
      return;
    }
    const fresh = v.takeNewViolations();
    for (const vi of fresh) this._emitViolation(vi);
  }

  _emitViolation(vi) {
    const ev = { type: 'violation', path: vi.path, message: vi.message, value: vi.value };
    const hs = this.handlers['violation'];
    if (hs) for (const cb of hs) cb(ev);
    const ws = this.handlers['*'];
    if (ws) for (const cb of ws) cb(ev);
    if (this.abortOnValidation)
      throw this._err('schema validation failed at ' + vi.path + ': ' + vi.message);
  }

  _handleError(e) {
    if (this.error) return e;
    this.error = e;
    const hs = this.handlers['error'];
    if (hs) for (const cb of hs) cb({ type: 'error', error: e });
    this.ended = true;
    this._emit('end');
    return e;
  }

  _err(msg) {
    return new YAMLException('YAML at line ' + this.lineNo + ': ' + msg);
  }

  _indentOf(line) {
    let i = 0;
    while (i < line.length && line[i] === ' ') i++;
    if (i < line.length && line[i] === '\t')
      throw this._err('Tab characters are not allowed for indentation in YAML 1.2');
    return i;
  }

  _count() {
    this.produced++;
    if (this.cfg.maxNodes > 0 && this.produced > this.cfg.maxNodes)
      throw this._err('nodes limit exceeded (possible bomb) — reached ' + this.produced);
    if (this.cfg.maxExpansion > 0 && this.produced > this.cfg.maxExpansion)
      throw this._err('expansion limit exceeded (possible bomb) — reached ' + this.produced);
  }

  _checkString(v) {
    if (this.cfg.maxStringLength > 0 && typeof v === 'string' && v.length > this.cfg.maxStringLength)
      throw this._err('string length exceeds limit (' + this.cfg.maxStringLength + ')');
  }

  // ── Line feeding ────────────────────────────────────────

  _feedLine(line) {
    this.lineNo++;
    if (line.endsWith('\r')) line = line.slice(0, -1);

    if (this.pendingBlock) { this._feedBlockLine(line); return; }

    if (this.rootMode === 'flow' && this._topFlow !== null) {
      const tl = line.trim();
      if (tl !== '' && !tl.startsWith('#')) this._topFlow += '\n' + tl;
      if (this._flowBalanced(this._topFlow)) {
        const t = this._topFlow; this._topFlow = null;
        this._emitFlowRoot(t);
      }
      return;
    }

    if (this.pendingFlow !== null) {
      const tl = line.trim();
      if (tl !== '') {
        if (this._indentOf(line) < this.pendingFlow.minIndent)
          throw this._err('deficient indentation within a flow collection');
        if (!tl.startsWith('#')) this.pendingFlow.flow += '\n' + tl;
      }
      if (this._flowBalanced(this.pendingFlow.flow)) {
        const pf = this.pendingFlow; this.pendingFlow = null;
        this._emitFlow(pf.ctx, pf.flow, pf.anchor);
      }
      return;
    }

    const trimmed = line.trim();

    if (this.rootMode === 'scalar' && this._rootScalarLines !== null) {
      if (findKeySepTop(line, 0) >= 0) {
        this.rootMode = 'block';
        this._rootScalarLines = null;
        this._handleContentLine(line);
        return;
      }
      this._rootScalarLines.push(line);
      return;
    }

    if (trimmed === '' || trimmed.startsWith('#')) return;

    if (trimmed.startsWith('%')) {
      if (trimmed.startsWith('%TAG')) {
        const parts = trimmed.split(/\s+/);
        if (parts.length >= 3) this.tagMap[parts[1]] = parts[2];
      }
      return;
    }

    if (trimmed === '...' || trimmed.startsWith('... ')) {
      this._closeDocument();
      return;
    }

    if (trimmed === '---' || trimmed.startsWith('--- ')) {
      if (this.docStarted && !this.docClosed) this._closeDocument();
      this._emit('documentStart');
      this.docStarted = true;
      this.docClosed = false;
      if (trimmed.length > 4) {
        const rest = trimmed.slice(4);
        if (rest.trim() !== '' && !rest.trim().startsWith('#'))
          this._handleContentLine(rest);
      }
      return;
    }

    if (!this.docStarted) { this._emit('documentStart'); this.docStarted = true; this.docClosed = false; }

    this._handleContentLine(line);
  }

  _handleContentLine(line) {
    const indent = this._indentOf(line);
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return;

    if (this.rootMode === undefined && this.stack.length === 0 && (trimmed.startsWith('[') || trimmed.startsWith('{'))) {
      this.rootMode = 'flow';
      this._topFlow = trimmed;
      if (this._flowBalanced(trimmed)) { this._topFlow = null; this._emitFlowRoot(trimmed); }
      return;
    }
    if (this.rootMode === 'flow') return;

    if (this.pendingExplicitKey) {
      const pk = this.pendingExplicitKey;
      this.pendingExplicitKey = null;
      if (trimmed.startsWith(':')) {
        const valStr = trimmed.slice(1).trim();
        if (valStr === '' || valStr.startsWith('#')) { pk.ctx.expectValue = true; return; }
        this._handleValue(pk.ctx, valStr);
        return;
      }
      this._emitScalar(pk.ctx, null, '');
    }

    if (this.pendingScalar) {
      const pend = this.pendingScalar;
      if (pend.quote) {
        if (indent <= pend.seqIndent)
          throw this._err('deficient indentation within a quoted scalar');
        const content = line.slice(indent);
        const scan = pend.quote === '"' ? this._scanDoubleQuoteEnd(content) : this._scanSingleQuoteEnd(content);
        if (scan >= 0) {
          this.pendingScalar = null;
          const text = pend.parts.concat([content.slice(0, scan)]).join(' ');
          const v = pend.quote === '"' ? unescapeYaml(text) : text.replace(/''/g, "'");
          this._emitScalar(pend.seqCtx, v, pend.raw, pend.anchor);
          return;
        }
        pend.parts.push(content);
        return;
      }
      if (indent > pend.seqIndent) {
        if (pend.colonIdx < 0 && this._isPlainContinuation(line, indent)) {
          if (pend.lines) pend.lines.push(line);
          else pend.lines = [pend.raw, line];
          this.pendingScalar = pend;
          return;
        }
        this.pendingScalar = null;
        if (pend.colonIdx >= 0) {
          this._openSeqItemMapping(pend.seqCtx, pend.seqIndent, pend.raw, pend.colonIdx);
        } else {
          pend.seqCtx.pendingItem = true;
        }
      } else {
        this._finalizePendingScalar();
      }
    }

    while (this.stack.length) {
      const top = this.stack[this.stack.length - 1];
      if (top.indent > indent) this._closeTop();
      else break;
    }

    const top = this.stack[this.stack.length - 1] || null;

    if (top && top.plainValueLines) {
      if (indent <= top.indent && this._parseMapKey(line, indent)) {
        this._finishPlainValue(top);
      } else {
        top.plainValueLines.push(line);
        return;
      }
    }

    if (top && top.kind === 'map' && top.expectValue && indent > top.indent) {
      const flowProbe = trimmed.replace(/^&[^\s,\[\]{}]+[ \t]*/, '').replace(/^![^\s]+[ \t]*/, '');
      if (flowProbe.startsWith('[') || flowProbe.startsWith('{')) {
        const trail = this._closedFlowTrail(flowProbe);
        if (trail !== null && (trail.trim() === '' || trail.trim().startsWith('#'))) {
          this._handleBareScalar(line, indent, trimmed, top);
          return;
        }
      }
    }

    if (trimmed === '-' || trimmed.startsWith('- ')) {
      this._handleSeqItem(indent, trimmed, top);
      return;
    }

    const kp = this._parseMapKey(line, indent);
    if (kp) {
      this._handleMapKey(line, indent, top, kp);
      return;
    }

    this._handleBareScalar(line, indent, trimmed, top);
  }

  // ── Block parsing ───────────────────────────────────────

  _parseMapKey(line, indent) {
    const afterIndent = line.slice(indent);
    if (afterIndent === '?' || afterIndent.startsWith('? ')) {
      const key = afterIndent.slice(afterIndent.startsWith('? ') ? 2 : 1).trim();
      return { key, valStr: '', explicit: true, rawKey: key };
    }
    let colonIdx = -1;
    let key;
    if (afterIndent.startsWith('"')) {
      let close = -1, pos = 1;
      while (pos < afterIndent.length) {
        if (afterIndent[pos] === '\\') { pos += 2; continue; }
        if (afterIndent[pos] === '"') { close = pos; break; }
        pos++;
      }
      if (close > 0) {
        const ci = findKeySepTop(afterIndent, close);
        if (ci >= 0) { colonIdx = indent + ci; key = unescapeYaml(afterIndent.slice(1, close)); }
      }
    } else if (afterIndent.startsWith("'")) {
      let close = -1, pos = 1;
      while (pos < afterIndent.length) {
        if (afterIndent[pos] === "'" && pos + 1 < afterIndent.length && afterIndent[pos + 1] === "'") { pos += 2; continue; }
        if (afterIndent[pos] === "'") { close = pos; break; }
        pos++;
      }
      if (close > 0) {
        const ci = findKeySepTop(afterIndent, close);
        if (ci >= 0) { colonIdx = indent + ci; key = afterIndent.slice(1, close).replace(/''/g, "'"); }
      }
    }
    if (colonIdx < 0) colonIdx = findKeySepTop(line, indent);
    if (colonIdx < 0) return null;
    const rawKey = line.slice(indent, colonIdx).trim();
    if (key === undefined) {
      key = rawKey;
      const keyTagM = key.match(/^(![^\s]+)[ \t]+(.*)$/);
      if (keyTagM) key = keyTagM[2].trim() === '' ? '' : keyTagM[2].trim();
    }
    const valStr = line.slice(colonIdx + 1).trim();
    return { key, valStr, explicit: false, rawKey, colonIdx };
  }

  _handleMapKey(line, indent, top, kp) {
    let mctx;
    if (top && top.kind === 'map') {
      if (indent > top.indent && top.expectValue) {
        top.expectValue = false;
        this._emit('mappingStart');
        this._count();
        mctx = this._openMap(indent);
        mctx.anchor = top.valueAnchor;
        top.valueAnchor = null;
        this._emitMapKey(mctx, kp);
        return;
      }
      if (top.expectValue && top.pendingKey !== null) {
        top.expectValue = false;
        this._registerValueAnchor(top, null);
        this._emit('scalar', { value: null, raw: '' });
        this._count();
        this._assignValue(top, null);
      }
      mctx = top;
    } else if (top && top.kind === 'seq' && indent > top.indent) {
      this._retractSeqInline(top);
      this._emit('mappingStart');
      this._count();
      mctx = this._openMap(indent);
      this._emitMapKey(mctx, kp);
      return;
    } else {
      this._emit('mappingStart');
      this._count();
      mctx = this._openMap(indent);
      if (this.rootMode === undefined) this.rootMode = 'block';
    }
    this._emitMapKey(mctx, kp);
  }

  _emitMapKey(mctx, kp) {
    this._emit('key', { value: kp.key, raw: kp.rawKey !== undefined ? kp.rawKey : kp.key });
    this._count();
    this._checkString(kp.key);
    this._addMapKey(mctx, kp.key);
    mctx.pendingKey = kp.key;
    if (kp.explicit) {
      this.pendingExplicitKey = { ctx: mctx };
    } else {
      this._handleValue(mctx, kp.valStr);
    }
  }

  _addMapKey(ctx, key) {
    if (this.cfg.maxKeys > 0 && ctx.keys.size >= this.cfg.maxKeys)
      throw this._err('mapping keys limit exceeded (' + this.cfg.maxKeys + ')');
    if (key === '<<') {
      ctx.mergeOverride = new Set(ctx.keys);
    } else if (ctx.keys.has(key)) {
      throw this._err('Duplicate key: "' + key + '"');
    }
    ctx.keys.add(key);
  }

  _handleSeqItem(indent, trimmed, top) {
    let seqCtx;
    if (top && top.kind === 'map' && top.expectValue && indent > top.indent) {
      top.expectValue = false;
      this._emit('sequenceStart');
      this._count();
      seqCtx = this._openSeq(indent);
      seqCtx.valueAnchor = top.valueAnchor;
      top.valueAnchor = null;
    } else if (top && top.kind === 'seq' && top.indent === indent) {
      seqCtx = top;
    } else {
      this._retractSeqInline(top);
      this._emit('sequenceStart');
      this._count();
      seqCtx = this._openSeq(indent);
    }
    if (this.rootMode === undefined) this.rootMode = 'block';

    if (seqCtx.pendingItem && indent === seqCtx.indent) {
      seqCtx.pendingItem = false;
      if (seqCtx.pendingEmpty) {
        seqCtx.pendingEmpty = false;
        this._emitScalar(seqCtx, null, '');
      }
    }

    const item = trimmed.slice(2);
    if (item.trim() === '') {
      seqCtx.pendingItem = true;
      seqCtx.pendingEmpty = true;
      return;
    }
    if (item === '-' || item.startsWith('- ')) {
      seqCtx.pendingItem = true;
      this._emit('sequenceStart');
      this._count();
      const inner = this._openSeq(indent + 2);
      this._handleSeqItem(indent + 2, item, inner);
      return;
    }
    if (item.startsWith('[') || item.startsWith('{')) {
      if (!this._flowBalanced(item)) {
        this.pendingFlow = { ctx: seqCtx, anchor: null, flow: item, minIndent: seqCtx.indent + 1 };
        return;
      }
      this._emitFlow(seqCtx, item, null);
      return;
    }
    if (item.startsWith('&') || item.startsWith('*')) {
      this._handleValue(seqCtx, item);
      return;
    }
    const ci = findKeySepTop(item);
    if (ci >= 0 && item[ci + 1] === ' ') {
      this._openSeqItemMapping(seqCtx, indent, item, ci);
      return;
    }
    if (ci >= 0 && item[ci + 1] === undefined) {
      const key = item.slice(0, ci).trim();
      this.pendingScalar = { seqCtx, seqIndent: indent, value: key + ':', raw: item, anchor: null, colonIdx: ci, lines: null, quote: null, parts: null };
      return;
    }
    const itemTrim = item.trim();
    if (itemTrim[0] === '"' && this._scanDoubleQuoteEnd(itemTrim, 1) < 0) {
      this.pendingScalar = { seqCtx, seqIndent: indent, value: null, raw: itemTrim, anchor: null, colonIdx: -1, lines: null, quote: '"', parts: [itemTrim.slice(1)] };
      return;
    }
    if (itemTrim[0] === "'" && this._scanSingleQuoteEnd(itemTrim, 1) < 0) {
      this.pendingScalar = { seqCtx, seqIndent: indent, value: null, raw: itemTrim, anchor: null, colonIdx: -1, lines: null, quote: "'", parts: [itemTrim.slice(1)] };
      return;
    }
    const v = resolveScalarTop(item, this.schema, this.tagMap);
    this.pendingScalar = { seqCtx, seqIndent: indent, value: v, raw: item, anchor: null, colonIdx: -1, lines: null, quote: null, parts: null };
  }

  _openSeqItemMapping(seqCtx, indent, item, ci) {
    this._emit('mappingStart');
    this._count();
    const vm = this._openMap(indent + 2);
    if (this.buffered) seqCtx.pendingItem = true;
    const kp = this._parseMapKey(item, 0);
    const key = kp ? kp.key : item.slice(0, ci).trim();
    const valStr = kp ? kp.valStr : item.slice(ci + 1).trim();
    this._emit('key', { value: key, raw: key });
    this._count();
    this._checkString(key);
    this._addMapKey(vm, key);
    vm.pendingKey = key;
    if (kp && kp.explicit) {
      this.pendingExplicitKey = { ctx: vm };
    } else {
      this._handleValue(vm, valStr);
    }
  }

  _handleBareScalar(line, indent, trimmed, top) {
    if (top === null && this.stack.length === 0) {
      if (this.rootMode === undefined) {
        const raw = line.slice(indent);
        if (raw === '-' || raw.startsWith('- ') || raw.startsWith('? ') ||
            /^[&*!]/.test(raw) || /^[|>]/.test(raw)) {
          this.rootMode = 'block';
          if (raw === '-' || raw.startsWith('- ') || raw.startsWith('? ')) this._handleContentLine(line);
          return;
        }
        this.rootMode = 'scalar';
        this._rootScalarLines = [line];
      }
      return;
    }
    if (top && top.kind === 'map' && top.expectValue && indent > top.indent) {
      top.expectValue = false;
      const flowProbe = trimmed.replace(/^&[^\s,\[\]{}]+[ \t]*/, '').replace(/^![^\s]+[ \t]*/, '');
      if (flowProbe.startsWith('[') || flowProbe.startsWith('{')) {
        this._handleValue(top, trimmed);
        if (this.pendingFlow) this.pendingFlow.minIndent = indent;
        return;
      }
      top.plainValueLines = [line];
      return;
    }
    if (top && top.kind === 'seq' && indent > top.indent) {
      const flowProbe = trimmed.replace(/^&[^\s,\[\]{}]+[ \t]*/, '').replace(/^![^\s]+[ \t]*/, '');
      if (flowProbe.startsWith('[') || flowProbe.startsWith('{')) {
        this._handleValue(top, trimmed);
        if (this.pendingFlow) this.pendingFlow.minIndent = indent;
        return;
      }
      const v = resolveScalarTop(trimmed, this.schema, this.tagMap);
      if (this.buffered && top.lastInlineIndex >= 0) {
        top.node[top.lastInlineIndex] = v;
        top.lastInlineIndex = -1;
        this._count();
        this._checkString(v);
        this._emit('scalar', { value: v, raw: trimmed });
        return;
      }
      this._emitScalar(top, v, trimmed);
      return;
    }
  }

  // ── Contexts / stack ────────────────────────────────────

  _openMap(indent) {
    if (this.cfg.maxDepth > 0 && this.stack.length > this.cfg.maxDepth)
      throw this._err('nesting depth exceeds limit (' + this.cfg.maxDepth + ')');
    const ctx = {
      kind: 'map', indent, keys: new Set(), pendingKey: null, expectValue: false,
      valueAnchor: null, anchor: null, mergeOverride: null, plainValueLines: null,
      node: this.buffered ? {} : null,
    };
    this.stack.push(ctx);
    return ctx;
  }

  _openSeq(indent) {
    if (this.cfg.maxDepth > 0 && this.stack.length > this.cfg.maxDepth)
      throw this._err('nesting depth exceeds limit (' + this.cfg.maxDepth + ')');
    const ctx = {
      kind: 'seq', indent, pendingItem: false, pendingEmpty: false, valueAnchor: null, anchor: null,
      lastInlineIndex: -1, replaceInline: -1,
      node: this.buffered ? [] : null,
    };
    this.stack.push(ctx);
    return ctx;
  }

  _closeTop() {
    const ctx = this.stack.pop();
    if (ctx.kind === 'map') {
      this._finishPlainValue(ctx);
      if (ctx.pendingKey !== null) {
        this._registerValueAnchor(ctx, null);
        this._emit('scalar', { value: null, raw: '' });
        this._count();
        this._assignValue(ctx, null);
      }
      this._finalizeMap(ctx);
      if (ctx.anchor) this._registerAnchor(ctx.anchor, ctx.node);
      this._emit('mappingEnd');
      this._attachToParent(ctx);
    } else {
      if (ctx.pendingItem) {
        ctx.pendingItem = false;
        if (ctx.pendingEmpty) {
          ctx.pendingEmpty = false;
          this._emitScalar(ctx, null, '');
        }
      }
      if (ctx.anchor) this._registerAnchor(ctx.anchor, ctx.node);
      this._emit('sequenceEnd');
      this._attachToParent(ctx);
    }
  }

  _closeAll() {
    if (this.pendingExplicitKey) {
      const pk = this.pendingExplicitKey;
      this.pendingExplicitKey = null;
      this._emitScalar(pk.ctx, null, '');
    }
    if (this.pendingScalar) this._finalizePendingScalar();
    while (this.stack.length) this._closeTop();
  }

  _closeDocument() {
    if (!this.docStarted || this.docClosed) return;
    if (this.pendingBlock) this._finishBlock();
    if (this.rootMode === 'scalar') {
      const lines = this._rootScalarLines || [];
      const f0 = (lines[0] || '').trim();
      let text;
      const multiQuoted = (f0[0] === '"' || f0[0] === "'") &&
        (f0[0] === '"' ? this._scanDoubleQuoteEnd(f0, 1) : this._scanSingleQuoteEnd(f0, 1)) < 0;
      text = multiQuoted ? this._foldQuotedRoot(lines) : this._foldRootScalarLines(lines);
      const v = resolveScalarTop(text, this.schema, this.tagMap);
      this._checkString(v);
      this._count();
      this.root = v;
      this._emit('scalar', { value: v, raw: lines.join('\n') });
    } else if (this.rootMode === 'flow') {
      if (this._topFlow !== null) {
        const t = this._topFlow; this._topFlow = null;
        if (this._flowBalanced(t))
          this._emitFlowRoot(t);
        else
          throw this._err('unexpected end of the stream within a flow ' + (t[0] === '{' ? 'mapping' : 'sequence'));
      }
    }
    if (this.pendingFlow !== null) {
      const pf = this.pendingFlow; this.pendingFlow = null;
      if (this._flowBalanced(pf.flow))
        this._emitFlow(pf.ctx, pf.flow, pf.anchor);
      else
        throw this._err('unexpected end of the stream within a flow ' + (pf.flow[0] === '{' ? 'mapping' : 'sequence'));
    }
    this._closeAll();
    this._emit('documentEnd');
    this.docClosed = true;
  }

  _finishPlainValue(ctx) {
    if (!ctx.plainValueLines) return;
    const lines = ctx.plainValueLines;
    ctx.plainValueLines = null;
    const text = this._foldScalarLines(lines);
    const v = resolveScalarTop(text, this.schema, this.tagMap);
    this._registerValueAnchor(ctx, v);
    this._emitScalar(ctx, v, text);
  }

  _assignValue(ctx, value) {
    if (ctx.kind === 'map') {
      if (ctx.pendingKey !== null) {
        if (this.buffered) {
          if (ctx.pendingKey === '<<') ctx.node['<<'] = value;
          else safeAssign(ctx.node, ctx.pendingKey, value);
        }
        ctx.pendingKey = null;
      }
    } else if (ctx.kind === 'seq') {
      if (this.buffered) {
        ctx.node.push(value);
        ctx.lastInlineIndex = ctx.node.length - 1;
      }
      ctx.pendingItem = false;
      ctx.pendingEmpty = false;
    }
  }

  _retractSeqInline(seqCtx) {
    if (!seqCtx || seqCtx.kind !== 'seq' || !this.buffered || seqCtx.lastInlineIndex < 0) return;
    seqCtx.node.pop();
    seqCtx.replaceInline = seqCtx.lastInlineIndex;
    seqCtx.lastInlineIndex = -1;
    this.retractions++;
  }

  _attachToParent(ctx) {
    if (!this.buffered) return;
    const top = this.stack[this.stack.length - 1];
    if (!top) { this.root = ctx.node; return; }
    if (top.kind === 'map') {
      if (top.pendingKey !== null) {
        safeAssign(top.node, top.pendingKey, ctx.node);
        top.pendingKey = null;
      }
    } else if (top.kind === 'seq') {
      if (top.pendingItem) {
        top.node.push(ctx.node);
        top.pendingItem = false;
        top.pendingEmpty = false;
      } else if (top.replaceInline >= 0) {
        top.node[top.replaceInline] = ctx.node;
        top.replaceInline = -1;
      } else if (ctx.indent > top.indent) {
        top.node.push(ctx.node);
      }
    }
  }

  _finalizeMap(ctx) {
    if (!this.buffered) return;
    const v = ctx.node;
    if (v['<<'] !== undefined) {
      const merged = {};
      const sources = Array.isArray(v['<<']) ? v['<<'] : [v['<<']];
      for (const src of sources) {
        if (src && typeof src === 'object' && !Array.isArray(src)) {
          for (const sk of Object.keys(src)) {
            if (!(sk in merged) && sk !== '<<') {
              if (ctx.mergeOverride && ctx.mergeOverride.has(sk))
                throw new YAMLException('Merge key << overwrites existing key "' + sk + '"');
              safeAssign(merged, sk, src[sk]);
            }
          }
        }
      }
      for (const k of Object.keys(v)) {
        if (k !== '<<') safeAssign(merged, k, v[k]);
      }
      ctx.node = merged;
    }
  }

  // ── Values: block scalar, flow, anchors, aliases ─────────

  _handleValue(ctx, valStr) {
    let anchor = null;
    let rest = valStr.trim();
    const am = rest.match(/^&([^ \t,\[\]{}]+)\s*(.*)/);
    if (am) { anchor = am[1]; rest = am[2].trim(); }
    if (this.anchorMode === 'disable' && anchor) throw this._err('anchors are disabled in streaming mode');
    if (anchor && rest.startsWith('*')) {
      const v = this._resolveAlias(rest.slice(1).trim());
      this._emitScalar(ctx, v, valStr, anchor, rest.slice(1).trim());
      return;
    }
    if (rest === '' || rest.startsWith('#')) {
      ctx.expectValue = true;
      ctx.valueAnchor = anchor;
      return;
    }
    if (rest.startsWith('*')) {
      const name = rest.slice(1).split(/[ ,}\]]/)[0];
      const v = this._resolveAlias(name);
      this._emitScalar(ctx, v, valStr, anchor);
      return;
    }
    const valForBlock = rest.replace(/^![^\s]+\s*/, '');
    const blockMatch = valForBlock.match(/^(\||>)(\d*)([\-+]?)$/);
    if (blockMatch && valForBlock.trim() === blockMatch[0]) {
      const full = blockMatch[0];
      this.pendingBlock = {
        ctx, indent: ctx.indent, style: full[0],
        chomp: full.endsWith('-') ? 'strip' : full.endsWith('+') ? 'keep' : 'clip',
        lines: [], contentIndent: null, anchor,
      };
      return;
    }
    if (rest.startsWith('[') || rest.startsWith('{')) {
      if (!this._flowBalanced(rest)) {
        this.pendingFlow = { ctx, anchor, flow: rest, minIndent: (ctx ? ctx.indent : 0) + 1 };
        return undefined;
      }
      return this._emitFlow(ctx, rest, anchor);
    }
    if (rest[0] === '"' && this._scanDoubleQuoteEnd(rest, 1) < 0) {
      this.pendingScalar = { seqCtx: ctx, seqIndent: ctx.indent, value: null, raw: rest, anchor, colonIdx: -1, lines: null, quote: '"', parts: [rest.slice(1)] };
      return;
    }
    if (rest[0] === "'" && this._scanSingleQuoteEnd(rest, 1) < 0) {
      this.pendingScalar = { seqCtx: ctx, seqIndent: ctx.indent, value: null, raw: rest, anchor, colonIdx: -1, lines: null, quote: "'", parts: [rest.slice(1)] };
      return;
    }
    const v = resolveScalarTop(rest, this.schema, this.tagMap);
    if (rest[0] !== '"' && rest[0] !== "'" && ctx && ctx.kind === 'map' && ctx.pendingKey !== null) {
      this.pendingScalar = { seqCtx: ctx, seqIndent: ctx.indent, value: v, raw: rest, anchor, colonIdx: -1, lines: null, quote: null, parts: null };
      return;
    }
    this._emitScalar(ctx, v, valStr, anchor);
  }

  _registerValueAnchor(ctx, value) {
    if (ctx.valueAnchor) {
      this._registerAnchor(ctx.valueAnchor, value);
      ctx.valueAnchor = null;
    }
  }

  _emitScalar(ctx, value, raw, anchor, srcAnchor) {
    if (anchor) this._registerAnchor(anchor, value, srcAnchor);
    this._count();
    this._checkString(value);
    this._emit('scalar', { value, raw });
    this._assignValue(ctx, value);
  }

  _registerAnchor(name, value, sourceAnchor) {
    if (this.anchorMode === 'disable') throw this._err('anchors are disabled in streaming mode');
    let depth = 0;
    if (sourceAnchor) {
      const sd = this.anchorDepths.get(sourceAnchor);
      depth = (sd === undefined ? 0 : sd) + 1;
      let cur = sourceAnchor;
      while (cur) {
        if (cur === name)
          throw new YAMLException('YAML: circular alias detected — "' + name + '"');
        cur = this.anchorSources.get(cur);
      }
    }
    if (depth > this.cfg.maxAliasDepth)
      throw new YAMLException('YAML: alias depth exceeds limit (' + this.cfg.maxAliasDepth + '), possible anchor bomb');
    this.anchors.set(name, value);
    this.anchorDepths.set(name, depth);
    if (sourceAnchor) this.anchorSources.set(name, sourceAnchor);
  }

  _resolveAlias(name) {
    if (this.anchorMode === 'disable') throw this._err('aliases are disabled in streaming mode');
    if (++this.aliasHits > this.cfg.maxAlias)
      throw this._err('YAML: alias expansion limit exceeded (bomb)');
    const v = this.anchors.get(name);
    if (v === undefined) return name;
    return v;
  }

  _feedBlockLine(line) {
    const pb = this.pendingBlock;
    const indent = this._indentOf(line);
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) { pb.lines.push(''); return; }
    if (indent <= pb.indent) {
      this._finishBlock();
      this._handleContentLine(line);
      return;
    }
    if (pb.contentIndent === null) pb.contentIndent = indent;
    pb.lines.push(line.slice(pb.contentIndent));
  }

  _finishBlock() {
    const pb = this.pendingBlock;
    this.pendingBlock = null;
    const { style, chomp, lines } = pb;
    let text;
    if (style === '|') {
      text = lines.join('\n');
      if (chomp === 'keep') text = text + '\n';
      else if (chomp !== 'strip') text = text + '\n';
      text = chomp === 'strip' ? text.replace(/\n+$/, '') : text;
    } else {
      const folded = [];
      let li = 0;
      while (li < lines.length) {
        if (lines[li] === '') { folded.push(''); li++; }
        else {
          let accum = lines[li];
          li++;
          while (li < lines.length && lines[li] !== '') { accum += ' ' + lines[li]; li++; }
          folded.push(accum);
        }
      }
      text = folded.join('\n');
      if (chomp === 'keep') text = text.replace(/\n*$/, '') + '\n';
      else if (chomp === 'strip') text = text.replace(/\n+$/, '');
      else text = text.replace(/\n*$/, '\n');
    }
    this._checkString(text);
    this._count();
    this._emit('scalar', { value: text, raw: text });
    if (pb.anchor) this._registerAnchor(pb.anchor, text);
    this._assignValue(pb.ctx, text);
  }

  // ── Flow parsing ────────────────────────────────────────

  _flowBalanced(str) {
    let depth = 0;
    let inS = false, inD = false, esc = false;
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (inD) {
        if (esc) esc = false;
        else if (ch === '\\') esc = true;
        else if (ch === '"') inD = false;
        continue;
      }
      if (inS) {
        if (ch === "'" && str[i + 1] === "'") { i++; continue; }
        if (ch === "'") inS = false;
        continue;
      }
      if (ch === '"') { inD = true; continue; }
      if (ch === "'") { inS = true; continue; }
      if (ch === '#' && (i === 0 || str[i - 1] === ' ' || str[i - 1] === '\t' || str[i - 1] === '\n')) {
        while (i < str.length && str[i] !== '\n') i++;
        continue;
      }
      if (ch === '[' || ch === '{') depth++;
      else if (ch === ']' || ch === '}') { depth--; if (depth < 0) return false; }
    }
    return depth === 0 && !inS && !inD;
  }

  _closedFlowTrail(str) {
    let depth = 0;
    let inS = false, inD = false, esc = false;
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (inD) {
        if (esc) esc = false;
        else if (ch === '\\') esc = true;
        else if (ch === '"') inD = false;
        continue;
      }
      if (inS) {
        if (ch === "'" && str[i + 1] === "'") { i++; continue; }
        if (ch === "'") inS = false;
        continue;
      }
      if (ch === '"') { inD = true; continue; }
      if (ch === "'") { inS = true; continue; }
      if (ch === '[' || ch === '{') depth++;
      else if (ch === ']' || ch === '}') {
        depth--;
        if (depth === 0) return str.slice(i + 1);
      }
    }
    return null;
  }

  _emitFlow(ctx, str, anchor) {
    const r = this._parseFlowEmitting(str, 0);
    if (anchor) this._registerAnchor(anchor, r.value);
    this._assignValue(ctx, r.value);
    this._registerValueAnchor(ctx, r.value);
    return r.value;
  }

  _emitFlowRoot(str) {
    const r = this._parseFlowEmitting(str, 0);
    this.root = r.value;
  }

  _flowScalar(val, raw) {
    this._count();
    this._checkString(val);
    this._emit('scalar', { value: val, raw });
    return val;
  }

  _parseFlowEmitting(s, _depth) {
    if (_depth === undefined) _depth = 0;
    if (_depth > 100) throw this._err('flow nesting too deep (>100)');
    s = s.trim();
    if (s.startsWith('[')) {
      const items = [];
      let i = 1;
      let afterComma = true;
      this._emit('sequenceStart');
      this._count();
      while (i < s.length) {
        const c = s[i];
        if (c === ']') {
          this._emit('sequenceEnd');
          return { value: items, endPos: i + 1 };
        }
        if (c === ',' || c === ' ' || c === '\n' || c === '\t') {
          if (c === ',') {
            if (afterComma) throw this._err('unexpected comma in flow sequence');
            afterComma = true;
          }
          i++; continue;
        }
        if (c === '#') {
          while (i < s.length && s[i] !== '\n') i++;
          continue;
        }
        const r = this._parseFlowEmitting(s.slice(i), _depth + 1);
        items.push(r.value);
        i += r.endPos;
        afterComma = false;
      }
      this._emit('sequenceEnd');
      return { value: items, endPos: s.length };
    }
    if (s.startsWith('{')) {
      const obj = {};
      const seen = new Set();
      let i = 1;
      let needKey = true;
      this._emit('mappingStart');
      this._count();
      while (i < s.length) {
        const c = s[i];
        if (c === '}') {
          this._emit('mappingEnd');
          return { value: obj, endPos: i + 1 };
        }
        if (c === ',' || c === ' ' || c === '\n' || c === '\t') {
          if (c === ',') {
            if (needKey) throw this._err('unexpected comma in flow mapping');
            needKey = true;
          }
          i++; continue;
        }
        if (c === '#') {
          while (i < s.length && s[i] !== '\n') i++;
          continue;
        }
        let key;
        if (s[i] === '"' || s[i] === "'") {
          const quote = s[i];
          let close = -1, pos = i + 1;
          if (quote === '"') {
            while (pos < s.length) { if (s[pos] === '\\') { pos += 2; continue; } if (s[pos] === '"') { close = pos; break; } pos++; }
          } else {
            while (pos < s.length) { if (s[pos] === "'" && pos + 1 < s.length && s[pos + 1] === "'") { pos += 2; continue; } if (s[pos] === "'") { close = pos; break; } pos++; }
          }
          if (close < 0) { this._emit('mappingEnd'); return { value: obj, endPos: s.length }; }
          key = s.slice(i + 1, close);
          if (quote === '"') key = unescapeYaml(key);
          i = close + 1;
        } else {
          let j = i;
          while (j < s.length && s[j] !== ':' && s[j] !== ',' && s[j] !== '}' && s[j] !== '\n') j++;
          key = s.slice(i, j).trim();
          i = j;
        }
        if (this.cfg.maxKeys > 0 && seen.size >= this.cfg.maxKeys)
          throw this._err('inline mapping keys limit exceeded (' + this.cfg.maxKeys + ')');
        if (seen.has(key)) throw this._err('Duplicate key: "' + key + '"');
        seen.add(key);
        while (i < s.length && (s[i] === ' ' || s[i] === '\t' || s[i] === '\n' || s[i] === ':')) i++;
        this._emit('key', { value: key, raw: key });
        this._count();
        const r = this._parseFlowEmitting(s.slice(i), _depth + 1);
        safeAssign(obj, key, r.value);
        i += r.endPos;
        needKey = false;
      }
      this._emit('mappingEnd');
      return { value: obj, endPos: s.length };
    }
    if (s.startsWith('&')) {
      const nameEnd = s.slice(1).search(/[ \t\n\r,\[\]{}]/);
      if (nameEnd < 0) {
        const aname = s.slice(1);
        if (this.anchorMode === 'disable') throw this._err('anchors are disabled in streaming mode');
        this._registerAnchor(aname, null);
        this._flowScalar(null, s);
        return { value: null, endPos: s.length };
      }
      const aname = s.slice(1, 1 + nameEnd);
      const afterName = s.slice(1 + nameEnd);
      const rest = afterName.trim();
      const wsLen = afterName.length - rest.length;
      if (this.anchorMode === 'disable') throw this._err('anchors are disabled in streaming mode');
      if (rest) {
        const r = this._parseFlowEmitting(rest, _depth + 1);
        this._registerAnchor(aname, r.value);
        return { value: r.value, endPos: 1 + aname.length + wsLen + r.endPos };
      }
      this._registerAnchor(aname, null);
      this._flowScalar(null, s);
      return { value: null, endPos: 1 + aname.length + wsLen };
    }
    if (s.startsWith('*')) {
      const aname = s.slice(1).split(/[ ,}\]]/)[0];
      const v = this._resolveAlias(aname);
      this._flowScalar(v, s);
      return { value: v, endPos: aname.length + 1 };
    }
    const tagPrefix = s.match(/^(![^\s]+)\s+/);
    if (tagPrefix) {
      const rawTag = tagPrefix[1];
      const rest = s.slice(tagPrefix[0].length);
      const r = this._parseFlowEmitting(rest, _depth + 1);
      let val = r.value;
      let fullTag;
      if (rawTag.startsWith('!!')) {
        const expanded = expandTagTop(rawTag, this.tagMap);
        fullTag = expanded !== rawTag ? expanded : 'tag:yaml.org,2002:' + rawTag.slice(2);
      } else {
        fullTag = expandTagTop(rawTag, this.tagMap);
      }
      const type = this.schema._explicit[fullTag];
      if (!type) {
        if (!rawTag.startsWith('!!')) {
          const v = resolveScalarTop(s, this.schema, this.tagMap);
          this._flowScalar(v, s);
          return { value: v, endPos: s.length };
        }
      } else {
        val = type.construct(String(val));
      }
      this._flowScalar(val, s);
      return { value: val, endPos: tagPrefix[0].length + r.endPos };
    }
    if (s.startsWith('"')) {
      let close = -1, pos = 1;
      while (pos < s.length) { if (s[pos] === '\\') { pos += 2; continue; } if (s[pos] === '"') { close = pos; break; } pos++; }
      if (close > 0) { const inner = s.slice(1, close); return { value: this._flowScalar(unescapeYaml(inner), s), endPos: close + 1 }; }
    }
    if (s.startsWith("'")) {
      let close = -1, pos = 1;
      while (pos < s.length) { if (s[pos] === "'" && pos + 1 < s.length && s[pos + 1] === "'") { pos += 2; continue; } if (s[pos] === "'") { close = pos; break; } pos++; }
      if (close > 0) { const v = s.slice(1, close).replace(/''/g, "'"); return { value: this._flowScalar(v, s), endPos: close + 1 }; }
    }
    let end = s.search(/[,})\]\n]/);
    if (end < 0) {
      let raw = s;
      const hv = raw.search(/#(?=[ \t])/);
      if (hv >= 0) raw = raw.slice(0, hv).trimEnd();
      const v = resolveScalarTop(raw, this.schema, this.tagMap);
      return { value: this._flowScalar(v, raw), endPos: s.length };
    }
    if (end === 0) { const v = resolveScalarTop(s, this.schema, this.tagMap); return { value: this._flowScalar(v, s), endPos: s.length }; }
    let raw = s.slice(0, end);
    if (raw.endsWith(' ')) raw = raw.trimEnd();
    const v = resolveScalarTop(raw, this.schema, this.tagMap);
    return { value: this._flowScalar(v, raw), endPos: end };
  }

  _isPlainContinuation(line, indent) {
    const c = line.slice(indent);
    if (c === '' || c.startsWith('#') || c === '-' || c.startsWith('- ') || c === '?' || c.startsWith('? ') ||
        c.startsWith('&') || c.startsWith('*') || c.startsWith('!') || c.startsWith('|') || c.startsWith('>') ||
        c.startsWith('[') || c.startsWith('{')) return false;
    if (findKeySepTop(c) >= 0) return false;
    return true;
  }

  _scanDoubleQuoteEnd(s, from = 0) {
    let i = from;
    while (i < s.length) {
      if (s[i] === '\\') { i += 2; continue; }
      if (s[i] === '"') return i;
      i++;
    }
    return -1;
  }

  _scanSingleQuoteEnd(s, from = 0) {
    let i = from;
    while (i < s.length) {
      if (s[i] === "'") {
        if (s[i + 1] === "'") { i += 2; continue; }
        return i;
      }
      i++;
    }
    return -1;
  }

  _foldQuotedRoot(lines) {
    const quote = lines[0].trim()[0];
    let text = lines[0].trim().slice(1);
    for (let i = 1; i < lines.length; i++) {
      const c = lines[i].trim();
      const close = quote === '"' ? this._scanDoubleQuoteEnd(c) : this._scanSingleQuoteEnd(c);
      if (close >= 0) { text += ' ' + c.slice(0, close); break; }
      text += ' ' + c;
    }
    return quote === '"' ? unescapeYaml(text) : text.replace(/''/g, "'");
  }

  _finalizePendingScalar() {
    const pend = this.pendingScalar;
    this.pendingScalar = null;
    if (!pend) return;
    if (pend.lines) {
      const text = this._foldScalarLines(pend.lines);
      const v = resolveScalarTop(text, this.schema, this.tagMap);
      this._emitScalar(pend.seqCtx, v, pend.raw, pend.anchor);
      return;
    }
    if (pend.quote) {
      const text = pend.parts.join(' ');
      const v = pend.quote === '"' ? unescapeYaml(text) : text.replace(/''/g, "'");
      this._emitScalar(pend.seqCtx, v, pend.raw, pend.anchor);
      return;
    }
    this._emitScalar(pend.seqCtx, pend.value, pend.raw, pend.anchor);
  }

  _foldRootScalarLines(lines) {
    const out = [];
    let buf = null;
    for (const l of lines) {
      const t = l.trim();
      if (t === '') {
        if (buf !== null) out.push(buf);
        buf = null;
        out.push('');
        continue;
      }
      buf = buf === null ? t : buf + ' ' + t;
    }
    if (buf !== null) out.push(buf);
    return out.join('\n');
  }

  _foldScalarLines(lines) {
    const folded = [];
    let i = 0;
    while (i < lines.length) {
      if (lines[i].trim() === '') { folded.push(''); i++; }
      else {
        let accum = lines[i];
        i++;
        while (i < lines.length && (lines[i].trim() === '' || lines[i].startsWith(' '))) {
          if (lines[i].trim() === '') { folded.push(accum); accum = ''; i++; }
          else { accum += ' ' + lines[i].trim(); i++; }
        }
        folded.push(accum);
      }
    }
    return folded.join('\n');
  }
}

/**
 * Create a SAX-style streaming YAML parser.
 * Feed chunks with `.write(chunk)`, finish with `.end()`, consume events
 * via `.on(type, cb)` or `for await`. Every event is `{ type, ... }`.
 * Event types: documentStart, mappingStart, sequenceStart, key, scalar,
 * mappingEnd, sequenceEnd, documentEnd, error, end.
 * @param {{maxNodes?: number, maxAlias?: number, maxAliasDepth?: number, maxExpansion?: number, maxInputMB?: number, maxInputBytes?: number, maxStringLength?: number, maxKeys?: number, maxDepth?: number, anchors?: 'buffer'|'disable', schema?: Schema}} [opts]
 * @returns {StreamParser}
 */
export function createStream(opts = {}) {
  return new StreamParser(opts);
}

/**
 * Stream-parse YAML documents (single or multi-doc, `---`-separated).
 * Accepts a string or any (async) iterable of string chunks. Yields each
 * parsed document as it completes. Security limits are enforced while
 * streaming, so a malicious document is rejected before the whole input
 * is consumed.
 * @param {string|Iterable<string>|AsyncIterable<string>} input
 * @param {{maxNodes?: number, maxAlias?: number, maxAliasDepth?: number, maxExpansion?: number, maxInputMB?: number, maxInputBytes?: number, maxStringLength?: number, maxKeys?: number, maxDepth?: number, anchors?: 'buffer'|'disable', schema?: Schema}} [opts]
 * @yields {*} Parsed document
 */
export async function* parseStream(input, opts = {}) {
  const parser = new StreamParser(opts);
  const withValidation = opts.validate !== undefined;
  const queue = [];
  let waker = null;
  let closed = false;
  parser.on('document', (doc) => {
    const out = withValidation
      ? { value: doc, errors: parser.validator ? parser.validator.finalErrors : [] }
      : doc;
    if (waker) { const w = waker; waker = null; w(out); }
    else queue.push(out);
  });
  parser.on('end', () => {
    closed = true;
    if (waker) { const w = waker; waker = null; w(undefined); }
  });

  const drain = function* () { while (queue.length) yield queue.shift(); };

  if (typeof input === 'string') {
    parser.write(input);
    parser.end();
  } else {
    for await (const chunk of input) {
      parser.write(chunk);
      yield* drain();
    }
    parser.end();
  }
  yield* drain();
  if (parser.error) throw parser.error;
  while (true) {
    if (parser.error) throw parser.error;
    if (queue.length) yield queue.shift();
    else if (closed) break;
    else await new Promise((res) => { waker = res; });
  }
}

YamlSecurity.setLimits = setLimits;

// ── Internal helpers shared with the streaming module ─────

/** @internal */
export function getBaseConfig() {
  return { ..._baseCfg };
}

/** @internal */
export { DEFAULT_SCHEMA, unescapeYaml, byteLength };

// ── Schema validation (see src/validate.js) ──────────────

export {
  s, string, int, number, float, bool, nullType, any, never,
  enumType, timestamp, array, tuple, object, record,
  optional, nullable, oneOf, anyOf, allOf, not, custom,
  validate, createStreamValidator, fromJSONSchema, toJSONSchema,
};
