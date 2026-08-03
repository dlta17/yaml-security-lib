// ────────────────────────────────────────────────────────
// YAML Security Lib — Safe YAML Parser & Dumper
// Zero dependencies. Works in Node ≥16 and modern browsers.
// ────────────────────────────────────────────────────────

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
  '_': '\xa0', 'L': '\u2028', 'P': '\u2029',
};
function unescapeYaml(s) {
  return s.replace(/\\(x[\da-fA-F]{1,2}|u[\da-fA-F]{4}|U[\da-fA-F]{8}|.)/g, (m, seq) => {
    const ch = seq[0];
    if (ch === 'x') return String.fromCharCode(parseInt(seq.slice(1), 16));
    if (ch === 'u') return String.fromCharCode(parseInt(seq.slice(1), 16));
    if (ch === 'U') {
      const cp = parseInt(seq.slice(1), 16);
      return cp > 0xFFFF ? String.fromCharCode(0xD800 + ((cp - 0x10000) >> 10), 0xDC00 + ((cp - 0x10000) & 0x3FF)) : String.fromCharCode(cp);
    }
    return ESC_MAP[ch] !== undefined ? ESC_MAP[ch] : ch;
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

// ── YAML Parser ──────────────────────────────────────────

function yamlToJS(yamlStr, cfg, _depth, _schema, _state) {
  if (_depth === undefined) _depth = 0;
  if (_schema === undefined) _schema = _baseSchema;
  if (_depth > 50) throw new YAMLException('YAML: recursion too deep (>50) — possible anchor bomb');
  if (byteLength(yamlStr) > cfg.maxInputBytes) {
    throw new YAMLException('YAML: input too large (>' + Math.round(cfg.maxInputBytes / 1048576 * 10) / 10 + 'MB)');
  }

  const state = _state || {
    produced: 0,
    aliasHits: 0,
    anchors: {},
    anchorDepths: {},
    anchorSources: {},
    mergeOverrideKeys: new Set(),
    nodeWeights: new WeakMap(),
  };
  const { anchors, anchorDepths, anchorSources, mergeOverrideKeys, nodeWeights } = state;

  const lines = yamlStr.split('\n');
  while (lines.length > 0 && lines[lines.length - 1].trim() === '') lines.pop();

  // ── Process YAML directives & markers ──
  let docStartIdx = 0;
  const tags = {};
  while (docStartIdx < lines.length) {
    const raw = lines[docStartIdx];
    const trimmed = raw.trim();
    if (trimmed === '---' || trimmed.startsWith('--- ') || trimmed === '...' || trimmed.startsWith('... ')) {
      if (trimmed.startsWith('--- ') && trimmed.length > 4) {
        lines[docStartIdx] = raw.slice(0, raw.length - trimmed.length) + trimmed.slice(4);
        break;
      }
      if (trimmed.startsWith('... ') && trimmed.length > 4) {
        lines[docStartIdx] = raw.slice(0, raw.length - trimmed.length) + trimmed.slice(4);
        break;
      }
      docStartIdx++; continue;
    }
    if (trimmed.startsWith('%TAG')) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 3) tags[parts[1]] = parts[2];
      docStartIdx++; continue;
    }
    if (trimmed.startsWith('%')) { docStartIdx++; continue; }
    if (trimmed === '' || trimmed.startsWith('#')) { docStartIdx++; continue; }
    break;
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

  function expandTag(rawTag) {
    for (const [handle, prefix] of Object.entries(tags)) {
      if (rawTag.startsWith(handle)) {
        const suffix = rawTag.slice(handle.length);
        if (suffix.length > 0) return prefix + suffix;
      }
    }
    return rawTag;
  }

  let currentLine = -1;
  let currentColumn = -1;

  // Find the first `:` that acts as a key-value separator:
  // followed by space, tab, EOL, `#`, `}`, `]` — but not inside a quoted string
  function findKeySep(str, start) {
    for (let i = start || 0; i < str.length; i++) {
      if (str[i] === ':') {
        if (i + 1 >= str.length || str[i + 1] === ' ' || str[i + 1] === '\t' || str[i + 1] === '}' || str[i + 1] === ']')
          return i;
      }
    }
    return -1;
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
    if (i < line.length && line[i] === '\t')
      throw err('Tab characters are not allowed for indentation in YAML 1.2', i);
    return i;
  }

  function parseScalar(s) {
    let trimmed = s.trim();

    // Fold multi-line plain scalars (continuation lines starting with spaces)
    if (trimmed.includes('\n')) {
      const lines = trimmed.split('\n');
      const folded = [];
      let i = 0;
      while (i < lines.length) {
        if (lines[i].trim() === '') {
          folded.push('');
          i++;
        } else {
          let accum = lines[i];
          i++;
          while (i < lines.length && (lines[i].trim() === '' || lines[i].startsWith(' '))) {
            if (lines[i].trim() === '') {
              folded.push(accum);
              accum = '';
              i++;
            } else {
              accum += ' ' + lines[i].trim();
              i++;
            }
          }
          folded.push(accum);
        }
      }
      trimmed = folded.join('\n');
    }

    const tagMatch = trimmed.match(/^(![^\s]+)\s+/);
    if (tagMatch) {
      const rawTag = tagMatch[1];
      const tagVal = trimmed.slice(tagMatch[0].length);
      let fullTag;

      if (rawTag.startsWith('!!')) {
        const expanded = expandTag(rawTag);
        fullTag = expanded !== rawTag ? expanded : 'tag:yaml.org,2002:' + rawTag.slice(2);
      } else {
        fullTag = expandTag(rawTag);
      }

      const type = _schema._explicit[fullTag];
      if (type) return type.construct(tagVal);

      if (rawTag.startsWith('!!')) {
        // unknown !! tag — fall through to implicit
      } else {
        return trimmed;
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

  function parseInlineFlow(str, _flowDepth, _line) {
    if (_flowDepth === undefined) _flowDepth = 0;
    if (_flowDepth > 100) throw new YAMLException('YAML: flow nesting too deep (>100)');
    const s = str.trim();
    const offset = str.length - s.length;
    if (s.startsWith('[')) {
      const items = [];
      let i = 1;
      while (i < s.length) {
        const c = s[i];
        if (c === ']') {
          const w = items.reduce((s, item) => s + nodeWeight(item), 1);
          return { value: track(items, w), endPos: i + 1 };
        }
        if (c === ',' || c === ' ') { i++; continue; }
        const r = parseInlineFlow(s.slice(i), _flowDepth + 1, _line);
        items.push(r.value);
        i += r.endPos;
      }
      const w = items.reduce((s, item) => s + nodeWeight(item), 1);
      return { value: track(items, w), endPos: s.length };
    }
    if (s.startsWith('{')) {
      const obj = {};
      const seenKeys = new Set();
      let i = 1;
      while (i < s.length) {
        const c = s[i];
        if (c === '}') {
          const w = Object.values(obj).reduce((s, item) => s + nodeWeight(item), 1);
          return { value: track(obj, w), endPos: i + 1 };
        }
        if (c === ',' || c === ' ') { i++; continue; }
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
            const w = Object.values(obj).reduce((s, item) => s + nodeWeight(item), 1);
            return { value: track(obj, w), endPos: s.length };
          }
          key = s.slice(i + 1, close);
          if (quote === '"') key = unescapeYaml(key);
          i = close + 1;
        } else {
          let j = i;
          while (j < s.length && s[j] !== ':' && s[j] !== ',' && s[j] !== '}') j++;
          key = s.slice(i, j).trim();
          i = j;
        }
        if (cfg.maxKeys > 0 && seenKeys.size >= cfg.maxKeys)
          throw new YAMLException('YAML: inline mapping keys limit exceeded (' + cfg.maxKeys + ')');
        if (seenKeys.has(key)) throw new YAMLException('YAML: Duplicate key: "' + key + '"');
        seenKeys.add(key);
        while (i < s.length && (s[i] === ' ' || s[i] === ':')) i++;
        const r = parseInlineFlow(s.slice(i), _flowDepth + 1, _line);
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
        } else if (typeof val === 'string' && val.startsWith('*')) {
          const aname = val.slice(1);
          safeAssign(obj, key, track(resolveAlias(aname)));
          i += val.length;
        } else {
          safeAssign(obj, key, val);
          i += r.endPos;
        }
      }
      const w = Object.values(obj).reduce((s, item) => s + nodeWeight(item), 1);
      return { value: track(obj, w), endPos: s.length };
    }
    if (s.startsWith('&')) {
      const nameEnd = s.slice(1).search(/[ \t\[{"'*,]/);
      if (nameEnd < 0) {
        const aname = s.slice(1);
        setAnchor(aname, track(null));
        return { value: null, endPos: s.length };
      }
      const aname = s.slice(1, 1 + nameEnd);
      const afterName = s.slice(1 + nameEnd);
      const rest = afterName.trim();
      const wsLen = afterName.length - rest.length;
      const r = rest ? parseInlineFlow(rest, _flowDepth + 1, _line) : { value: null, endPos: 0 };
      const val = track(r.value !== undefined ? r.value : rest);
      const restTrimmed = rest.trim();
      const srcAnchor = restTrimmed.startsWith('*') ? restTrimmed.slice(1).split(/[ ,}\]]/)[0] : null;
      setAnchor(aname, val, srcAnchor);
      return { value: val, endPos: 1 + aname.length + wsLen + r.endPos };
    }
    if (s.startsWith('*')) {
      const aname = s.slice(1).split(/[ ,}\]]/)[0];
      return { value: track(resolveAlias(aname)), endPos: aname.length + 1 };
    }
    const tagPrefix = s.match(/^(![^\s]+)\s+/);
    if (tagPrefix) {
      const rawTag = tagPrefix[1];
      const rest = s.slice(tagPrefix[0].length);
      const r = parseInlineFlow(rest, _flowDepth + 1, _line);
      let val = r.value;
      if (val === undefined) val = parseScalar(rest);
      let fullTag;
      if (rawTag.startsWith('!!')) {
        const expanded = expandTag(rawTag);
        fullTag = expanded !== rawTag ? expanded : 'tag:yaml.org,2002:' + rawTag.slice(2);
      } else {
        fullTag = expandTag(rawTag);
      }
      const type = _schema._explicit[fullTag];
      if (!type) {
        if (rawTag.startsWith('!!')) {
          // Unknown !! tag: use resolved val (backward compat)
        } else {
          // Unknown ! tag: re-parse as plain scalar (backward compat)
          return { value: track(parseScalar(s)), endPos: s.length };
        }
      } else {
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
        return { value: track(unescapeYaml(inner)), endPos: close + 1 };
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
      if (close > 0) return { value: track(s.slice(1, close).replace(/''/g, "'")), endPos: close + 1 };
    }
    let end = s.search(/[,})\]]/);
    if (end < 0) return { value: track(parseScalar(s)), endPos: s.length };
    if (end === 0) return { value: track(parseScalar(s)), endPos: s.length };
    let raw = s.slice(0, end);
    if (raw.endsWith(' ')) raw = raw.trimEnd();
    return { value: track(parseScalar(raw)), endPos: end };
  }

  function parseInlineValue(str) {
    const r = parseInlineFlow(str);
    if (r.value !== undefined) return r.value;
    return track(parseScalar(str));
  }

  // Pre-scan for anchors at all levels
  let _anchoring = false;
  for (let i = 0; i < contentLines.length; i++) {
    currentLine = i;
    const line = contentLines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith('&') && trimmed.includes(' ')) {
      if (_anchoring) continue; // guard re-entrancy
      _anchoring = true;
      const space = trimmed.indexOf(' ');
      const aname = trimmed.slice(1, space);
      const rest = trimmed.slice(space + 1);
      if (anchors[aname] !== undefined) { _anchoring = false; continue; }
      if (rest.startsWith('*')) {
        const srcAnchor = rest.slice(1).trim();
        const val = track(resolveAlias(srcAnchor));
        setAnchor(aname, val, srcAnchor);
      } else if (rest.startsWith('[') || rest.startsWith('{')) {
        const flowResult = parseInlineFlow(rest);
        setAnchor(aname, flowResult.value !== undefined ? flowResult.value : track(parseScalar(rest)));
      } else if (rest.includes(':')) {
        const indent = getIndent(line);
        const dummy = rest + '\n' + contentLines.slice(i + 1)
          .filter(l => getIndent(l) > indent)
          .map(l => l.slice(indent))
          .join('\n');
        setAnchor(aname, track(yamlToJS(dummy, cfg, _depth + 1, _schema, state)));
      } else {
        setAnchor(aname, track(parseScalar(rest)));
      }
      _anchoring = false;
    }
  }
  _anchoring = false;

  function parseBlock(startIdx, baseIndent, sourceLines, blockDepth) {
    if (blockDepth === undefined) blockDepth = 0;
    if (cfg.maxDepth > 0 && blockDepth > cfg.maxDepth)
      throw err('nesting depth exceeds limit (' + cfg.maxDepth + ')');
    const ls = sourceLines || contentLines;
    const result = {};
    const seenKeys = new Set();
    function addKey(key) {
      if (cfg.maxKeys > 0 && seenKeys.size >= cfg.maxKeys)
        throw err('mapping keys limit exceeded (' + cfg.maxKeys + ')');
      if (seenKeys.has(key)) throw err('Duplicate key: "' + key + '"');
      seenKeys.add(key);
    }
    const seq = [];
    let inSeq = false;
    let i = startIdx;

    while (i < ls.length) {
      currentLine = i;
      const line = ls[i];
      const indent = getIndent(line);
      if (indent < baseIndent) break;
      const trimmed = line.trim();
      if (trimmed === '' || trimmed.startsWith('#')) { i++; continue; }
      if (trimmed === '...') break;

      if (trimmed.startsWith('- ')) {
        inSeq = true;
        const itemContent = trimmed.slice(2);
        const subIndent = indent + 2;

        const itemLines = [];
        let j = i + 1;
        while (j < ls.length) {
          const nindent = getIndent(ls[j]);
          if (nindent < subIndent) break;
          if (ls[j].trim() === '' || ls[j].trim().startsWith('#')) { j++; continue; }
          if (ls[j].trimStart().startsWith('- ') && nindent === indent) break;
          itemLines.push(ls[j]);
          j++;
        }

        const colonIdxItem = findKeySep(itemContent);
        const isMappingItem = colonIdxItem >= 0 && (itemContent[colonIdxItem + 1] === ' ' || itemLines.length > 0);
        if (isMappingItem) {
          const itemYaml = [itemContent, ...itemLines.map(l => l.slice(subIndent))].join('\n');
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1, _schema, state)));
        } else if (itemLines.length === 0) {
          seq.push(track(parseInlineValue(itemContent)));
        } else {
          const itemYaml = itemLines.map(l => l.slice(subIndent)).join('\n');
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1, _schema, state)));
        }
        i = j - 1;
      } else {
        let colonIdx = -1;
        let key;
        const afterIndent = line.slice(indent);
        if (afterIndent.startsWith('"')) {
          let close = -1;
          let pos = 1;
          while (pos < afterIndent.length) {
            if (afterIndent[pos] === '\\') { pos += 2; continue; }
            if (afterIndent[pos] === '"') { close = pos; break; }
            pos++;
          }
          if (close > 0) { colonIdx = indent + afterIndent.indexOf(':', close); key = unescapeYaml(afterIndent.slice(1, close)); }
        } else if (afterIndent.startsWith("'")) {
          let close = -1;
          let pos = 1;
          while (pos < afterIndent.length) {
            if (afterIndent[pos] === "'" && pos + 1 < afterIndent.length && afterIndent[pos + 1] === "'") { pos += 2; continue; }
            if (afterIndent[pos] === "'") { close = pos; break; }
            pos++;
          }
          if (close > 0) { colonIdx = indent + afterIndent.indexOf(':', close); key = afterIndent.slice(1, close).replace(/''/g, "'"); }
        }
        let valStr;
        // Explicit key syntax: ? key \n : value  (check BEFORE colon detection)
        if (afterIndent.startsWith('? ')) {
          key = afterIndent.slice(2);
          const nextLine = i + 1 < ls.length ? ls[i + 1].trim() : '';
          if (nextLine.startsWith(': ')) {
            valStr = nextLine.slice(2).trim();
            i++; // consume the : line
          } else if (nextLine === ':') {
            valStr = '';
            i++; // consume the : line
          } else {
            // Key with no value (e.g. in !!set)
            addKey(key);
            safeAssign(result, key, track(null));
            i++;
            continue;
          }
        } else {
          if (colonIdx < 0) colonIdx = findKeySep(line, indent);
          if (colonIdx < 0) { i++; continue; }
          if (key === undefined) key = line.slice(indent, colonIdx).trim();
          valStr = line.slice(colonIdx + 1).trim();
        }
        currentColumn = colonIdx >= 0 ? colonIdx + 1 : 0;

        // Track merge keys to catch override attempts
        if (key === '<<') {
          mergeOverrideKeys.clear();
          for (const existingKey of seenKeys) mergeOverrideKeys.add(existingKey);
        }

        // Support explicit block scalar indent indicators (|1, |2, >1, >2, etc.)
        const valForBlock = valStr.replace(/^![^\s]+\s*/, '');
        const blockMatch = valForBlock.match(/^(\||>)(\d*)([\-+]?)$/);
        if (blockMatch && valForBlock.trim() === blockMatch[0]) {
          const blockLines = [];
          let j = i + 1;
          let contentIndent = null;
          while (j < ls.length) {
            const nindent = getIndent(ls[j]);
            if (nindent <= indent && ls[j].trim() !== '') break;
            if (ls[j].trim() === '' || ls[j].trim().startsWith('#')) { blockLines.push(''); j++; continue; }
            if (contentIndent === null) contentIndent = nindent;
            blockLines.push(ls[j].slice(contentIndent));
            j++;
          }
          const style = blockMatch[0];
          const chomp = style.endsWith('-') ? 'strip' : style.endsWith('+') ? 'keep' : 'clip';
          const baseStyle = style[0];
          let text;
          if (baseStyle === '|') {
            text = blockLines.join('\n');
            if (chomp === 'keep') text = text + '\n';
            else if (chomp !== 'strip') text = text + '\n';
            text = chomp === 'strip' ? text.replace(/\n+$/, '') : text;
          } else {
            const folded = [];
            let li = 0;
            while (li < blockLines.length) {
              if (blockLines[li] === '') {
                folded.push('');
                li++;
              } else {
                let accum = blockLines[li];
                li++;
                while (li < blockLines.length && blockLines[li] !== '') {
                  accum += ' ' + blockLines[li];
                  li++;
                }
                folded.push(accum);
              }
            }
            text = folded.join('\n');
            if (chomp === 'keep') text = text.replace(/\n*$/, '') + '\n';
            else if (chomp === 'strip') text = text.replace(/\n+$/, '');
            else text = text.replace(/\n*$/, '\n');
          }
          addKey(key);
          safeAssign(result, key, track(text));
          i = j - 1;
          i++;
          continue;
        }

        const anchorMatch = valStr.match(/^&([a-zA-Z_][a-zA-Z0-9_-]*)\s*(.*)/);
        if (anchorMatch) {
          const aname = anchorMatch[1];
          const rest = anchorMatch[2].trim();
          if (rest === '' && i + 1 < ls.length && getIndent(ls[i + 1]) > indent) {
            const sub = parseBlock(i + 1, indent + 2, ls, blockDepth + 1);
            setAnchor(aname, track(sub));
            addKey(key);
            safeAssign(result, key, track(sub));
            let next = i + 1;
            while (next < ls.length) {
              const nindent = getIndent(ls[next]);
              const t = ls[next].trim();
              if (nindent >= indent + 2 && t !== '' && !t.startsWith('#')) { next++; continue; }
              break;
            }
            i = next - 1;
            i++;
            continue;
          }
          addKey(key);
          safeAssign(result, key, track(parseInlineValue(valStr)));
          i++;
          continue;
        }

        const aliasAnchorMatch = valStr.match(/^&([a-zA-Z_][a-zA-Z0-9_-]*)\s+\*([a-zA-Z_][a-zA-Z0-9_-]*)/);
        if (aliasAnchorMatch) {
          const aname = aliasAnchorMatch[1];
          const srcAnchor = aliasAnchorMatch[2];
          const val = track(resolveAlias(srcAnchor));
          setAnchor(aname, val, srcAnchor);
          addKey(key);
          safeAssign(result, key, val);
          i++;
          continue;
        }

        if (valStr === '' || valStr.startsWith('#')) {
          let nextNonBlank = i + 1;
          while (nextNonBlank < ls.length && (ls[nextNonBlank].trim() === '' || ls[nextNonBlank].trim().startsWith('#'))) nextNonBlank++;
          if (nextNonBlank >= ls.length || getIndent(ls[nextNonBlank]) <= indent) {
            addKey(key);
            safeAssign(result, key, track(null));
            i++;
            continue;
          }
          const sub = parseBlock(i + 1, indent + 2, ls, blockDepth + 1);
          addKey(key);
          safeAssign(result, key, track(sub));
          let next = i + 1;
          while (next < ls.length) {
            const t = ls[next].trim();
            if (t === '' || t.startsWith('#')) { next++; continue; }
            if (getIndent(ls[next]) >= indent + 2) { next++; continue; }
            break;
          }
          i = next - 1;
        } else {
          addKey(key);
          safeAssign(result, key, track(parseInlineValue(valStr)));
        }
      }
      i++;
    }

    if (inSeq) {
      const w = seq.reduce((s, item) => s + nodeWeight(item), 1);
      return track(seq, w);
    }
    return track(result);
  }

  const topContent = contentLines.join('\n').trim();
  const top = yamlStr.trim();
  let result;
  if (topContent.startsWith('[') || topContent.startsWith('{')) {
    const r = parseInlineFlow(topContent);
    result = r.value !== undefined ? track(r.value) : track(parseScalar(topContent));
  } else if (topContent === '' || topContent === '---' || topContent === '...') {
    result = null;
  } else if (findKeySep(topContent) < 0 && !topContent.startsWith('- ') && !topContent.startsWith('&') && !topContent.startsWith('*') && !topContent.startsWith('?')) {
    result = track(parseScalar(topContent));
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

function parseAllYaml(yamlStr, cfg, _schema) {
  if (byteLength(yamlStr) > cfg.maxInputBytes)
    throw new YAMLException('YAML: input too large (>' + Math.round(cfg.maxInputBytes / 1048576 * 10) / 10 + 'MB)');
  const docs = [];
  const lines = yamlStr.split('\n');
  let current = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (current.length === 0 && (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith('%') || trimmed === '---' || trimmed === '...')) continue;
    if (trimmed === '---' || trimmed === '...') {
      if (current.length > 0) {
        docs.push(yamlToJS(current.join('\n'), cfg, 0, _schema));
        current = [];
      }
      continue;
    }
    current.push(line);
  }
  if (current.length > 0) docs.push(yamlToJS(current.join('\n'), cfg, 0, _schema));
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
   * Create a SAX-style streaming YAML parser bound to this instance's schema.
   * @param {{maxNodes?: number, maxAlias?: number, maxAliasDepth?: number, maxExpansion?: number, maxInputMB?: number, maxInputBytes?: number, maxStringLength?: number, maxKeys?: number, maxDepth?: number, anchors?: 'buffer'|'disable'}} [opts]
   * @returns {StreamParser}
   */
  createStream(opts) {
    return createStream(Object.assign({}, opts, { schema: this._schema }));
  }

  /**
   * Stream-parse YAML documents (single or multi-doc). Accepts a string or
   * any (async) iterable of chunks and yields each document as it completes.
   * @param {string|Iterable<string>|AsyncIterable<string>} input
   * @param {{maxNodes?: number, maxAlias?: number, maxAliasDepth?: number, maxExpansion?: number, maxInputMB?: number, maxInputBytes?: number, maxStringLength?: number, maxKeys?: number, maxDepth?: number, anchors?: 'buffer'|'disable'}} [opts]
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
  const trimmed = s.trim();
  const tagMatch = trimmed.match(/^(![^\s]+)\s+/);
  if (tagMatch) {
    const rawTag = tagMatch[1];
    const tagVal = trimmed.slice(tagMatch[0].length);
    let fullTag;
    if (rawTag.startsWith('!!')) {
      const expanded = expandTagTop(rawTag, tagMap);
      fullTag = expanded !== rawTag ? expanded : 'tag:yaml.org,2002:' + rawTag.slice(2);
    } else {
      fullTag = expandTagTop(rawTag, tagMap);
    }
    const type = schema._explicit[fullTag];
    if (type) return type.construct(tagVal);
    if (!rawTag.startsWith('!!')) return trimmed;
  }
  let val = trimmed;
  if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) return unescapeYaml(val.slice(1, -1));
  if (val.startsWith("'") && val.endsWith("'") && val.length >= 2) return val.slice(1, -1);
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
      this._topFlow += '\n' + line.trim();
      if (this._flowBalanced(this._topFlow)) {
        const t = this._topFlow; this._topFlow = null;
        this._emitFlowRoot(t);
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
    if (key === undefined) key = rawKey;
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
    }

    const item = trimmed.slice(2);
    if (item.trim() === '') {
      seqCtx.pendingItem = true;
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
      top.plainValueLines = [line];
      return;
    }
    if (top && top.kind === 'seq' && indent > top.indent) {
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
      kind: 'seq', indent, pendingItem: false, valueAnchor: null, anchor: null,
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
        this._emitFlowRoot(t);
      }
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
    if (!this.buffered) return;
    if (ctx.kind === 'map') {
      if (ctx.pendingKey !== null) {
        if (ctx.pendingKey === '<<') ctx.node['<<'] = value;
        else safeAssign(ctx.node, ctx.pendingKey, value);
        ctx.pendingKey = null;
      }
    } else if (ctx.kind === 'seq') {
      ctx.node.push(value);
      ctx.pendingItem = false;
      ctx.lastInlineIndex = ctx.node.length - 1;
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
      this._emitFlow(ctx, rest, anchor);
      return;
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
      if (ch === '[' || ch === '{') depth++;
      else if (ch === ']' || ch === '}') { depth--; if (depth < 0) return false; }
    }
    return depth === 0 && !inS && !inD;
  }

  _emitFlow(ctx, str, anchor) {
    const r = this._parseFlowEmitting(str, 0);
    if (anchor) this._registerAnchor(anchor, r.value);
    this._assignValue(ctx, r.value);
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
      this._emit('sequenceStart');
      this._count();
      while (i < s.length) {
        const c = s[i];
        if (c === ']') {
          this._emit('sequenceEnd');
          return { value: items, endPos: i + 1 };
        }
        if (c === ',' || c === ' ') { i++; continue; }
        const r = this._parseFlowEmitting(s.slice(i), _depth + 1);
        items.push(r.value);
        i += r.endPos;
      }
      this._emit('sequenceEnd');
      return { value: items, endPos: s.length };
    }
    if (s.startsWith('{')) {
      const obj = {};
      const seen = new Set();
      let i = 1;
      this._emit('mappingStart');
      this._count();
      while (i < s.length) {
        const c = s[i];
        if (c === '}') {
          this._emit('mappingEnd');
          return { value: obj, endPos: i + 1 };
        }
        if (c === ',' || c === ' ') { i++; continue; }
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
          while (j < s.length && s[j] !== ':' && s[j] !== ',' && s[j] !== '}') j++;
          key = s.slice(i, j).trim();
          i = j;
        }
        if (this.cfg.maxKeys > 0 && seen.size >= this.cfg.maxKeys)
          throw this._err('inline mapping keys limit exceeded (' + this.cfg.maxKeys + ')');
        if (seen.has(key)) throw this._err('Duplicate key: "' + key + '"');
        seen.add(key);
        while (i < s.length && (s[i] === ' ' || s[i] === ':')) i++;
        this._emit('key', { value: key, raw: key });
        this._count();
        const r = this._parseFlowEmitting(s.slice(i), _depth + 1);
        safeAssign(obj, key, r.value);
        i += r.endPos;
      }
      this._emit('mappingEnd');
      return { value: obj, endPos: s.length };
    }
    if (s.startsWith('&')) {
      const nameEnd = s.slice(1).search(/[ \t\[{"'*,]/);
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
    let end = s.search(/[,})\]]/);
    if (end < 0) { const v = resolveScalarTop(s, this.schema, this.tagMap); return { value: this._flowScalar(v, s), endPos: s.length }; }
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
  const queue = [];
  let waker = null;
  let closed = false;
  parser.on('document', (doc) => {
    if (waker) { const w = waker; waker = null; w(doc); }
    else queue.push(doc);
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
