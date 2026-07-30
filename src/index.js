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
};

let _baseCfg = { ...DEFAULTS };

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
  if (opts.maxInputMB !== undefined) {
    const v = opts.maxInputMB;
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0.001)
      throw new YAMLException('setLimits: maxInputMB must be a positive number');
    _baseCfg.maxInputBytes = Math.round(v * 1_048_576);
  }
}

// ── Custom Error ─────────────────────────────────────────

export class YAMLException extends Error {
  constructor(msg, mark) {
    super(msg);
    this.name = 'YAMLException';
    this.mark = mark || null;
  }
}

// ── Prototype Pollution Guard ────────────────────────────

function safeAssign(obj, key, value) {
  if (key === '__proto__' || key === 'constructor')
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

export class YamlType {
  constructor(tag, opts = {}) {
    this.tag = tag;
    this.kind = opts.kind || 'scalar';
    this.construct = opts.construct || ((v) => v);
    this.resolve = opts.resolve || (() => true);
    this.instance = opts.instance || undefined;
  }
}

export class Schema {
  constructor() {
    this._types = [];
    this._explicit = {};
    this._implicit = [];
  }

  addType(type) {
    this._types.push(type);
    this._explicit[type.tag] = type;
    if (type.kind === 'scalar' && type.instance === undefined) {
      this._implicit.push(type);
    }
    return this;
  }

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
      const n = Number(v);
      return isNaN(n) || !Number.isFinite(n) ? v : n;
    },
    resolve: (v) => {
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

function yamlToJS(yamlStr, cfg, _depth, _schema) {
  if (_depth === undefined) _depth = 0;
  if (_schema === undefined) _schema = _baseSchema;
  if (_depth > 50) throw new YAMLException('YAML: recursion too deep (>50) — possible anchor bomb');
  if (byteLength(yamlStr) > cfg.maxInputBytes) {
    throw new YAMLException('YAML: input too large (>' + Math.round(cfg.maxInputBytes / 1048576 * 10) / 10 + 'MB)');
  }

  const lines = yamlStr.split('\n');
  while (lines.length > 0 && lines[lines.length - 1].trim() === '') lines.pop();

  // ── Process YAML directives & markers ──
  let docStartIdx = 0;
  const tags = {};
  while (docStartIdx < lines.length) {
    const raw = lines[docStartIdx];
    const trimmed = raw.trim();
    if (trimmed === '---' || trimmed === '...') { docStartIdx++; continue; }
    if (trimmed.startsWith('%YAML')) { docStartIdx++; continue; }
    if (trimmed.startsWith('%TAG')) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 3) tags[parts[1]] = parts[2];
      docStartIdx++; continue;
    }
    if (trimmed === '' || trimmed.startsWith('#')) { docStartIdx++; continue; }
    break;
  }
  const contentLines = lines.slice(docStartIdx);

  const anchors = {};
  const anchorDepths = {};
  let produced = 0;
  let aliasHits = 0;
  const mergeOverrideKeys = new Set();
  const nodeWeights = new WeakMap();

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
    if (typeof node !== 'object' || node === null) {
      produced++;
      if (produced > cfg.maxNodes)
        throw err('nodes limit exceeded (possible bomb) — reached ' + produced);
      if (produced > cfg.maxExpansion)
        throw err('expansion limit exceeded (possible bomb) — reached ' + produced);
      return node;
    }
    if (weight === undefined) {
      weight = nodeWeights.has(node) ? nodeWeights.get(node) : 1;
    }
    produced += weight;
    nodeWeights.set(node, weight);
    if (produced > cfg.maxNodes)
      throw err('nodes limit exceeded (possible bomb) — reached ' + produced);
    if (produced > cfg.maxExpansion)
      throw err('expansion limit exceeded (possible bomb) — reached ' + produced);
    return node;
  }

  function setAnchor(aname, value, sourceAnchor) {
    const depth = sourceAnchor ? (anchorDepths[sourceAnchor] || 0) + 1 : 0;
    if (depth > cfg.maxAliasDepth)
      throw new YAMLException('YAML: alias depth exceeds limit (' + cfg.maxAliasDepth + '), possible anchor bomb');
    anchors[aname] = value;
    anchorDepths[aname] = depth;
  }

  function resolveAlias(aname) {
    if (++aliasHits > cfg.maxAlias) throw new YAMLException('YAML: alias expansion limit exceeded (bomb)');
    const val = anchors[aname];
    if (val === undefined) return aname;
    return val;
  }

  function applyTags(s) {
    for (const handle of Object.keys(tags)) {
      if (s.startsWith(handle)) {
        const rest = s.slice(handle.length);
        if (rest.length > 0) return rest;
      }
    }
    return s;
  }

  let currentLine = -1;
  let currentColumn = -1;

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
    const trimmed = s.trim();

    // Detect tags: !!xxx (shorthand) or !xxx (local tag)
    const tagMatch = trimmed.match(/^(![^\s]+)\s+/);
    if (tagMatch) {
      const rawTag = tagMatch[1];
      const tagVal = trimmed.slice(tagMatch[0].length);

      if (rawTag.startsWith('!!')) {
        const fullTag = 'tag:yaml.org,2002:' + rawTag.slice(2);
        const type = _schema._explicit[fullTag];
        if (type) return type.construct(tagVal);
      } else {
        const type = _schema._explicit[rawTag];
        if (type) return type.construct(tagVal);
        return trimmed;
      }
    }

    const val = trimmed;
    for (const type of _schema._implicit) {
      if (type.resolve && type.resolve(val)) {
        return type.construct(val);
      }
    }

    if (val.startsWith('"') && val.endsWith('"')) {
      const inner = val.slice(1, -1);
      return unescapeYaml(inner);
    }
    if ((val.startsWith("'") && val.endsWith("'")))
      return val.slice(1, -1);
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
        items.push(track(r.value));
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
          safeAssign(obj, key, track(val));
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
        fullTag = 'tag:yaml.org,2002:' + rawTag.slice(2);
      } else {
        fullTag = rawTag;
      }
      const type = _schema._explicit[fullTag];
      if (type) val = type.construct(String(val));
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
    let end = s.search(/[,}\]\s]/);
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
      } else if (rest.includes(':')) {
        const indent = getIndent(line);
        const dummy = rest + '\n' + contentLines.slice(i + 1)
          .filter(l => getIndent(l) > indent)
          .map(l => l.slice(indent))
          .join('\n');
        setAnchor(aname, track(yamlToJS(dummy, cfg, _depth + 1, _schema)));
      } else {
        setAnchor(aname, track(parseScalar(rest)));
      }
      _anchoring = false;
    }
  }
  _anchoring = false;

  function parseBlock(startIdx, baseIndent, sourceLines) {
    const ls = sourceLines || contentLines;
    const result = {};
    const seenKeys = new Set();
    function addKey(key) {
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

        const colonIdxItem = itemContent.indexOf(':');
        const isMappingItem = colonIdxItem >= 0 && (itemContent[colonIdxItem + 1] === ' ' || itemLines.length > 0);
        if (isMappingItem) {
          const itemYaml = [itemContent, ...itemLines.map(l => l.slice(subIndent))].join('\n');
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1, _schema)));
        } else if (itemLines.length === 0) {
          seq.push(track(parseInlineValue(itemContent)));
        } else {
          const itemYaml = itemLines.map(l => l.slice(subIndent)).join('\n');
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1, _schema)));
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
        if (colonIdx < 0) { colonIdx = line.indexOf(':'); key = line.slice(indent, colonIdx).trim(); }
        if (colonIdx < 0) { i++; continue; }
        currentColumn = colonIdx + 1;
        let valStr = line.slice(colonIdx + 1).trim();

        // Track merge keys to catch override attempts
        if (key === '<<') {
          mergeOverrideKeys.clear();
          for (const existingKey of seenKeys) mergeOverrideKeys.add(existingKey);
        }

        // Support explicit block scalar indent indicators (|1, |2, >1, >2, etc.)
        const blockMatch = valStr.match(/^(\||>)(\d*)([\-+]?)$/);
        if (blockMatch && valStr.replace(/^!!\w+\s*/, '').trim() === blockMatch[0]) {
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
            const sub = parseBlock(i + 1, indent + 2, ls);
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
          const sub = parseBlock(i + 1, indent + 2, ls);
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

  const top = yamlStr.trim();
  let result;
  if (top.startsWith('[') || top.startsWith('{')) {
    const r = parseInlineFlow(top);
    result = r.value !== undefined ? track(r.value) : track(parseScalar(top));
  } else if (top === '' || top === '---' || top === '...') {
    result = null;
  } else if (!top.includes(':') && !top.startsWith('- ') && !top.startsWith('&') && !top.startsWith('*')) {
    result = track(parseScalar(top));
  } else {
    result = parseBlock(0, 0);
  }

  // Resolve merge keys (<<: *anchor)
  function resolveMerges(v) {
    if (Array.isArray(v)) return v.map(resolveMerges);
    if (v && typeof v === 'object' && !Array.isArray(v)) {
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

export function dump(value, opts) {
  return yamlDump(value, opts);
}

// ── Public API Class ──────────────────────────────────────

export class YamlSecurity {
  constructor(opts) {
    this._overrides = opts ? { ...opts } : {};
    this._schema = DEFAULT_SCHEMA;
  }

  setSchema(schema) {
    if (!(schema instanceof Schema)) throw new YAMLException('setSchema: expected a Schema instance');
    this._schema = schema;
  }

  _getCfg() {
    const cfg = { ..._baseCfg };
    const ov = this._overrides;
    if (ov.maxAliasDepth !== undefined) cfg.maxAliasDepth = ov.maxAliasDepth;
    if (ov.maxNodes !== undefined) cfg.maxNodes = ov.maxNodes;
    if (ov.maxExpansion !== undefined) cfg.maxExpansion = ov.maxExpansion;
    return cfg;
  }

  parse(yamlStr) {
    try {
      const result = yamlToJS(yamlStr, this._getCfg(), 0, this._schema);
      return { ok: true, result };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  parseAll(yamlStr) {
    try {
      const docs = parseAllYaml(yamlStr, this._getCfg(), this._schema);
      return { ok: true, result: docs };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  dump(value, opts) {
    try {
      const result = yamlDump(value, opts);
      return { ok: true, result };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  parseToJSON(yamlStr) {
    const r = this.parse(yamlStr);
    if (!r.ok) return r;
    return { ok: true, result: JSON.stringify(r.result, null, 2) };
  }
}

YamlSecurity.setLimits = setLimits;
