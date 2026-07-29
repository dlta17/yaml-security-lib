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
  if (opts.maxNodes !== undefined) _baseCfg.maxNodes = opts.maxNodes;
  if (opts.maxAlias !== undefined) _baseCfg.maxAlias = opts.maxAlias;
  if (opts.maxAliasDepth !== undefined) _baseCfg.maxAliasDepth = opts.maxAliasDepth;
  if (opts.maxExpansion !== undefined) _baseCfg.maxExpansion = opts.maxExpansion;
  if (opts.maxInputMB !== undefined) _baseCfg.maxInputBytes = Math.round(opts.maxInputMB * 1_048_576);
  if (opts.maxInputBytes !== undefined) _baseCfg.maxInputBytes = opts.maxInputBytes;
}

// ── Billion Laughs / Expansion Guard ────────────────────

function deepSize(v, depth) {
  if (depth > 50) return 0;
  if (v === null || v === undefined) return 1;
  if (typeof v !== 'object') return 1;
  let n = 1;
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) n += deepSize(v[i], depth + 1); }
  else { const ks = Object.keys(v); for (let i = 0; i < ks.length; i++) n += deepSize(v[ks[i]], depth + 1); }
  return n;
}

// ── Custom Error ─────────────────────────────────────────

export class YAMLException extends Error {
  constructor(msg) {
    super(msg);
    this.name = 'YAMLException';
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

// ── YAML Parser ──────────────────────────────────────────

function yamlToJS(yamlStr, cfg, _depth) {
  if (_depth === undefined) _depth = 0;
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

  function track(node, weight) {
    produced += weight || 1;
    if (produced > cfg.maxNodes)
      throw err('nodes limit exceeded (possible bomb)');
    if (produced > cfg.maxExpansion)
      throw err('expansion limit exceeded (possible bomb)');
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
    // Apply %TAG directive shortcuts to !!tags
    for (const handle of Object.keys(tags)) {
      if (s.startsWith(handle)) {
        const rest = s.slice(handle.length);
        // Only apply if handle is ! or !something! and rest starts with a non-empty tag
        if (rest.length > 0) return rest;
      }
    }
    return s;
  }

  function parseScalar(s) {
    const trimmed = s.trim();
    const applied = applyTags(trimmed);
    const tagMatch = applied.match(/^!!(\w+)\s*/);
    const tagName = tagMatch ? tagMatch[1] : null;
    const val = tagMatch ? trimmed.slice(tagMatch[0].length) : trimmed;

    if (tagName === 'str') return val;
    if (tagName === 'null') return null;
    if (tagName === 'bool') return val === 'true';
    if (tagName === 'int') { const n = Number(val); return isNaN(n) ? val : n; }
    if (tagName === 'float') { const n = Number(val); return isNaN(n) ? val : n; }
    if (tagName === 'timestamp') return val;

    if (val === 'null' || val === '~') return null;
    if (val === 'true') return true;
    if (val === 'false') return false;
    const num = Number(val);
    if (!isNaN(num) && val !== '' && val.trim() !== '') return num;
    if (val.startsWith('"') && val.endsWith('"')) {
      const inner = val.slice(1, -1);
      return unescapeYaml(inner);
    }
    if ((val.startsWith("'") && val.endsWith("'")))
      return val.slice(1, -1);
    return val;
  }

  function parseInlineFlow(str, _flowDepth) {
    if (_flowDepth === undefined) _flowDepth = 0;
    if (_flowDepth > 100) throw new YAMLException('YAML: flow nesting too deep (>100)');
    const s = str.trim();
    if (s.startsWith('[')) {
      const items = [];
      let i = 1;
      while (i < s.length) {
        const c = s[i];
        if (c === ']') { const exp = deepSize(items, 0); return { value: track(items, exp), endPos: i + 1 }; }
        if (c === ',' || c === ' ') { i++; continue; }
        const r = parseInlineFlow(s.slice(i), _flowDepth + 1);
        items.push(track(r.value));
        i += r.endPos;
      }
      const expA = deepSize(items, 0); return { value: track(items, expA), endPos: s.length };
    }
    if (s.startsWith('{')) {
      const obj = {};
      const seenKeys = new Set();
      let i = 1;
      while (i < s.length) {
        const c = s[i];
        if (c === '}') { const exp = deepSize(obj, 0); return { value: track(obj, exp), endPos: i + 1 }; }
        if (c === ',' || c === ' ') { i++; continue; }
        let key;
        if (s[i] === '"' || s[i] === "'") {
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
            close = s.indexOf("'", i + 1);
          }
          if (close < 0) { const exp = deepSize(obj, 0); return { value: track(obj, exp), endPos: s.length }; }
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
        const r = parseInlineFlow(s.slice(i), _flowDepth + 1);
        const val = r.value;
        if (typeof val === 'string' && val.startsWith('&')) {
          const aname = val.slice(1).split(/[ ,\]}]/)[0];
          const rest = val.slice(aname.length + 1).trim();
          const rr = parseInlineFlow(rest, _flowDepth + 1);
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
      const expO = deepSize(obj, 0); return { value: track(obj, expO), endPos: s.length };
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
      const r = rest ? parseInlineFlow(rest, _flowDepth + 1) : { value: null, endPos: 0 };
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
    const tagPrefix = s.match(/^!!\w+\s+/);
    if (tagPrefix) {
      const tagName = tagPrefix[0].slice(2).trim();
      const rest = s.slice(tagPrefix[0].length);
      const r = parseInlineFlow(rest, _flowDepth + 1);
      let val = r.value;
      if (val === undefined) val = parseScalar(rest);
      if (tagName === 'str') val = String(val);
      else if (tagName === 'int') val = typeof val === 'number' ? Math.floor(val) : Number(val);
      else if (tagName === 'float') val = Number(val);
      else if (tagName === 'null') val = null;
      else if (tagName === 'bool') val = val === 'true' || val === true;
      else if (tagName === 'timestamp') val = String(val);
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
      const close = s.indexOf("'", 1);
      if (close > 0) return { value: track(s.slice(1, close)), endPos: close + 1 };
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

  let currentLine = -1;

  function err(msg) {
    const loc = currentLine >= 0 ? ' at line ' + (currentLine + 1) : '';
    return new YAMLException('YAML' + loc + ': ' + msg);
  }

  function getIndent(line) {
    let i = 0;
    while (i < line.length && (line[i] === ' ' || line[i] === '\t')) i++;
    return i;
  }

  // Pre-scan for anchors at all levels (not just top-level)
  for (let i = 0; i < contentLines.length; i++) {
    const line = contentLines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith('&') && trimmed.includes(' ')) {
      const space = trimmed.indexOf(' ');
      const aname = trimmed.slice(1, space);
      const rest = trimmed.slice(space + 1);
      if (anchors[aname] !== undefined) continue; // already scanned
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
        setAnchor(aname, track(yamlToJS(dummy, cfg, _depth + 1)));
      } else {
        setAnchor(aname, track(parseScalar(rest)));
      }
    }
  }

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
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1)));
        } else if (itemLines.length === 0) {
          seq.push(track(parseInlineValue(itemContent)));
        } else {
          const itemYaml = itemLines.map(l => l.slice(subIndent)).join('\n');
          seq.push(track(yamlToJS(itemYaml, cfg, _depth + 1)));
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
        let valStr = line.slice(colonIdx + 1).trim();

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
            // Folded block scalar — fold lines correctly
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

    if (inSeq) { const expS = deepSize(seq, 0); return track(seq, expS); }
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
    // Standalone scalar
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
              if (!(sk in merged) && sk !== '<<') safeAssign(merged, sk, resolveMerges(src[sk]));
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

function parseAllYaml(yamlStr, cfg) {
  if (byteLength(yamlStr) > cfg.maxInputBytes)
    throw new YAMLException('YAML: input too large (>' + Math.round(cfg.maxInputBytes / 1048576 * 10) / 10 + 'MB)');
  const docs = [];
  const lines = yamlStr.split('\n');
  let current = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    // Skip directives and blank lines at document start
    if (current.length === 0 && (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith('%') || trimmed === '---' || trimmed === '...')) continue;
    if (trimmed === '---' || trimmed === '...') {
      if (current.length > 0) {
        docs.push(yamlToJS(current.join('\n'), cfg));
        current = [];
      }
      continue;
    }
    current.push(line);
  }
  if (current.length > 0) docs.push(yamlToJS(current.join('\n'), cfg));
  return docs;
}

// ── YAML Dumper ─────────────────────────────────────────

function yamlDump(value, opts = {}) {
  const indent = opts.indent !== undefined ? opts.indent : 2;
  const flowLevel = opts.flowLevel !== undefined ? opts.flowLevel : 6;
  const visited = new Set();
  function needsQuotes(s) {
    if (typeof s !== 'string') return false;
    if (s === '' || s === 'null' || s === 'true' || s === 'false' || s === 'yes' || s === 'no' || s === 'on' || s === 'off') return true;
    if (/^[ \t]|^[#!&*?\-:>|\[\]{}%@`]|[,\[\]{}<>"\n]|^$|^\d+(\.\d+)?$/.test(s)) return true;
    if (s.includes(': ') || s.includes(' #') || s.startsWith(':') || s.endsWith(':') || s.endsWith(' ') || s.endsWith('\t')) return true;
    return false;
  }
  function quote(s) {
    if (needsQuotes(s)) {
      if (s.includes("'") && !s.includes('"')) return '"' + s + '"';
      return "'" + s.replace(/'/g, "''") + "'";
    }
    return s;
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
    else if (Array.isArray(v)) {
      if (v.length === 0) result = '[]';
      else if (depth >= flowLevel) result = '[' + v.map(item => _dump(item, depth + 1)).join(', ') + ']';
      else result = v.map(item => sp + '- ' + _dump(item, depth + 1).trimStart()).join('\n');
    } else if (typeof v === 'object') {
      const keys = Object.keys(v);
      if (keys.length === 0) result = '{}';
      else if (depth >= flowLevel) result = '{' + keys.map(k => quote(k) + ': ' + _dump(v[k], depth + 1)).join(', ') + '}';
      else result = keys.map(k => {
        const vv = v[k];
        const isScalar = vv === null || vv === undefined || typeof vv !== 'object';
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

// ── Public API ──────────────────────────────────────────

export class YamlSecurity {
  constructor(opts) {
    this._overrides = opts ? { ...opts } : {};
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
      const result = yamlToJS(yamlStr, this._getCfg());
      return { ok: true, result };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  parseAll(yamlStr) {
    try {
      const docs = parseAllYaml(yamlStr, this._getCfg());
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

// Static method
YamlSecurity.setLimits = setLimits;
