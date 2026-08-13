// ─────────────────────────────────────────────────────────────
// Schema validation: fluent builder + pure validate + JSON Schema
// bridge + incremental SAX validator for the streaming API.
// Zero dependencies; imported by src/index.js and bundled by rollup.
// ─────────────────────────────────────────────────────────────

function fail(errors, path, message, value) {
  errors.push({ path, message, value });
}

function seg(path, key) {
  return /^[A-Za-z_$][\w$]*$/.test(key) ? path + '.' + key : path + '[' + JSON.stringify(key) + ']';
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime();
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false;
    return true;
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    for (const k of ka) if (!(k in b) || !deepEqual(a[k], b[k])) return false;
    return true;
  }
  return false;
}

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

// ── ReDoS guard ────────────────────────────────────────────
// Native JS RegExp has no timeout, so a pattern with catastrophic backtracking
// (e.g. /(a+)+b/, /(a|aa)+/, /(\d+)*x/) runs in exponential time against a
// crafted input. The input is attacker-controlled (the YAML value), so every
// pattern a schema can invoke — `pattern` and `patternProperties` — is scanned
// once here for the known ambiguous families and refused with a clear error
// when found. Zero dependencies.
const RE_SAFE_CACHE = new Map();
const RE_SAFE_KEYS = new Set(['s', 'i', 'm', 'u', 'y', 'g', 'd', 'v']);

function compileSafePattern(pattern) {
  const isRe = pattern instanceof RegExp;
  const source = isRe ? pattern.source : String(pattern);
  const flags = isRe ? Array.from(pattern.flags).sort().join('') : '';
  const key = flags + '::' + source;
  const cached = RE_SAFE_CACHE.get(key);
  if (cached !== undefined) {
    if (cached.error) throw cached.error;
    return cached.re;
  }
  let re;
  let error = null;
  try {
    re = new RegExp(source, flags);
  } catch (e) {
    error = new TypeError('invalid regex pattern: ' + e.message);
  }
  if (!error) error = scanCatastrophic(source);
  if (error) {
    if (error instanceof TypeError && /invalid regex/.test(error.message)) {
      // Only cache genuine syntax errors; pass them through.
    }
    RE_SAFE_CACHE.set(key, { error });
    throw error;
  }
  RE_SAFE_CACHE.set(key, { re });
  return re;
}

// Returns a TypeError describing the hazard, or null when the pattern looks
// linear. Conservative: only flags unambiguous ambiguity; safe patterns
// (disjoint alternatives, single quantifiers) pass untouched.
function scanCatastrophic(source) {
  // Strip flags accidentally embedded in `source`: a RegExp.source never
  // contains flags, but pattern strings may look like "/.../g". Normalize.
  let s = source;
  if (source.length > 2 && source[0] === '/' ) {
    const end = source.lastIndexOf('/');
    if (end > 0) {
      const flagsPart = source.slice(end + 1);
      if (flagsPart !== '' && [...flagsPart].every((c) => RE_SAFE_KEYS.has(c))) {
        if (flagsPart.trim() !== '') s = source.slice(1, end);
      }
    }
  }
  try {
    return analyzeRegex(s);
  } catch (e) {
    return null; // unparseable by our scanner → let the engine decide (fail-open)
  }
}

// ── Minimal regex AST scanner ──────────────────────────────
// Tokenises the source (groups, alternation, quantifiers, char classes,
// classes, literals, anchors, lookarounds, backreferences) and flags the
// ambiguity families that cause exponential / runaway backtracking.
function analyzeRegex(src) {
  let pos = 0;
  const n = src.length;
  const fail = () => { throw new Error('unparseable'); };

  // Parse an alternation: seq ( '|' seq )*
  function parseAlt() {
    const branches = [parseSeq()];
    while (pos < n && src[pos] === '|') { pos++; branches.push(parseSeq()); }
    if (branches.length === 1) return branches[0];
    return { t: 'alt', branches };
  }
  // Parse a sequence of atoms (each atom may carry a quantifier).
  function parseSeq() {
    const children = [];
    while (pos < n) {
      const c = src[pos];
      if (c === '|' || c === ')') break;
      const atom = parseAtom();
      if (atom === null) break;
      // quantifier?
      const q = readQuantifier();
      children.push(q ? { t: 'q', node: atom, meta: q } : atom);
    }
    if (children.length === 0) return { t: 'empty' };
    if (children.length === 1) return children[0];
    return { t: 'seq', children };
  }
  function readQuantifier() {
    if (pos >= n) return null;
    const c = src[pos];
    if (c === '*' || c === '+' || c === '?') { pos++; return c; }
    if (c === '{') {
      const m = /^\{(\d+)(,)(\d*)?\}/.exec(src.slice(pos)) || /^\{(\d+)\}/.exec(src.slice(pos));
      if (!m) return null; // literal '{'
      pos += m[0].length;
      if (m[2] === ',') {
        const max = m[3] !== undefined && m[3] !== '' ? Number(m[3]) : undefined;
        return { min: Number(m[1]), max };
      }
      return { min: Number(m[1]), max: Number(m[1]) };
    }
    return null;
  }
  // Atom kinds: literal, class, dot, group/lookaround, anchor, backref.
  function parseAtom() {
    const c = src[pos];
    if (c === '(') {
      pos++;
      let kind = 'group';
      if (src[pos] === '?') {
        pos++;
        if (src[pos] === ':') { pos++; kind = 'ncap'; }
        else if (src[pos] === '=' || src[pos] === '!') { kind = 'look' + (src[pos] === '=' ? 'ahead' : 'neg'); pos++; }
        else if (src[pos] === '<' && (src[pos + 1] === '=' || src[pos + 1] === '!')) { kind = 'lookbehind' + (src[pos + 1] === '=' ? '':''); pos += 2; }
        else { // (?<name>...) or (?x) — named group or flags
          if (/^\?<[A-Za-z_][\w$]*>/.test(src.slice(pos))) { pos += src.slice(pos).match(/^\?<[A-Za-z_][\w$]*>/)[0].length; kind='ncap'; }
          else { // unknown (? extensions — treat group as ncap-ish, position on
            // scan until ':' or end to skip flags block
            let j = pos;
            while (j < n && src[j] !== ':' && src[j] !== ')') j++;
            if (j < n && src[j] === ':') pos = j + 1; else { pos = j; fail(); }
          }
        }
      }
      const inner = parseAlt();
      if (pos >= n || src[pos] !== ')') fail();
      pos++;
      return { t: 'grp', kind, inner };
    }
    if (c === '[') {
      let j = pos + 1;
      let negated = false;
      if (src[j] === '^') { negated = true; j++; }
      let set = '';
      while (j < n && src[j] !== ']') {
        if (src[j] === '\\' && j + 1 < n) { set += src[j] + src[j + 1]; j += 2; continue; }
        set += src[j]; j++;
      }
      if (j >= n) return null; // unterminated → ignore
      pos = j + 1;
      return negated ? { t: 'cls', negated: true } : { t: 'cls', klass: charset(set) };
    }
    if (c === '\\') {
      pos++;
      if (pos >= n) return null;
      const e = src[pos];
      pos++;
      if (/[1-9]/.test(e) || (e === 'k')) return { t: 'backref' }; // numeric or named backref
      if (e === 'd') return { t: 'cls', klass: 'digit' };
      if (e === 'D') return { t: 'cls', negated: true };
      if (e === 'w') return { t: 'cls', klass: 'word' };
      if (e === 'W') return { t: 'cls', negated: true };
      if (e === 's') return { t: 'cls', klass: 'space' };
      if (e === 'S') return { t: 'cls', negated: true };
      if (e === 'b' || e === 'B' || e === 'A' || e === 'z' || e === 'Z' || e === 'G') return { t: 'anchor' };
      if (e === 'p' || e === 'P') { // \p{...} / \P{...}
        if (src[pos] === '{') { let j = pos + 1; while (j < n && src[j] !== '}') j++; pos = j + 1; }
        return { t: 'cls', klass: e === 'p' ? 'any' : undefined, negated: e === 'P' };
      }
      return { t: 'lit', c: e };
    }
    if (c === '.') { pos++; return { t: 'cls', klass: 'any' }; }
    if (c === '^' || c === '$') { pos++; return { t: 'anchor' }; }
    if (c === '?') { pos++; return { t: 'empty' }; } // lone '?' in quantifier position already consumed
    if (c === '*' || c === '+') { pos++; return { t: 'empty' }; }
    if (c === '{' ) { pos++; return { t: 'lit', c: '{' }; }
    // plain literal
    pos++;
    return { t: 'lit', c };
  }
  // Approximate a char class by a compact token: a small literal set, or a
  // coarse class name (digit/word/space/any).
  function charset(body) {
    const chars = [];
    let coarse = null;
    let i = 0;
    const b = body;
    while (i < b.length) {
      const ch = b[i];
      if (ch === '\\' && i + 1 < b.length) {
        const e = b[i + 1];
        if (e === 'd') { coarse = coarse || (coarse === null ? 'digit' : 'multi'); }
        else if (e === 'w') { coarse = coalesce(coarse, 'word'); }
        else if (e === 's') { coarse = coalesce(coarse, 'space'); }
        else { const cc = unescape(e); if (cc !== null) chars.push(cc); else coarse = 'word'; }
        i += 2;
        continue;
      }
      if (ch === '-' && i > 0 && i < b.length - 1) {
        const from = b[i - 1]; const to = b[i + 1];
        chars.push(from + '-' + to); // range marker
        i += 2;
        continue;
      }
      chars.push(ch);
      i++;
    }
    if (coarse !== null) return coarse;
    if (chars.length === 0) return 'word';
    if (chars.length <= 4 && chars.every((x) => x.length === 1)) return { set: new Set(chars) };
    return 'multi';
  }
  function unescape(e) {
    if (e === 'n') return '\n';
    if (e === 't') return '\t';
    if (e === 'r') return '\r';
    if (e === '0') return '\0';
    if (/[xX]/.test(e)) return null;
    if (e === 'u') return null;
    return e;
  }
  function coalesce(cur, next) { return (cur === null || cur === next) ? next : 'multi'; }

  // Analysis: nullable / first-set / hazard propagation. Hazards found at any
  // depth are recorded in `foundHazard` (first wins) so parents propagate them.
  let foundHazard = null;
  function hazard(msg) {
    if (foundHazard === null) foundHazard = msg;
    return msg;
  }
  function analyze(node, inRepeat) {
    switch (node.t) {
      case 'empty': return { nullable: true, first: [] };
      case 'anchor': return { nullable: true, first: [] };
      case 'lit': return { nullable: false, first: [tagForChar(node.c)] };
      case 'backref': return { nullable: true, first: ['any'] };
      case 'cls': {
        if (node.negated) return { nullable: false, first: ['any'] };
        if (typeof node.klass === 'string') return { nullable: false, first: [node.klass] };
        if (node.klass && node.klass.set) return { nullable: false, first: ['set:' + [...node.klass.set].sort().join('')] };
        return { nullable: false, first: ['word'] };
      }
      case 'grp': return analyze(node.inner, inRepeat);
      case 'alt': {
        const infos = node.branches.map((b) => analyze(b, inRepeat));
        const nullable = infos.some((x) => x.nullable);
        const first = unionFirst(infos.map((x) => x.first));
        if (inRepeat && altAmbiguous(node.branches, infos)) hazard('ambiguous alternation inside a quantifier');
        return { nullable, first };
      }
      case 'seq': {
        let nullable = true;
        const first = [];
        for (const ch of node.children) {
          const a = analyze(ch, inRepeat);
          if (first.length === 0 && !a.nullable) first.push(...a.first);
          if (!a.nullable) nullable = false;
        }
        const seqHazard = siblingQuantifierOverlap(node.children);
        if (seqHazard) hazard(seqHazard);
        return { nullable, first };
      }
      case 'q': {
        const meta = node.meta;
        const unbounded = meta === '*' || meta === '+' || (typeof meta === 'object' && meta.max === undefined);
        const inner = analyze(node.node, unbounded || inRepeat);
        if (unbounded) {
          if (inner.nullable) hazard('quantified sub-expression can match the empty string and loop');
          else if (node.node.t === 'q' || isNestedRepeat(node.node)) hazard('nested repeats inside a quantifier');
        }
        return {
          nullable: (meta === '*' || meta === '?' || (typeof meta === 'object' && meta.min === 0)) ? true : inner.nullable,
          first: inner.first,
        };
      }
    }
    return { nullable: true, first: [] };
  }
  function isNestedRepeat(node) {
    if (node.t === 'q') return true;
    if (node.t === 'grp') return isNestedRepeat(node.inner);
    if (node.t === 'seq') return node.children.some(isNestedRepeat);
    return false;
  }
  function tagForChar(c) {
    if (/[0-9]/.test(c)) return 'digit';
    if (/[A-Za-z_]/.test(c)) return 'word';
    if (/\s/.test(c)) return 'space';
    return 'char:' + c;
  }
  function unionFirst(lists) {
    const out = [];
    for (const l of lists) for (const f of l) if (!out.includes(f)) out.push(f);
    return out;
  }

  // A branch "first token" precisely classifies what the branch can start with:
  // a concrete literal char, or a coarse class tag. Literal chars are compared
  // exactly (so `a` vs `b` don't falsely collide like coarse `word` tags do).
  function firstToken(node) {
    if (node === null) return null;
    switch (node.t) {
      case 'lit': return { lit: node.c };
      case 'cls': {
        if (node.negated) return { tag: 'neg' };
        if (typeof node.klass === 'string') {
          if (node.klass === 'any') return { tag: 'any' };
          return { tag: node.klass };
        }
        if (node.klass && node.klass.set) {
          if (node.klass.set.size === 1) return { lit: [...node.klass.set][0] };
          return { tag: 'multi' };
        }
        return { tag: 'multi' };
      }
      case 'grp': return firstToken(node.inner);
      case 'seq': {
        for (const ch of node.children) {
          if (ch.t === 'anchor' || (ch.t === 'q' && (ch.meta === '*' || ch.meta === '?' || (typeof ch.meta === 'object' && ch.meta.min === 0)))) continue;
          const t = firstToken(ch);
          if (t !== null) return t;
        }
        return null;
      }
      case 'q': return firstToken(node.node);
      case 'alt': return { tag: 'multi' };
      default: return null;
    }
  }
  function litInTag(ch, tag) {
    if (tag === 'any' || tag === 'neg' || tag === 'multi') return false;
    if (tag === 'word') return /[A-Za-z0-9_]/.test(ch);
    if (tag === 'digit') return /[0-9]/.test(ch);
    if (tag === 'space') return /\s/.test(ch);
    return false;
  }
  function tokenOverlap(a, b) {
    if (!a || !b) return false;
    if (a.lit !== undefined && b.lit !== undefined) return a.lit === b.lit;
    if (a.lit !== undefined && b.tag !== undefined) return litInTag(a.lit, b.tag);
    if (b.lit !== undefined && a.tag !== undefined) return litInTag(b.lit, a.tag);
    if (a.tag === 'multi' || b.tag === 'multi') return false;
    if (a.tag === b.tag) return true;
    if (a.tag === 'any' || b.tag === 'any') return true;
    if (a.tag === 'neg' || b.tag === 'neg') return true;
    if ((a.tag === 'word' && b.tag === 'digit') || (a.tag === 'digit' && b.tag === 'word')) return true;
    return false;
  }
  // Alternation ambiguity: two branches are ambiguous when one's language is a
  // prefix of the other's or both share an overlapping first char — (a|aa),
  // (x|xy), (a|), (a*|b) are; (ab|ac), (name|id), (a|b) and (ab|cd) are not.
  // A nullable branch collides with every consuming branch inside a repeat
  // (each consumed char could instead be the empty branch), so it is flagged.
  function altAmbiguous(branches, infos) {
    const tokens = branches.map((b) => firstToken(b));
    for (let i = 0; i < branches.length; i++) {
      for (let j = i + 1; j < branches.length; j++) {
        if (infos[i].nullable !== infos[j].nullable) return true;
        if (tokenOverlap(tokens[i], tokens[j])) return true;
      }
    }
    return false;
  }
  function siblingQuantifierOverlap(children) {
    // Adjacent unbounded repeats with overlapping first chars — a+a+, \w+\w+,
    // \d+\w+ — are ambiguous (quadratic/exponential). A non-repeat atom breaks
    // adjacency, so a+@b+ / [^@\s]+@[^@\s]+ stay linear and are allowed.
    let lastToken = null;
    for (const ch of children) {
      const isUnbounded = ch.t === 'q' && (ch.meta === '*' || ch.meta === '+' || (typeof ch.meta === 'object' && ch.meta.max === undefined));
      if (isUnbounded) {
        const t = firstToken(ch.node);
        if (lastToken !== null && tokenOverlap(t, lastToken)) {
          return 'adjacent unbounded repeats with overlapping first chars';
        }
        if (t !== null) lastToken = t;
      } else {
        lastToken = null; // a consuming non-repeat atom separates the repeats
      }
    }
    return null;
  }

  const root = parseAlt();
  const info = analyze(root, false);
  if (foundHazard !== null) return new TypeError('unsafe regex pattern — possible catastrophic backtracking (' + foundHazard + ')');
  return null;
}

// ── Fluent builders ─────────────────────────────────────────

function string(o = {}) { return { __s: 'string', ...o }; }
function int(o = {}) { return { __s: 'int', ...o }; }
function number(o = {}) { return { __s: 'float', ...o }; }
function float(o = {}) { return { __s: 'float', ...o }; }
function bool(o = {}) { return { __s: 'bool', ...o }; }
function nullType(o = {}) { return { __s: 'null', ...o }; }
function any() { return { __s: 'any' }; }
function never() { return { __s: 'never' }; }
function enumType(values) { return { __s: 'enum', values }; }
function timestamp(o = {}) { return { __s: 'timestamp', ...o }; }
function array(items, o = {}) { return { __s: 'array', items, ...o }; }
function tuple(items, o = {}) { return { __s: 'tuple', items, ...o }; }
function object(shape, o = {}) { return { __s: 'object', shape: shape || {}, ...o }; }
function record(values) { return { __s: 'record', values }; }
function optional(spec) { return { __s: 'optional', spec }; }
function nullable(spec) { return { __s: 'nullable', spec }; }
function oneOf(specs) { return { __s: 'oneOf', specs }; }
function anyOf(specs) { return { __s: 'anyOf', specs }; }
function allOf(specs) { return { __s: 'allOf', specs }; }
function not(specs) { return { __s: 'not', spec: specs }; }
function custom(fn) { return { __s: 'custom', fn }; }

// ── Pure value validation ───────────────────────────────────

function checkNumberRange(spec, value, errors, path) {
  if (spec.min !== undefined && value < spec.min) fail(errors, path, 'must be >= ' + spec.min, value);
  if (spec.max !== undefined && value > spec.max) fail(errors, path, 'must be <= ' + spec.max, value);
  if (spec.exclusiveMin !== undefined && value <= spec.exclusiveMin) fail(errors, path, 'must be > ' + spec.exclusiveMin, value);
  if (spec.exclusiveMax !== undefined && value >= spec.exclusiveMax) fail(errors, path, 'must be < ' + spec.exclusiveMax, value);
  if (spec.multipleOf !== undefined && value % spec.multipleOf !== 0) fail(errors, path, 'must be a multiple of ' + spec.multipleOf, value);
}

function checkStringRange(spec, value, errors, path) {
  if (spec.min !== undefined && value.length < spec.min) fail(errors, path, 'must be at least ' + spec.min + ' chars', value);
  if (spec.max !== undefined && value.length > spec.max) fail(errors, path, 'must be at most ' + spec.max + ' chars', value);
  if (spec.pattern !== undefined && !compileSafePattern(spec.pattern).test(value)) fail(errors, path, 'does not match pattern /' + spec.pattern + '/', value);
  if (spec.enum !== undefined && !spec.enum.includes(value)) fail(errors, path, 'must be one of [' + spec.enum.join(', ') + ']', value);
}

function checkValue(value, spec, path, errors, ctx) {
  if (spec == null) return;
  switch (spec.__s) {
    case 'optional':
      if (value !== undefined) checkValue(value, spec.spec, path, errors, ctx);
      return;
    case 'nullable':
      if (value === null) return;
      checkValue(value, spec.spec, path, errors, ctx);
      return;
    case 'any': return;
    case 'never': fail(errors, path, 'no value allowed', value); return;
    case 'null':
      if (value !== null) fail(errors, path, 'expected null', value);
      return;
    case 'bool':
      if (typeof value !== 'boolean') fail(errors, path, 'expected boolean', value);
      return;
    case 'string':
      if (typeof value !== 'string') { fail(errors, path, 'expected string', value); return; }
      checkStringRange(spec, value, errors, path);
      return;
    case 'int':
      if (typeof value !== 'number' || !Number.isInteger(value)) { fail(errors, path, 'expected integer', value); return; }
      checkNumberRange(spec, value, errors, path);
      return;
    case 'float':
      if (typeof value !== 'number' || !Number.isFinite(value)) { fail(errors, path, 'expected number', value); return; }
      checkNumberRange(spec, value, errors, path);
      return;
    case 'timestamp':
      if (value instanceof Date) {
        if (isNaN(value.getTime())) fail(errors, path, 'invalid date', value);
        return;
      }
      if (typeof value === 'string' && ISO_DATE_RE.test(value.trim())) return;
      fail(errors, path, 'expected ISO 8601 date', value);
      return;
    case 'enum':
      if (!spec.values.some((v) => deepEqual(value, v)))
        fail(errors, path, 'must be one of [' + spec.values.map((v) => JSON.stringify(v)).join(', ') + ']', value);
      return;
    case 'array': {
      if (!Array.isArray(value)) { fail(errors, path, 'expected array', value); return; }
      if (spec.minItems !== undefined && value.length < spec.minItems) fail(errors, path, 'must have at least ' + spec.minItems + ' items', value);
      if (spec.maxItems !== undefined && value.length > spec.maxItems) fail(errors, path, 'must have at most ' + spec.maxItems + ' items', value);
      if (spec.uniqueItems) {
        for (let i = 0; i < value.length; i++)
          for (let j = i + 1; j < value.length; j++)
            if (deepEqual(value[i], value[j])) fail(errors, path + '[' + j + ']', 'duplicate item', value[j]);
      }
      const itemSpec = spec.items || { __s: 'any' };
      value.forEach((it, i) => checkValue(it, itemSpec, path + '[' + i + ']', errors, ctx));
      return;
    }
    case 'tuple': {
      if (!Array.isArray(value)) { fail(errors, path, 'expected array', value); return; }
      if (value.length !== spec.items.length)
        fail(errors, path, 'expected exactly ' + spec.items.length + ' items, got ' + value.length, value);
      value.forEach((it, i) => checkValue(it, spec.items[i] || { __s: 'any' }, path + '[' + i + ']', errors, ctx));
      return;
    }
    case 'object': {
      if (!isPlainObject(value)) { fail(errors, path, 'expected object', value); return; }
      const keys = Object.keys(value);
      if (spec.minProps !== undefined && keys.length < spec.minProps) fail(errors, path, 'must have at least ' + spec.minProps + ' properties', value);
      if (spec.maxProps !== undefined && keys.length > spec.maxProps) fail(errors, path, 'must have at most ' + spec.maxProps + ' properties', value);
      const shape = spec.shape || {};
      let required;
      if (Array.isArray(spec.required)) required = spec.required;
      else required = Object.keys(shape).filter((k) => !shape[k] || shape[k].__s !== 'optional');
      for (const k of required) {
        if (!(k in value)) fail(errors, seg(path, k), 'missing required property "' + k + '"', undefined);
      }
      const strict = spec.allowExtra === undefined ? true : spec.allowExtra !== true;
      for (const k of keys) {
        const v = value[k];
        if (shape[k] !== undefined) { checkValue(v, shape[k], seg(path, k), errors, ctx); continue; }
        if (spec.patternProperties) {
          const match = Object.keys(spec.patternProperties).find((p) => compileSafePattern(p).test(k));
          if (match) { checkValue(v, spec.patternProperties[match], seg(path, k), errors, ctx); continue; }
        }
        if (spec.additionalProperties !== undefined && spec.additionalProperties !== false) {
          checkValue(v, spec.additionalProperties, seg(path, k), errors, ctx);
          continue;
        }
        if (strict && spec.additionalProperties !== false) fail(errors, seg(path, k), 'unexpected property "' + k + '"', v);
      }
      return;
    }
    case 'record': {
      if (!isPlainObject(value)) { fail(errors, path, 'expected object', value); return; }
      for (const k of Object.keys(value)) checkValue(value[k], spec.values, seg(path, k), errors, ctx);
      return;
    }
    case 'oneOf': {
      let count = 0;
      for (const alt of spec.specs) {
        const e = [];
        checkValue(value, alt, path, e, ctx);
        if (e.length === 0) count++;
      }
      if (count !== 1) fail(errors, path, 'expected exactly one alternative to match (' + count + ' matched)', value);
      return;
    }
    case 'anyOf': {
      for (const alt of spec.specs) {
        const e = [];
        checkValue(value, alt, path, e, ctx);
        if (e.length === 0) return;
      }
      fail(errors, path, 'did not match any alternative', value);
      return;
    }
    case 'allOf':
      for (const alt of spec.specs) checkValue(value, alt, path, errors, ctx);
      return;
    case 'not': {
      const e = [];
      checkValue(value, spec.spec, path, e, ctx);
      if (e.length === 0) fail(errors, path, 'should not match the schema', value);
      return;
    }
    case 'custom': {
      if (typeof spec.fn !== 'function') return;
      let res;
      try {
        res = spec.fn(value, { path, errors, validate: (v, s2) => validate(v, s2) });
      } catch (e) {
        res = e && e.message ? e.message : String(e);
      }
      if (res === false) fail(errors, path, 'failed custom validation', value);
      else if (typeof res === 'string') fail(errors, path, res, value);
      return;
    }
    default:
      return;
  }
}

function validate(value, spec) {
  const errors = [];
  checkValue(value, spec, '$', errors, {});
  return { ok: errors.length === 0, errors };
}

// ── Spec introspection helpers (used by the SAX validator) ──

function unwrapSpec(sp) {
  let x = sp;
  while (x && (x.__s === 'optional' || x.__s === 'nullable')) x = x.spec;
  return x;
}

function kindOf(sp) {
  const u = unwrapSpec(sp);
  if (u.__s === 'object' || u.__s === 'record') return 'obj';
  if (u.__s === 'array' || u.__s === 'tuple') return 'arr';
  return 'scalar';
}

function describe(sp) {
  const u = unwrapSpec(sp);
  const names = { string: 'string', int: 'integer', float: 'number', bool: 'boolean', null: 'null', any: 'any value', never: 'no value', enum: 'one of the allowed values', timestamp: 'ISO 8601 date', array: 'array', tuple: 'tuple', object: 'object', record: 'object', optional: 'optional value', nullable: 'nullable value', oneOf: 'one of several alternatives', anyOf: 'any of several alternatives', allOf: 'all alternatives', not: 'a value not matching a schema', custom: 'custom constraint' };
  return names[u.__s] || 'value';
}

function requiredKeysOf(spec) {
  const u = unwrapSpec(spec);
  if (u.__s !== 'object') return [];
  const shape = u.shape || {};
  if (Array.isArray(u.required)) return u.required;
  return Object.keys(shape).filter((k) => !shape[k] || shape[k].__s !== 'optional');
}

function pickCombinatorBranch(spec, wantKind) {
  const u = unwrapSpec(spec);
  if (u.__s === 'oneOf' || u.__s === 'anyOf' || u.__s === 'allOf') {
    const list = u.specs || [];
    return list.find((a) => kindOf(a) === wantKind) || null;
  }
  if (u.__s === 'not') return null;
  return null;
}

// ── Incremental SAX validator ───────────────────────────────
//
// Consumes the StreamParser's event stream one event at a time and
// reports violations incrementally, so a bad document can be rejected
// before the rest of the input is consumed. Structure-level constraints
// (object/array/record/tuple/scalar/range) are exact. OneOf/anyOf/allOf/
// not/custom and deep uniqueness are authoritative only when a materialized
// document is available (buffered mode, the default) — see documentEnd().

function createStreamValidator(spec) {
  const rootSpec = spec;
  let rootFrame = { kind: 'root', spec: rootSpec, path: '$', done: false };
  const stack = [];
  let live = [];
  let pending = [];
  let finalErrors = [];

  function report(e) {
    pending.push(e);
    live.push(e);
  }

  function takeNewViolations() {
    if (pending.length === 0) return pending;
    const out = pending;
    pending = [];
    return out;
  }

  function frameValueSpec(fr) {
    if (fr.kind === 'root') return fr.spec;
    if (fr.kind === 'arr') {
      const sp = fr.spec;
      if (sp.__s === 'tuple') return sp.items[fr.count] || { __s: 'never' };
      if (sp.__s === 'array') return sp.items || { __s: 'any' };
      return { __s: 'any' };
    }
    return fr.valueSpec;
  }

  function childPath(fr, key) {
    if (fr.kind === 'obj') return seg(fr.path, key || '');
    if (fr.kind === 'arr') return fr.path + '[' + fr.count + ']';
    return '$';
  }

  function openCollection(collectionKind) {
    const parent = stack.length ? stack[stack.length - 1] : rootFrame;
    if (rootFrame.done) return;
    const slot = frameValueSpec(parent);
    const childP = childPath(parent, parent.kind === 'obj' ? parent.pendingKey : undefined);
    let concrete = unwrapSpec(slot);
    const branch = pickCombinatorBranch(slot, collectionKind);
    if (branch) concrete = unwrapSpec(branch);
    if (kindOf(slot) === 'scalar' && concrete.__s !== 'never') {
      report({ path: childP, message: 'expected ' + describe(slot) + ' but got ' + (collectionKind === 'obj' ? 'object' : 'array'), value: undefined });
      concrete = { __s: 'any' };
    }
    const frame = {
      kind: collectionKind,
      spec: concrete,
      path: childP,
      count: 0,
      seen: new Set(),
      expectKey: true,
      pendingKey: null,
      valueSpec: { __s: 'any' },
    };
    stack.push(frame);
  }

  function finishCollection() {
    const top = stack.pop();
    if (!top) return;
    if (top.kind === 'obj') {
      for (const k of requiredKeysOf(top.spec)) {
        if (!top.seen.has(k)) report({ path: seg(top.path, k), message: 'missing required property "' + k + '"', value: undefined });
      }
      if (top.spec.minProps !== undefined && top.seen.size < top.spec.minProps)
        report({ path: top.path, message: 'must have at least ' + top.spec.minProps + ' properties', value: undefined });
      if (top.spec.maxProps !== undefined && top.seen.size > top.spec.maxProps)
        report({ path: top.path, message: 'must have at most ' + top.spec.maxProps + ' properties', value: undefined });
    } else {
      if (top.spec.minItems !== undefined && top.count < top.spec.minItems)
        report({ path: top.path, message: 'must have at least ' + top.spec.minItems + ' items', value: undefined });
      if (top.spec.maxItems !== undefined && top.count > top.spec.maxItems)
        report({ path: top.path, message: 'must have at most ' + top.spec.maxItems + ' items', value: undefined });
    }
    const parent = stack.length ? stack[stack.length - 1] : rootFrame;
    if (parent.kind === 'obj') parent.expectKey = true;
    if (parent.kind === 'arr') parent.count++;
    if (parent.kind === 'root') rootFrame.done = true;
  }

  return {
    get finalErrors() { return finalErrors; },
    get violations() { return live; },
    takeNewViolations() { return takeNewViolations(); },
    documentStart() {
      stack.length = 0;
      rootFrame = { kind: 'root', spec: rootSpec, path: '$', done: false };
      pending.length = 0;
      live = [];
      finalErrors = [];
    },
    mappingStart() { openCollection('obj'); },
    sequenceStart() { openCollection('arr'); },
    mappingEnd() { finishCollection(); },
    sequenceEnd() { finishCollection(); },
    key(k) {
      const top = stack[stack.length - 1];
      if (!top || top.kind !== 'obj') return;
      top.expectKey = false;
      top.pendingKey = k;
      top.seen.add(k);
      const sp = top.spec;
      if (sp.__s === 'record') { top.valueSpec = sp.values; return; }
      if (sp.__s === 'object') {
        const shape = sp.shape || {};
        if (shape[k] !== undefined) { top.valueSpec = shape[k]; return; }
        if (sp.patternProperties) {
          const m = Object.keys(sp.patternProperties).find((p) => compileSafePattern(p).test(k));
          if (m) { top.valueSpec = sp.patternProperties[m]; return; }
        }
        if (sp.additionalProperties !== undefined && sp.additionalProperties !== false) { top.valueSpec = sp.additionalProperties; return; }
        if (sp.allowExtra === true) { top.valueSpec = { __s: 'any' }; return; }
        report({ path: seg(top.path, k), message: 'unexpected property "' + k + '"', value: k });
        top.valueSpec = { __s: 'any' };
        return;
      }
      top.valueSpec = { __s: 'any' };
    },
    scalar(v) {
      const parent = stack.length ? stack[stack.length - 1] : rootFrame;
      if (rootFrame.done) return;
      const childP = childPath(parent, parent.kind === 'obj' ? parent.pendingKey : undefined);
      const errors = [];
      checkValue(v, frameValueSpec(parent), childP, errors, {});
      for (const e of errors) report(e);
      if (parent.kind === 'arr') parent.count++;
      if (parent.kind === 'obj') parent.expectKey = true;
      if (parent.kind === 'root') rootFrame.done = true;
    },
    // Root is the materialized document (buffered mode). When available,
    // run the authoritative full validation and merge any combinator-level
    // findings that the incremental pass could not express.
    documentEnd(root) {
      if (root !== undefined) {
        const authoritative = validate(root, rootSpec).errors;
        const seen = new Set(live.map((e) => e.path + '\u0000' + e.message));
        for (const e of authoritative) {
          if (!seen.has(e.path + '\u0000' + e.message)) report(e);
        }
        finalErrors = authoritative;
      } else {
        finalErrors = live.slice();
      }
      return takeNewViolations();
    },
  };
}

// ── JSON Schema bridge ──────────────────────────────────────

function fromJSONSchema(js, opts = {}) {
  if (js === true) return { __s: 'any' };
  if (js === false) return { __s: 'never' };
  if (js == null || typeof js !== 'object') throw new Error('invalid JSON Schema');

  const memo = new Map();
  function conv(node, depth) {
    if (node === true) return { __s: 'any' };
    if (node === false) return { __s: 'never' };
    if (typeof node !== 'object' || Array.isArray(node)) throw new Error('invalid JSON Schema node');
    if (depth > 64) throw new Error('JSON Schema too deeply nested');
    if (memo.has(node)) return memo.get(node);

    if (node.$ref !== undefined) {
      const ref = node.$ref;
      let target;
      if (ref === '#') target = js;
      else if (ref.startsWith('#/')) {
        const parts = ref.slice(2).split('/').filter(Boolean).map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'));
        target = js;
        for (const p of parts) {
          if (target == null) throw new Error('unresolved $ref "' + ref + '"');
          target = target[p];
        }
      } else {
        if (opts.resolveExternal) target = opts.resolveExternal(ref);
        else throw new Error('unsupported external $ref "' + ref + '"');
      }
      const result = conv(target, depth + 1);
      memo.set(node, result);
      return result;
    }

    if (node.oneOf) { const specs = node.oneOf.map((c) => conv(c, depth + 1)); return { __s: 'oneOf', specs }; }
    if (node.anyOf) { const specs = node.anyOf.map((c) => conv(c, depth + 1)); return { __s: 'anyOf', specs }; }
    if (node.allOf) {
      const specs = node.allOf.map((c) => conv(c, depth + 1));
      const inner = { __s: 'allOf', specs };
      memo.set(node, inner);
      return inner;
    }
    if (node.not) return { __s: 'not', spec: conv(node.not, depth + 1) };
    if (node.enum !== undefined) return { __s: 'enum', values: node.enum };
    if (node.const !== undefined) return { __s: 'enum', values: [node.const] };

    const types = Array.isArray(node.type) ? node.type : (node.type ? [node.type] : null);
    const coreType = types ? types.find((t) => t !== 'null') : null;
    const nullable = types ? types.includes('null') : false;
    const wrap = (sp) => (nullable ? { __s: 'nullable', spec: sp } : sp);

    let sp;
    if (coreType === 'string') {
      sp = { __s: 'string' };
      if (node.minLength !== undefined) sp.min = node.minLength;
      if (node.maxLength !== undefined) sp.max = node.maxLength;
      if (node.pattern !== undefined) sp.pattern = node.pattern;
      if (node.format === 'date' || node.format === 'date-time') return wrap({ __s: 'timestamp' });
      return wrap(sp);
    }
    if (coreType === 'integer') {
      sp = { __s: 'int' };
      if (node.minimum !== undefined) sp.min = node.minimum;
      if (node.maximum !== undefined) sp.max = node.maximum;
      if (node.exclusiveMinimum !== undefined) sp.exclusiveMin = node.exclusiveMinimum;
      if (node.exclusiveMaximum !== undefined) sp.exclusiveMax = node.exclusiveMaximum;
      if (node.multipleOf !== undefined) sp.multipleOf = node.multipleOf;
      return wrap(sp);
    }
    if (coreType === 'number') {
      sp = { __s: 'float' };
      if (node.minimum !== undefined) sp.min = node.minimum;
      if (node.maximum !== undefined) sp.max = node.maximum;
      if (node.exclusiveMinimum !== undefined) sp.exclusiveMin = node.exclusiveMinimum;
      if (node.exclusiveMaximum !== undefined) sp.exclusiveMax = node.exclusiveMaximum;
      if (node.multipleOf !== undefined) sp.multipleOf = node.multipleOf;
      return wrap(sp);
    }
    if (coreType === 'boolean') return wrap({ __s: 'bool' });
    if (coreType === 'null') return wrap({ __s: 'null' });
    if (coreType === 'array') {
      if (Array.isArray(node.items)) {
        const items = node.items.map((c) => conv(c, depth + 1));
        return wrap({ __s: 'tuple', items });
      }
      sp = { __s: 'array' };
      if (node.items !== undefined) sp.items = conv(node.items, depth + 1);
      if (node.minItems !== undefined) sp.minItems = node.minItems;
      if (node.maxItems !== undefined) sp.maxItems = node.maxItems;
      if (node.uniqueItems === true) sp.uniqueItems = true;
      return wrap(sp);
    }
    if (coreType === 'object' || node.properties || node.required || node.patternProperties || node.additionalProperties !== undefined) {
      const shape = {};
      for (const [k, v] of Object.entries(node.properties || {})) shape[k] = conv(v, depth + 1);
      sp = { __s: 'object', shape };
      if (Array.isArray(node.required)) sp.required = node.required;
      if (node.minProperties !== undefined) sp.minProps = node.minProperties;
      if (node.maxProperties !== undefined) sp.maxProps = node.maxProperties;
      if (node.additionalProperties === false) sp.allowExtra = false;
      else if (node.additionalProperties && node.additionalProperties !== true) sp.additionalProperties = conv(node.additionalProperties, depth + 1);
      if (node.patternProperties) {
        sp.patternProperties = {};
        for (const [p, v] of Object.entries(node.patternProperties)) sp.patternProperties[p] = conv(v, depth + 1);
      }
      return wrap(sp);
    }
    sp = { __s: 'any' };
    if (node.minimum !== undefined) { sp = { __s: 'float', min: node.minimum }; }
    else if (node.maximum !== undefined) { sp = { __s: 'float', max: node.maximum }; }
    else if (node.items !== undefined) { sp = { __s: 'array', items: conv(node.items, depth + 1) }; }
    return sp;
  }
  return conv(js, 0);
}

function toJSONSchema(sp) {
  switch (sp.__s) {
    case 'string': {
      const o = { type: 'string' };
      if (sp.min !== undefined) o.minLength = sp.min;
      if (sp.max !== undefined) o.maxLength = sp.max;
      if (sp.pattern !== undefined) o.pattern = sp.pattern;
      return o;
    }
    case 'int': {
      const o = { type: 'integer' };
      if (sp.min !== undefined) o.minimum = sp.min;
      if (sp.max !== undefined) o.maximum = sp.max;
      if (sp.exclusiveMin !== undefined) o.exclusiveMinimum = sp.exclusiveMin;
      if (sp.exclusiveMax !== undefined) o.exclusiveMaximum = sp.exclusiveMax;
      if (sp.multipleOf !== undefined) o.multipleOf = sp.multipleOf;
      return o;
    }
    case 'float': {
      const o = { type: 'number' };
      if (sp.min !== undefined) o.minimum = sp.min;
      if (sp.max !== undefined) o.maximum = sp.max;
      if (sp.exclusiveMin !== undefined) o.exclusiveMinimum = sp.exclusiveMin;
      if (sp.exclusiveMax !== undefined) o.exclusiveMaximum = sp.exclusiveMax;
      if (sp.multipleOf !== undefined) o.multipleOf = sp.multipleOf;
      return o;
    }
    case 'bool': return { type: 'boolean' };
    case 'null': return { type: 'null' };
    case 'any': return {};
    case 'never': return false;
    case 'timestamp': return { type: 'string', format: 'date-time' };
    case 'enum': return { enum: sp.values };
    case 'array': {
      const o = { type: 'array' };
      if (sp.items) o.items = toJSONSchema(sp.items);
      if (sp.minItems !== undefined) o.minItems = sp.minItems;
      if (sp.maxItems !== undefined) o.maxItems = sp.maxItems;
      if (sp.uniqueItems) o.uniqueItems = true;
      return o;
    }
    case 'tuple': {
      const o = { type: 'array', items: sp.items.map((i) => toJSONSchema(i)), minItems: sp.items.length, maxItems: sp.items.length };
      return o;
    }
    case 'object': {
      const o = { type: 'object' };
      const properties = {};
      const required = [];
      const shape = sp.shape || {};
      const req = Array.isArray(sp.required) ? sp.required : Object.keys(shape).filter((k) => !shape[k] || shape[k].__s !== 'optional');
      for (const [k, v] of Object.entries(shape)) {
        properties[k] = toJSONSchema(v);
        if (req.includes(k)) required.push(k);
      }
      if (Object.keys(properties).length) o.properties = properties;
      if (required.length) o.required = required;
      if (sp.allowExtra === true) o.additionalProperties = true;
      else if (sp.additionalProperties) o.additionalProperties = toJSONSchema(sp.additionalProperties);
      else o.additionalProperties = false;
      if (sp.minProps !== undefined) o.minProperties = sp.minProps;
      if (sp.maxProps !== undefined) o.maxProperties = sp.maxProps;
      return o;
    }
    case 'record': return { type: 'object', additionalProperties: toJSONSchema(sp.values) };
    case 'optional': return toJSONSchema(sp.spec);
    case 'nullable': {
      const inner = toJSONSchema(sp.spec);
      if (Array.isArray(inner.type)) inner.type = inner.type.concat(['null']);
      else if (inner.type) inner.type = [inner.type, 'null'];
      return inner;
    }
    case 'oneOf': return { oneOf: sp.specs.map((x) => toJSONSchema(x)) };
    case 'anyOf': return { anyOf: sp.specs.map((x) => toJSONSchema(x)) };
    case 'allOf': return { allOf: sp.specs.map((x) => toJSONSchema(x)) };
    case 'not': return { not: toJSONSchema(sp.spec) };
    case 'custom': return {};
    default: return {};
  }
}

const s = {
  string, int, number, float, bool, null: nullType, any, never,
  enum: enumType, timestamp, array, tuple, object, record,
  optional, nullable, oneOf, anyOf, allOf, not, custom,
  fromJSONSchema,
};

export {
  s, string, int, number, float, bool, nullType, any, never,
  enumType, timestamp, array, tuple, object, record,
  optional, nullable, oneOf, anyOf, allOf, not, custom,
  validate, createStreamValidator, fromJSONSchema, toJSONSchema,
};
