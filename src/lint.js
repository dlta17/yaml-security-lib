// YAML linter for yaml-security-lib: syntax + security + basic style rules.
// Pure module: the parser is injected via `parseFn` so it stays dependency-free.

export const LINT_RULES = Object.freeze({
  'syntax-error': 'error',
  'duplicate-key': 'error',
  'anchor-bomb': 'error',
  'prototype-pollution': 'error',
  'unsafe-tag': 'warning',
  'hidden-character': 'warning',
  'merge-key': 'warning',
  'inconsistent-eol': 'warning',
  'trailing-spaces': 'warning',
  'line-length': 'warning',
  'missing-newline-at-eof': 'warning',
  'space-after-colon': 'warning',
  'space-after-dash': 'warning',
  'truthy-yes-no': 'warning',
});

const RULE_NAMES = Object.freeze(Object.keys(LINT_RULES));
const DEFAULT_MAX_LINE_LENGTH = 120;

const SECURITY_MATCHERS = [
  [/duplicate key/i, 'duplicate-key'],
  [/circular alias|alias depth|alias expansion|expansion limit|too many aliases/i, 'anchor-bomb'],
  [/prototype pollution|cannot set key/i, 'prototype-pollution'],
];

const TRUTHY_WORDS = /^(yes|no|on|off)$/i;

// Tags for code-executing language plugins (js-yaml FULL_SCHEMA, PyYAML, …).
const UNSAFE_TAG_RE = /!!\s*(js|python|ruby|perl|php)\s*\/[A-Za-z0-9_.$-]*/i;
// Invisible & bidirectional text controls used in "trojan source" attacks.
const HIDDEN_CHARS_RE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2061\u2066-\u2069\uFEFF]/;
// YAML merge key `<<` — aliased merges can amplify entity expansion.
const MERGE_KEY_RE = /(?:^|[\s\t](?:-|&)\s*|[\s\t])<<\s*:/;

function resolveRules(rules) {
  const out = {};
  if (rules === undefined || rules === null) rules = {};
  if (Array.isArray(rules)) {
    for (const name of RULE_NAMES) out[name] = 'off';
    for (const name of rules) {
      if (RULE_NAMES.includes(name)) out[name] = LINT_RULES[name];
    }
    return out;
  }
  for (const key of Object.keys(rules)) {
    if (!RULE_NAMES.includes(key))
      throw new TypeError('lint: unknown rule "' + key + '". Valid rules: ' + RULE_NAMES.join(', '));
    const v = rules[key];
    if (v === false || v === 0 || v === 'off') out[key] = 'off';
    else if (v === true || v === 'error') out[key] = 'error';
    else if (v === 'warn' || v === 'warning') out[key] = 'warning';
    else throw new TypeError('lint: bad severity for rule "' + key + '": ' + v);
  }
  for (const name of RULE_NAMES) if (out[name] === undefined) out[name] = LINT_RULES[name];
  return out;
}

function parseErrorMsg(err) {
  const m = /at line (\d+)(?:, column (\d+))?:\s*([^\n]*)/.exec(err);
  if (m) return { line: Number(m[1]), column: m[2] !== undefined ? Number(m[2]) : 1, message: m[3] };
  return { line: 1, column: 1, message: String(err).split('\n')[0] };
}

function classifyError(err) {
  for (const [re, rule] of SECURITY_MATCHERS) {
    if (re.test(err)) return { rule, message: parseErrorMsg(err).message };
  }
  return { rule: 'syntax-error', message: parseErrorMsg(err).message };
}

function leadingSpaces(line) {
  let n = 0;
  while (n < line.length && line[n] === ' ') n++;
  return n;
}

function stripComment(s) {
  let quote = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (quote === '"') { if (ch === '\\') i++; else if (ch === '"') quote = null; }
      else { if (ch === "'" && s[i + 1] === "'") i++; else if (ch === "'") quote = null; }
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '#' && (i === 0 || s[i - 1] === ' ' || s[i - 1] === '\t')) return s.slice(0, i);
  }
  return s;
}

function firstColonCheck(line) {
  let depth = 0;
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (quote === '"') { if (ch === '\\') { i++; continue; } if (ch === '"') quote = null; }
      else { if (ch === "'" && line[i + 1] === "'") { i++; continue; } if (ch === "'") quote = null; }
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '[' || ch === '{') { depth++; continue; }
    if (ch === ']' || ch === '}') { if (depth > 0) depth--; continue; }
    if (ch === '#' && (i === 0 || line[i - 1] === ' ' || line[i - 1] === '\t')) return -1;
    if (ch === ':' && depth === 0) return i;
  }
  return -1;
}

function keyColonStrict(line) {
  const ci = firstColonCheck(line);
  if (ci < 0) return -1;
  const next = line[ci + 1];
  if (next === undefined || next === ' ' || next === '\t') return ci;
  return -1;
}

function runStyleRules(yaml, lines, rules, maxLineLength, issues) {
  const n = lines.length;
  let inBlock = false;
  let blockIndent = 0;
  for (let idx = 0; idx < n; idx++) {
    const lineNo = idx + 1;
    const line = lines[idx];
    const trimmed = line.trim();

    if (rules['trailing-spaces'] !== 'off') {
      const m = /[ \t]+$/.exec(line);
      if (m) issues.push({ rule: 'trailing-spaces', severity: rules['trailing-spaces'], message: 'trailing whitespace', line: lineNo, column: m.index + 1, snippet: line });
    }
    if (rules['line-length'] !== 'off') {
      if (line.length > maxLineLength)
        issues.push({ rule: 'line-length', severity: rules['line-length'], message: 'line exceeds ' + maxLineLength + ' characters', line: lineNo, column: maxLineLength + 1, snippet: line });
    }

    if (trimmed === '' || trimmed.startsWith('#') || trimmed === '---' || trimmed === '...') continue;
    const indent = leadingSpaces(line);

    if (inBlock) {
      if (trimmed === '' || indent > blockIndent) continue;
      inBlock = false;
    }

    if (rules['space-after-colon'] !== 'off') {
      const ci = firstColonCheck(line);
      if (ci >= 0) {
        const next = line[ci + 1];
        if (next !== undefined && next !== ' ' && next !== '\t' && next !== '/')
          issues.push({ rule: 'space-after-colon', severity: rules['space-after-colon'], message: 'expected a single space after the colon', line: lineNo, column: ci + 2, snippet: line });
      }
    }

    if (rules['space-after-dash'] !== 'off') {
      const dm = /^(\s*)-([^\s\t])/.exec(line);
      if (dm && !/^[\d.]/.test(dm[2]))
        issues.push({ rule: 'space-after-dash', severity: rules['space-after-dash'], message: 'expected a space after the dash', line: lineNo, column: dm[1].length + 2, snippet: line });
    }

    if (rules['truthy-yes-no'] !== 'off') {
      const tci = keyColonStrict(line);
      if (tci >= 0) {
        const v = stripComment(line.slice(tci + 1).trimStart()).trim();
        if (TRUTHY_WORDS.test(v))
          issues.push({ rule: 'truthy-yes-no', severity: rules['truthy-yes-no'], message: 'unquoted "' + v + '" resolves ambiguously in YAML', line: lineNo, column: tci + 2, snippet: line });
      } else {
        const dm = /^(\s*)-\s+(\S.*)$/.exec(line);
        if (dm) {
          const v = stripComment(dm[2]).trim();
          if (TRUTHY_WORDS.test(v))
            issues.push({ rule: 'truthy-yes-no', severity: rules['truthy-yes-no'], message: 'unquoted "' + v + '" resolves ambiguously in YAML', line: lineNo, column: dm[1].length + 2, snippet: line });
        }
      }
    }

    const code = stripComment(line);
    if (rules['unsafe-tag'] !== 'off') {
      const m = UNSAFE_TAG_RE.exec(code);
      if (m)
        issues.push({ rule: 'unsafe-tag', severity: rules['unsafe-tag'], message: 'unsafe "' + m[0] + '" tag: may execute code in tools that implement it', line: lineNo, column: m.index + 1, snippet: line });
    }
    if (rules['hidden-character'] !== 'off') {
      const hm = HIDDEN_CHARS_RE.exec(code);
      if (hm)
        issues.push({ rule: 'hidden-character', severity: rules['hidden-character'], message: 'invisible or bidi control character U+' + hm[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + ' (trojan-source risk)', line: lineNo, column: hm.index + 1, snippet: line });
    }
    if (rules['merge-key'] !== 'off') {
      if (MERGE_KEY_RE.test(code))
        issues.push({ rule: 'merge-key', severity: rules['merge-key'], message: 'YAML merge key "<<" — aliased merges can amplify alias expansion', line: lineNo, column: code.indexOf('<<') + 1, snippet: line });
    }

    let vtok = '';
    const hci = firstColonCheck(line);
    if (hci >= 0) vtok = stripComment(line.slice(hci + 1)).trim();
    if (/^[|>][0-9+\-]*$/.test(vtok)) { inBlock = true; blockIndent = indent; continue; }
    const dhm = /^(\s*)-\s*([|>][0-9+\-]*)$/.exec(line);
    if (dhm) { inBlock = true; blockIndent = dhm[1].length; continue; }
  }

  if (rules['missing-newline-at-eof'] !== 'off') {
    if (yaml !== '' && !yaml.endsWith('\n')) {
      const last = lines[lines.length - 1] || '';
      issues.push({ rule: 'missing-newline-at-eof', severity: rules['missing-newline-at-eof'], message: 'file does not end with a newline', line: lines.length || 1, column: last.length + 1, snippet: last });
    }
  }

  if (rules['inconsistent-eol'] !== 'off') {
    const raw = yaml.split('\n');
    let hasCrlf = false;
    let firstLfOnly = 0;
    for (let i = 0; i < raw.length - 1; i++) {
      if (raw[i].endsWith('\r')) hasCrlf = true;
      else if (firstLfOnly === 0) firstLfOnly = i + 1;
    }
    if (hasCrlf && firstLfOnly > 0)
      issues.push({ rule: 'inconsistent-eol', severity: rules['inconsistent-eol'], message: 'mixed line endings (CRLF and LF)', line: firstLfOnly, column: 1, snippet: lines[firstLfOnly - 1] || '' });
  }
}

export function lintCore(yaml, options, parseFn) {
  if (typeof yaml !== 'string') throw new TypeError('lint: expected a YAML string');
  if (typeof parseFn !== 'function') throw new TypeError('lint: a parse function is required');
  const maxLineLength = options.maxLineLength === undefined ? DEFAULT_MAX_LINE_LENGTH : options.maxLineLength;
  if (typeof maxLineLength !== 'number' || maxLineLength < 1)
    throw new TypeError('lint: maxLineLength must be a positive number');
  const rules = resolveRules(options.rules);
  const issues = [];
  const lines = yaml === '' ? [] : yaml.split('\n').map(l => (l.endsWith('\r') ? l.slice(0, -1) : l));

  const res = parseFn(yaml);
  if (!res.ok) {
    const cls = classifyError(res.error);
    if (rules[cls.rule] !== 'off') {
      const loc = parseErrorMsg(res.error);
      issues.push({ rule: cls.rule, severity: rules[cls.rule], message: cls.message, line: loc.line, column: loc.column, snippet: res.error });
    }
  }

  runStyleRules(yaml, lines, rules, maxLineLength, issues);

  const errors = issues.filter(i => i.severity === 'error').length;
  const warnings = issues.filter(i => i.severity === 'warning').length;
  return { valid: errors === 0, issues, errors, warnings };
}
