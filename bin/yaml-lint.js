#!/usr/bin/env node
// yaml-lint — CLI linter for yaml-security-lib.
// Imports the committed ES module source (src/index.js), not a build artifact,
// so it works from a fresh checkout / CI before any build step and from the
// published package (src/index.js ships in the tarball).
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { lint } from '../src/index.js';

const require = createRequire(import.meta.url);
const { version } = require('../package.json');

const HELP = `Usage: yaml-lint [options] [files...]

Lint YAML files (or stdin when no files are given) for syntax errors,
security concerns, and basic style issues.

Options:
  --json                    Emit results as JSON
  --max-line-length <n>     Maximum allowed line length (default: 120)
  -h, --help                Show this help message
  -v, --version             Print the version
`;

function parseArgs(argv) {
  const opts = { files: [], json: false, maxLineLength: undefined, help: false, version: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--version' || a === '-v') opts.version = true;
    else if (a === '--max-line-length') {
      const v = Number(argv[++i]);
      if (!Number.isInteger(v) || v < 1) throw new Error('--max-line-length expects a positive integer');
      opts.maxLineLength = v;
    } else if (a.startsWith('--max-line-length=')) {
      const v = Number(a.slice('--max-line-length='.length));
      if (!Number.isInteger(v) || v < 1) throw new Error('--max-line-length expects a positive integer');
      opts.maxLineLength = v;
    } else if (a === '--') {
      opts.files.push(...argv.slice(i + 1));
      break;
    } else if (a.startsWith('-')) {
      throw new Error('Unknown option: ' + a);
    } else {
      opts.files.push(a);
    }
  }
  return opts;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function colorize(severity) {
  if (!process.stdout.isTTY) return severity;
  if (severity === 'error') return '\x1b[31m' + severity + '\x1b[0m';
  return '\x1b[33m' + severity + '\x1b[0m';
}

function renderIssue(name, issue) {
  return name + ':' + issue.line + ':' + issue.column + ': [' + colorize(issue.severity) + '] ' +
    issue.rule + ': ' + issue.message;
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write('yaml-lint: ' + err.message + '\n\n' + HELP);
    process.exit(2);
  }
  if (opts.help) { process.stdout.write(HELP); process.exit(0); }
  if (opts.version) { process.stdout.write(version + '\n'); process.exit(0); }

  const targets = opts.files.length ? opts.files : ['<stdin>'];
  const results = [];
  let ioError = false;

  for (const name of targets) {
    let yaml;
    try {
      yaml = name === '<stdin>' ? await readStdin() : readFileSync(name, 'utf8');
    } catch (err) {
      process.stderr.write('yaml-lint: cannot read ' + name + ': ' + err.message + '\n');
      ioError = true;
      results.push({ file: name, error: err.message });
      continue;
    }
    const lintOptions = {};
    if (opts.maxLineLength !== undefined) lintOptions.maxLineLength = opts.maxLineLength;
    results.push({ file: name, ...lint(yaml, lintOptions) });
  }

  const unreadable = results.filter(r => r.error).length;
  const totalErrors = results.reduce((n, r) => n + (r.errors || 0), 0);
  const totalWarnings = results.reduce((n, r) => n + (r.warnings || 0), 0);

  if (opts.json) {
    const out = { files: results, errors: totalErrors, warnings: totalWarnings };
    if (unreadable) out.unreadable = unreadable;
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  } else {
    for (const r of results) {
      if (r.error) continue;
      for (const issue of r.issues) process.stdout.write(renderIssue(r.file, issue) + '\n');
    }
    process.stdout.write('Linted ' + targets.length + ' source' + (targets.length === 1 ? '' : 's') +
      ': ' + totalErrors + ' error' + (totalErrors === 1 ? '' : 's') + ', ' +
      totalWarnings + ' warning' + (totalWarnings === 1 ? '' : 's') +
      (unreadable ? ' (' + unreadable + ' could not be read)' : '') + '\n');
  }

  process.exit(ioError ? 2 : totalErrors > 0 ? 1 : 0);
}

main();
