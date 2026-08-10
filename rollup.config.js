import terser from '@rollup/plugin-terser';

// Node builds (FORMAT=esm|FORMAT=cjs) produce one self-contained minified file
// per entry. `index` is the full API (backward compatible); `core`, `validate`
// and `lint` are lean subpath entries that tree-shake the rest away, so
// `import { YamlSecurity } from 'yaml-security-lib'` and its `-core`/`-validate`
// siblings are each standalone bundles.
const NODE_ENTRIES = {
  index:   'src/index.js',
  core:    'src/entries/core.js',
  validate:'src/entries/validate.js',
  lint:    'src/entries/lint.js',
};

const NODE_FORMATS = {
  esm: (name) => `src/${name}.min.js`,
  cjs: (name) => `src/${name}.cjs`,
};

// Browser builds (FORMAT=browser-esm|FORMAT=browser-iife) produce one file per
// entry so CDN users can pull just the lean `core`/`validate`/`lint` bundles.
// `index` keeps its historical dist/yaml-security.* filenames for compatibility.
const BROWSER_ENTRIES = {
  index:    'src/index.js',
  core:     'src/entries/core.js',
  validate: 'src/entries/validate.js',
  lint:     'src/entries/lint.js',
};

const BROWSER_TARGETS = {
  'browser-esm': {
    index:    { file: 'dist/yaml-security.mjs',    format: 'esm' },
    core:     { file: 'dist/core.mjs',             format: 'esm' },
    validate: { file: 'dist/validate.mjs',         format: 'esm' },
    lint:     { file: 'dist/lint.mjs',             format: 'esm' },
  },
  'browser-iife': {
    index:    { file: 'dist/yaml-security.min.js', format: 'iife', name: 'YamlSecurity' },
    core:     { file: 'dist/core.min.js',          format: 'iife', name: 'YamlSecurityCore' },
    validate: { file: 'dist/validate.min.js',      format: 'iife', name: 'YamlSecurityValidate' },
    lint:     { file: 'dist/lint.min.js',          format: 'iife', name: 'YamlSecurityLint' },
  },
};

function nodeBuilds(format, fileName) {
  return Object.entries(NODE_ENTRIES).map(([name, input]) => ({
    input,
    output: { file: fileName(name), format, sourcemap: false, plugins: [terser()] },
  }));
}

function browserBuilds(format) {
  const targets = BROWSER_TARGETS[format];
  if (!targets) throw new Error(`Unknown FORMAT: ${format}`);
  return Object.entries(BROWSER_ENTRIES).map(([name, input]) => ({
    input,
    output: { ...targets[name], plugins: [terser()] },
  }));
}

export default () => {
  const format = process.env.FORMAT || 'esm';

  if (format === 'esm') return nodeBuilds('esm', NODE_FORMATS.esm);
  if (format === 'cjs') return nodeBuilds('cjs', NODE_FORMATS.cjs);
  return browserBuilds(format);
};