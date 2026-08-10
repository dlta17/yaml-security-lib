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

const BROWSER_TARGETS = {
  'browser-esm':  { file: 'dist/yaml-security.mjs',    format: 'esm' },
  'browser-iife': { file: 'dist/yaml-security.min.js', format: 'iife', name: 'YamlSecurity' },
};

function nodeBuilds(format, fileName) {
  return Object.entries(NODE_ENTRIES).map(([name, input]) => ({
    input,
    output: { file: fileName(name), format, sourcemap: false, plugins: [terser()] },
  }));
}

export default () => {
  const format = process.env.FORMAT || 'esm';

  if (format === 'esm') return nodeBuilds('esm', NODE_FORMATS.esm);
  if (format === 'cjs') return nodeBuilds('cjs', NODE_FORMATS.cjs);

  const out = BROWSER_TARGETS[format];
  if (!out) throw new Error(`Unknown FORMAT: ${format}`);
  return {
    input: 'src/index.js',
    output: { ...out, plugins: [terser()] },
  };
};