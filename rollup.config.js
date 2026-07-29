import terser from '@rollup/plugin-terser';

export default () => {
  const format = process.env.FORMAT || 'esm';

  const targets = {
    esm:         { file: 'src/index.min.js',              format: 'esm' },
    cjs:         { file: 'src/index.cjs',                 format: 'cjs' },
    'browser-esm':  { file: 'dist/yaml-security.mjs',        format: 'esm' },
    'browser-iife': { file: 'dist/yaml-security.min.js',     format: 'iife', name: 'YamlSecurity' },
  };

  const out = targets[format];
  if (!out) throw new Error(`Unknown FORMAT: ${format}`);

  return {
    input: 'src/index.js',
    output: {
      ...out,
      plugins: [terser()],
    },
  };
};
