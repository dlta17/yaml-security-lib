// Lean entry point: parsing, dumping, streaming and the YamlSecurity class —
// without the schema-validator builder (`s`, `validate`) or the linter. Import
// from `yaml-security-lib/core` when you only parse/dump untrusted YAML
// (validators and linters live in `yaml-security-lib/validate` / `-lint`).
export {
  YamlSecurity, YAMLException, YamlType, Schema, DEFAULT_SCHEMA,
  parse, parseAll, dump, validateYaml, createStream, parseStream,
  setLimits, getBaseConfig, byteLength, unescapeYaml,
  tree, parseTree, renderTree, assembleAST,
} from '../index.js';