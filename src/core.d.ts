// Type declarations for the lean `yaml-security-lib/core` entry — parsing,
// dumping, streaming and the YamlSecurity class (no schema builder, no linter).
export {
  YamlSecurity, YAMLException, YamlType, Schema,
  parse, parseAll, dump, validateYaml, createStream, parseStream,
  setLimits, getBaseConfig, unescapeYaml, byteLength,
  tree, parseTree, renderTree, assembleAST,
} from './index.js';