// Schema-validation entry point: the fluent builder (`s.*`), pure `validate`,
// the streaming validator and the JSON Schema bridge. Imports straight from
// `../validate.js` (self-contained) so the bundle stays lean — the parser is
// NOT bundled here. Import from `yaml-security-lib/validate`.
export {
  s, validate, createStreamValidator,
  fromJSONSchema, toJSONSchema,
  string, int, number, float, bool, nullType, any, never,
  enumType, timestamp, array, tuple, object, record,
  optional, nullable, oneOf, anyOf, allOf, not, custom,
} from '../validate.js';