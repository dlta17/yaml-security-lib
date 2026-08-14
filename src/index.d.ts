/** Error thrown by the parser/dumper on invalid YAML or security violations. */
export class YAMLException extends Error {
  constructor(msg: string, mark?: { line: number; column: number; snippet: string });
  mark: { line: number; column: number; snippet: string } | null;
}

export interface YamlSecurityOptions {
  /** Start from the hardened STRICT_DEFAULTS profile instead of the current global defaults. */
  strict?: boolean;
  /**
   * Max alias chain depth, measured at resolve time: resolving `*x` walks the
   * anchor-source chain back to its root and rejects when hops exceed the
   * limit. Catches chains hidden inside collections (`&a [*b]`,
   * `key: &a\n v: *b`, merge keys), not just direct `&a *b`. `0` disables.
   */
  maxAliasDepth?: number;
  maxNodes?: number;
  maxExpansion?: number;
  maxStringLength?: number;
  maxKeys?: number;
  maxDepth?: number;
}

export interface SetLimitsOptions {
  /**
   * `true` switches the global profile to STRICT_DEFAULTS (hardened ceilings);
   * `false` resets it back to the standard defaults. Explicit limit keys
   * given alongside `strict` override the corresponding profile value.
   */
  strict?: boolean;
  /**
   * Max alias chain depth, measured at resolve time (see
   * {@link YamlSecurityOptions.maxAliasDepth}). `0` disables.
   */
  maxAliasDepth?: number;
  maxNodes?: number;
  maxAlias?: number;
  maxExpansion?: number;
  maxStringLength?: number;
  maxKeys?: number;
  maxDepth?: number;
  maxInputMB?: number;
  maxInputBytes?: number;
}

export interface YamlResult<T = any> {
  ok: boolean;
  result?: T;
  error?: string;
}

export interface DumpOptions {
  indent?: number;
  flowLevel?: number;
  sortKeys?: boolean;
  lineWidth?: number;
  forceQuotes?: boolean;
  quotingType?: 'single' | 'double';
}

export interface ParseOptions {
  schema?: Schema;
  types?: YamlType[];
}

/** YAML type definition. Holds tag, kind, construct/resolve functions. */
export class YamlType {
  tag: string;
  kind: 'scalar' | 'mapping' | 'sequence';
  construct: (val: any) => any;
  resolve: (val: string) => boolean;
  instance?: any;

  constructor(tag: string, opts?: {
    kind?: 'scalar' | 'mapping' | 'sequence';
    construct?: (val: any) => any;
    resolve?: (val: string) => boolean;
    instance?: any;
  });
}

/** Schema registry of YAML types. Controls explicit tag lookup and implicit resolution order. */
export class Schema {
  constructor();

  /** Register a type. Returns `this` (chainable). */
  addType(type: YamlType): Schema;

  /** Remove a previously registered type. Returns true if found. */
  removeType(tag: string): boolean;

  /** Check whether a type with the given tag is registered. */
  hasType(tag: string): boolean;

  /** Return the YAML tag that best describes a JS value. */
  tagFor(val: any): string;
}

/** Safe YAML parser/dumper with error-safe API. */
export class YamlSecurity {
  constructor(opts?: YamlSecurityOptions);

  /** Replace the schema used for parsing. */
  setSchema(schema: Schema): void;

  /** Parse a YAML string. Always returns `{ ok, result }` or `{ ok, error }`. */
  parse(yamlStr: string): YamlResult<Record<string, any> | any[] | null | string | number | boolean>;

  /** Parse multi-document YAML. Accepts optional per-call schema/type overrides. */
  parseAll(yamlStr: string, opts?: ParseOptions): YamlResult<any[]>;

  /** Serialize a JS value to YAML. */
  dump(value: any, opts?: DumpOptions): YamlResult<string>;

  /** Parse YAML and return pretty-printed JSON string. */
  parseToJSON(yamlStr: string): YamlResult<string>;

  /** Validate a JS value against a schema spec. Never throws. */
  validate(value: any, spec: Spec): ValidationResult;

  /** Parse a YAML string and validate it against a schema spec. Never throws. */
  validateYaml(yamlStr: string, spec: Spec): { ok: boolean; value: any; errors: ValidationError[] };

  /** Create a streaming parser bound to this instance's schema and limits. */
  createStream(opts?: StreamOptions): StreamParser;

  /** Stream-parse documents, yielding each as it completes. */
  parseStream(
    input: string | Iterable<string> | AsyncIterable<string>,
    opts?: StreamOptions
  ): AsyncGenerator<any, void, void>;

  /** Globally adjust parser limits. */
  static setLimits(opts?: Partial<SetLimitsOptions>): void;
}

/** Globally adjust parser limits. */
export function setLimits(opts?: Partial<SetLimitsOptions>): void;

/** Parse a YAML string into a JS value. Throws on error. */
export function parse(yamlStr: string, opts?: ParseOptions): any;

/** Parse a multi-document YAML string. Throws on error. */
export function parseAll(yamlStr: string, opts?: ParseOptions): any[];

/** Serialize a JS value to YAML. */
export function dump(value: any, opts?: DumpOptions): string;

/**
 * Emit the YAML Test Suite-style tree event stream for a YAML string:
 * `+STR` / `+DOC` / `+MAP` / `+SEQ` / `=VAL` / `=ALI` lines with scalar
 * styles, anchors, tags and flow-style markers. Throws on parse error.
 */
export function tree(yamlStr: string, opts?: ParseOptions): string;

/** A parsed node in the AST produced by `parseTree` / `assembleAST`. */
export interface TreeNode {
  type: 'document' | 'mapping' | 'sequence' | 'scalar' | 'alias';
  /** Children for `mapping` (array of `{ key, value }`) and `sequence`. */
  items?: Array<TreeNode | { key: TreeNode; value: TreeNode }>;
  /** True if the collection used flow style `{}` / `[]`. */
  flow?: boolean;
  /** Anchor name, if any. */
  anchor?: string;
  /** Resolved tag, if any. */
  tag?: string;
  /** Scalar content, or alias target name for `'alias'`. */
  value?: any;
  /** `'plain'` / `'single'` / `'double'` / `'literal'` / `'folded'`. */
  style?: string;
  /** Present on `document` nodes: explicit `---` / `...` markers. */
  explicitStart?: boolean;
  explicitEnd?: boolean;
}

/** A flat AST event record from the internal parse. */
export interface TreeEvent {
  /** Event type: `'doc'`, `'docEnd'`, `'c'` (collection start), `'x'` (collection end), `'v'` (scalar), `'al'` (alias). */
  t: 'doc' | 'docEnd' | 'c' | 'x' | 'v' | 'al';
  /** Collection kind for `'c'` / `'x'`: `'map'` or `'seq'`. */
  k?: 'map' | 'seq';
  /** Style id: `1` plain, `2` single, `3` double, `4` literal, `5` folded; `'flow'` for flow collections. */
  s?: number | 'flow';
  /** Anchor name. */
  a?: string;
  /** Resolved tag. */
  g?: string;
  /** Scalar content. */
  c?: string;
  /** Alias target name (for `'al'`). */
  n?: string;
  /** Explicit document markers (for `'doc'` / `'docEnd'`). */
  e?: boolean;
}

/**
 * Parse YAML into a nested document AST (one node per document).
 * Throws on parse error.
 */
export function parseTree(yamlStr: string, opts?: ParseOptions): TreeDocument[];

export interface TreeDocument {
  type: 'document';
  explicitStart?: boolean;
  explicitEnd?: boolean;
  node?: TreeNode;
}

/** Render a flat event stream into the libyaml-style tree string. */
export function renderTree(events: TreeEvent[]): string;

/** Build the nested document AST from a flat event stream. */
export function assembleAST(events: TreeEvent[]): TreeDocument[];

/**
 * Copy of the current global default limits (reflects `setLimits`):
 * `{ maxNodes, maxAlias, maxAliasDepth, maxExpansion, maxInputMB, maxInputBytes, maxStringLength, maxKeys, maxDepth }`.
 */
export function getBaseConfig(): Required<SetLimitsOptions> & { maxInputMB: number };

/** Decode YAML double-quoted escapes (`\n`, `\t`, `\xNN`, `\uNNNN`, `\UNNNNNNNN`, …). Throws `YAMLException` on unknown escapes. */
export function unescapeYaml(str: string): string;

/** UTF-8 byte length of a string (Node `Buffer` or browser `TextEncoder`). */
export function byteLength(str: string): number;


/**
 * Streaming parser options. All limits are enforced WHILE streaming,
 * so a malicious document is rejected before the whole input is consumed.
 */
export interface StreamOptions extends Partial<SetLimitsOptions> {
  /**
   * Start from the hardened STRICT_DEFAULTS profile for this stream instead
   * of the current global defaults.
   */
  strict?: boolean;
  /**
   * Anchor handling strategy:
   * - `'buffer'` (default): anchors/aliases are supported; anchor values are
   *   buffered in memory until they resolve.
   * - `'disable'`: `&`/`*` are rejected outright for true zero-buffering.
   */
  anchors?: 'buffer' | 'disable';
  schema?: Schema;
  /** Validate each document against a schema spec while streaming. */
  validate?: Spec;
  /** Abort the stream on the first validation violation (emits `error`). */
  abortOnError?: boolean;
}

/** SAX-style event emitted by a `StreamParser`. */
export type StreamEventType =
  | 'documentStart'
  | 'mappingStart'
  | 'sequenceStart'
  | 'key'
  | 'scalar'
  | 'mappingEnd'
  | 'sequenceEnd'
  | 'documentEnd'
  | 'violation'
  | 'error'
  | 'end';

export interface StreamEvent {
  type: StreamEventType;
  /** Present on `key` and `scalar` events. */
  value?: any;
  /** Present on `key` and `scalar` events: the raw source text. */
  raw?: string;
  /** Present on `error` events. */
  error?: Error;
  /** Present on `violation` events. */
  path?: string;
  message?: string;
}

export type StreamListener = (ev: StreamEvent) => void;

/**
 * Incremental, push-based SAX parser. Feed it chunks with `write()`, listen
 * to events via `on()`, and finish with `end()`. The convenience `document`
 * event fires with each fully parsed document (works for single- and
 * multi-doc streams). Also async-iterable: `for await (const ev of parser)`.
 */
export class StreamParser {
  constructor(opts?: StreamOptions);
  on(type: string | '*', cb: StreamListener): this;
  off(type: string, cb: StreamListener): this;
  write(chunk: string | unknown): this;
  end(): this;
  abort(err?: Error | string): never;
  [Symbol.asyncIterator](): AsyncIterator<StreamEvent>;
}

/** Create a streaming YAML parser. */
export function createStream(opts?: StreamOptions): StreamParser;

/**
 * Stream-parse YAML (single- or multi-document, `---`-separated).
 * Accepts a string or any (async) iterable of string chunks, and yields each
 * parsed document as it completes.
 */
export function parseStream(
  input: string | Iterable<string> | AsyncIterable<string>,
  opts?: StreamOptions
): AsyncGenerator<any, void, void>;

// ── Schema validation ───────────────────────────────────────

/** Base shape shared by all schema specs. */
export interface Spec { __s: string; [k: string]: any; }

export interface StringSpec extends Spec {
  __s: 'string';
  min?: number; max?: number; pattern?: string; enum?: string[];
}
export interface IntSpec extends Spec {
  __s: 'int';
  min?: number; max?: number; exclusiveMin?: number; exclusiveMax?: number; multipleOf?: number;
}
export interface FloatSpec extends Spec {
  __s: 'float';
  min?: number; max?: number; exclusiveMin?: number; exclusiveMax?: number; multipleOf?: number;
}
export interface ArraySpec extends Spec {
  __s: 'array';
  items?: Spec; minItems?: number; maxItems?: number; uniqueItems?: boolean;
}
export interface TupleSpec extends Spec { __s: 'tuple'; items: Spec[]; }
export interface ObjectSpec extends Spec {
  __s: 'object';
  shape?: { [k: string]: Spec };
  required?: string[];
  allowExtra?: boolean;
  additionalProperties?: Spec | false;
  patternProperties?: { [p: string]: Spec };
  minProps?: number; maxProps?: number;
}
export interface RecordSpec extends Spec { __s: 'record'; values: Spec; }
export interface EnumSpec extends Spec { __s: 'enum'; values: any[]; }
export interface OptionalSpec extends Spec { __s: 'optional'; spec: Spec; }
export interface NullableSpec extends Spec { __s: 'nullable'; spec: Spec; }
export interface CombinatorSpec extends Spec {
  __s: 'oneOf' | 'anyOf' | 'allOf';
  specs: Spec[];
}
export interface NotSpec extends Spec { __s: 'not'; spec: Spec; }
export interface CustomSpec extends Spec {
  __s: 'custom';
  fn: (value: any, helpers: { path: string; errors: ValidationError[]; validate: (v: any, s2: Spec) => ValidationResult }) => boolean | string | void;
}

export interface ValidationError {
  path: string;
  message: string;
  value?: any;
}
export interface ValidationResult { ok: boolean; errors: ValidationError[]; }

/** Validation spec builder namespace. */
export const s: {
  string(opts?: { min?: number; max?: number; pattern?: string; enum?: string[] }): StringSpec;
  int(opts?: Partial<IntSpec>): IntSpec;
  number(opts?: Partial<FloatSpec>): FloatSpec;
  float(opts?: Partial<FloatSpec>): FloatSpec;
  bool(): Spec & { __s: 'bool' };
  null(): Spec & { __s: 'null' };
  any(): Spec & { __s: 'any' };
  never(): Spec & { __s: 'never' };
  enum(values: any[]): EnumSpec;
  timestamp(): Spec & { __s: 'timestamp' };
  array(items?: Spec, opts?: Partial<ArraySpec>): ArraySpec;
  tuple(items: Spec[]): TupleSpec;
  object(shape?: { [k: string]: Spec }, opts?: Partial<ObjectSpec>): ObjectSpec;
  record(values: Spec): RecordSpec;
  optional(spec: Spec): OptionalSpec;
  nullable(spec: Spec): NullableSpec;
  oneOf(specs: Spec[]): CombinatorSpec;
  anyOf(specs: Spec[]): CombinatorSpec;
  allOf(specs: Spec[]): CombinatorSpec;
  not(spec: Spec): NotSpec;
  custom(fn: CustomSpec['fn']): CustomSpec;
  fromJSONSchema(js: object, opts?: { resolveExternal?: (ref: string) => object }): Spec;
};

/** Validate a JS value against a spec. Never throws. */
export function validate(value: any, spec: Spec): ValidationResult;

/** Parse a YAML string and validate it against a spec. Never throws. */
export function validateYaml(
  yamlStr: string,
  spec: Spec,
  opts?: ParseOptions
): { ok: boolean; value: any; errors: ValidationError[] };

/** Incremental SAX validator that consumes StreamParser events. */
export interface StreamValidator {
  readonly finalErrors: ValidationError[];
  readonly violations: ValidationError[];
  takeNewViolations(): ValidationError[];
  documentStart(): void;
  mappingStart(): void;
  sequenceStart(): void;
  mappingEnd(): void;
  sequenceEnd(): void;
  key(k: any): void;
  scalar(v: any): void;
  documentEnd(root?: any): ValidationError[];
}
export function createStreamValidator(spec: Spec): StreamValidator;

/** Convert a JSON Schema (draft-07 subset) into a fluent spec. */
export function fromJSONSchema(js: object, opts?: { resolveExternal?: (ref: string) => object }): Spec;
/** Convert a fluent spec into a JSON Schema. */
export function toJSONSchema(spec: Spec): object;

/** Individual builder exports (same as the `s` namespace). */
export function string(opts?: { min?: number; max?: number; pattern?: string; enum?: string[] }): StringSpec;
export function int(opts?: Partial<IntSpec>): IntSpec;
export function number(opts?: Partial<FloatSpec>): FloatSpec;
export function float(opts?: Partial<FloatSpec>): FloatSpec;
export function bool(): Spec & { __s: 'bool' };
export function nullType(): Spec & { __s: 'null' };
export function any(): Spec & { __s: 'any' };
export function never(): Spec & { __s: 'never' };
export function enumType(values: any[]): EnumSpec;
export function timestamp(): Spec & { __s: 'timestamp' };
export function array(items?: Spec, opts?: Partial<ArraySpec>): ArraySpec;
export function tuple(items: Spec[]): TupleSpec;
export function object(shape?: { [k: string]: Spec }, opts?: Partial<ObjectSpec>): ObjectSpec;
export function record(values: Spec): RecordSpec;
export function optional(spec: Spec): OptionalSpec;
export function nullable(spec: Spec): NullableSpec;
export function oneOf(specs: Spec[]): CombinatorSpec;
export function anyOf(specs: Spec[]): CombinatorSpec;
export function allOf(specs: Spec[]): CombinatorSpec;
export function not(spec: Spec): NotSpec;
export function custom(fn: CustomSpec['fn']): CustomSpec;

/** Severity of a lint issue. */
export type LintSeverity = 'error' | 'warning';

/** Rules enabled by default: `error` for syntax/security, `warning` for style. */
export const LINT_RULES: Readonly<Record<string, LintSeverity>>;

export interface LintIssue {
  rule: string;
  severity: LintSeverity;
  message: string;
  line: number;
  column: number;
  snippet: string;
}

export interface LintResult {
  valid: boolean;
  issues: LintIssue[];
  errors: number;
  warnings: number;
}

export interface LintOptions {
  /** Enable/disable rules: an array of rule names, or a map of name → severity/boolean. */
  rules?: string[] | Record<string, boolean | 0 | 1 | 'off' | 'error' | 'warn' | 'warning'>;
  /** Maximum allowed line length for the `line-length` rule (default: 120). */
  maxLineLength?: number;
}

/**
 * Lint a YAML string for syntax errors, security concerns, and basic style.
 * Never throws for YAML content; returns issues with line/column positions.
 */
export function lint(yaml: string, options?: LintOptions): LintResult;

