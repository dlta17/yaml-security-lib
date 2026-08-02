/** Error thrown by the parser/dumper on invalid YAML or security violations. */
export class YAMLException extends Error {
  constructor(msg: string, mark?: { line: number; column: number; snippet: string });
  mark: { line: number; column: number; snippet: string } | null;
}

export interface YamlSecurityOptions {
  maxAliasDepth?: number;
  maxNodes?: number;
  maxExpansion?: number;
  maxStringLength?: number;
  maxKeys?: number;
  maxDepth?: number;
}

export interface SetLimitsOptions {
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
 * Streaming parser options. All limits are enforced WHILE streaming,
 * so a malicious document is rejected before the whole input is consumed.
 */
export interface StreamOptions extends Partial<SetLimitsOptions> {
  /**
   * Anchor handling strategy:
   * - `'buffer'` (default): anchors/aliases are supported; anchor values are
   *   buffered in memory until they resolve.
   * - `'disable'`: `&`/`*` are rejected outright for true zero-buffering.
   */
  anchors?: 'buffer' | 'disable';
  schema?: Schema;
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

