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
