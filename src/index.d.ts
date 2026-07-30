export class YAMLException extends Error {
  constructor(msg: string);
  mark: { line: number; column: number; snippet: string } | null;
}

export interface YamlSecurityOptions {
  maxAliasDepth?: number;
  maxNodes?: number;
  maxExpansion?: number;
}

export interface SetLimitsOptions {
  maxAliasDepth?: number;
  maxNodes?: number;
  maxAlias?: number;
  maxExpansion?: number;
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

// ── Schema System ──

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

export class Schema {
  constructor();
  addType(type: YamlType): Schema;
  tagFor(val: any): string;
}

export class YamlSecurity {
  constructor(opts?: YamlSecurityOptions);

  setSchema(schema: Schema): void;

  parse(yamlStr: string): YamlResult<Record<string, any> | any[] | null | string | number | boolean>;

  parseAll(yamlStr: string): YamlResult<any[]>;

  dump(value: any, opts?: DumpOptions): YamlResult<string>;

  parseToJSON(yamlStr: string): YamlResult<string>;

  static setLimits(opts?: Partial<SetLimitsOptions>): void;
}

export function setLimits(opts?: Partial<SetLimitsOptions>): void;

export function parse(yamlStr: string, opts?: ParseOptions): any;

export function parseAll(yamlStr: string, opts?: ParseOptions): any[];

export function dump(value: any, opts?: DumpOptions): string;
