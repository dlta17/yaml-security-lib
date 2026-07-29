export class YAMLException extends Error {
  constructor(msg: string);
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
}

export class YamlSecurity {
  constructor(opts?: YamlSecurityOptions);

  parse(yamlStr: string): YamlResult<Record<string, any> | any[] | null | string | number | boolean>;

  parseAll(yamlStr: string): YamlResult<any[]>;

  dump(value: any, opts?: DumpOptions): YamlResult<string>;

  parseToJSON(yamlStr: string): YamlResult<string>;

  static setLimits(opts?: Partial<SetLimitsOptions>): void;
}

export function setLimits(opts?: Partial<SetLimitsOptions>): void;
