export interface YamlSecurityOptions {
  maxAliasDepth?: number;
  maxNodes?: number;
  maxExpansion?: number;
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
  parse(yamlStr: string): YamlResult<Record<string, any> | any[] | null>;
  parseAll(yamlStr: string): YamlResult<any[]>;
  dump(value: any, opts?: DumpOptions): YamlResult<string>;
  parseToJSON(yamlStr: string): YamlResult<string>;
  static setLimits(opts: Partial<YamlSecurityOptions & { maxAlias?: number; maxExpansion?: number; maxInputMB?: number }>): void;
}
