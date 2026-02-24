/**
 * Kithkit Linter — Core Types
 *
 * Data model for skill manifests, linter results, and package structure.
 */
export interface SkillManifest {
    name: string;
    version: string;
    description: string;
    author: {
        name: string;
        github: string;
    };
    capabilities: {
        required: string[];
        optional?: string[];
    };
    config?: ConfigField[];
    tags?: string[];
    category?: string;
    recommends?: string[];
    trust_level?: 'first-party' | 'verified' | 'community';
    frameworks?: {
        tested?: string[];
    };
}
export interface ConfigField {
    key: string;
    type: 'credential' | 'string' | 'number' | 'boolean' | 'enum';
    required: boolean;
    default?: string | number | boolean;
    description: string;
    enum_values?: string[];
}
export type Severity = 'error' | 'warning' | 'info';
export interface Finding {
    severity: Severity;
    check: string;
    message: string;
    file?: string;
    line?: number;
    pattern?: string;
}
export interface CheckResult {
    pass: boolean;
    findings: Finding[];
}
export interface LintResult {
    pass: boolean;
    score: {
        errors: number;
        warnings: number;
        info: number;
    };
    checks: Record<string, CheckResult>;
    duration_ms: number;
}
export declare const REQUIRED_FILES: readonly ["manifest.yaml", "SKILL.md"];
export declare const OPTIONAL_FILES: readonly ["reference.md", "CHANGELOG.md"];
export declare const LOCAL_ONLY_FILES: readonly ["config.yaml", ".kithkit"];
export declare const MANIFEST_NAME_PATTERN: RegExp;
export declare const MANIFEST_NAME_MIN_LENGTH = 2;
export declare const MANIFEST_NAME_MAX_LENGTH = 64;
export declare const CONFIG_TYPES: readonly ["credential", "string", "number", "boolean", "enum"];
export type ConfigType = typeof CONFIG_TYPES[number];
export declare const TRUST_LEVELS: readonly ["first-party", "verified", "community"];
export type TrustLevel = typeof TRUST_LEVELS[number];
