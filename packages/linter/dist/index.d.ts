/**
 * Kithkit Linter — Main Entry Point
 *
 * Runs all check categories against a skill package directory.
 * Returns a unified LintResult.
 */
import type { LintResult } from './types.ts';
export { checkStructure } from './checks/structure.ts';
export { parseAndValidateManifest, validateManifest } from './checks/manifest.ts';
export { isKnownCapability, WELL_KNOWN_CAPABILITIES, getCapabilityDescription } from './capabilities.ts';
export type { LintResult, CheckResult, Finding, SkillManifest, ConfigField, Severity } from './types.ts';
export { REQUIRED_FILES, OPTIONAL_FILES, MANIFEST_NAME_PATTERN, CONFIG_TYPES, TRUST_LEVELS, } from './types.ts';
/**
 * Lint a skill package directory. Runs all applicable checks.
 */
export declare function lint(skillDir: string): LintResult;
