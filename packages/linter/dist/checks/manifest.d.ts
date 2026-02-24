/**
 * Kithkit Linter — Manifest Validation
 *
 * Validates manifest.yaml against the skill manifest schema.
 * Returns structured findings with actionable error messages.
 */
import type { CheckResult } from '../types.ts';
/**
 * Validate a parsed manifest object.
 */
export declare function validateManifest(manifest: Record<string, unknown>): CheckResult;
/**
 * Parse and validate a manifest.yaml string.
 */
export declare function parseAndValidateManifest(yamlContent: string): CheckResult;
