/**
 * Kithkit Linter — Structure Checks
 *
 * Validates skill package directory structure:
 * - Required files present (manifest.yaml, SKILL.md)
 * - No executable files
 * - Size limits (individual files and total package)
 */
import type { CheckResult } from '../types.ts';
/**
 * Check the structure of a skill package directory.
 */
export declare function checkStructure(skillDir: string): CheckResult;
