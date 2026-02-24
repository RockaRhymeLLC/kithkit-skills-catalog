/**
 * Kithkit Linter — Main Entry Point
 *
 * Runs all check categories against a skill package directory.
 * Returns a unified LintResult.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { checkStructure } from './checks/structure.ts';
import { parseAndValidateManifest } from './checks/manifest.ts';
export { checkStructure } from './checks/structure.ts';
export { parseAndValidateManifest, validateManifest } from './checks/manifest.ts';
export { isKnownCapability, WELL_KNOWN_CAPABILITIES, getCapabilityDescription } from './capabilities.ts';
export { REQUIRED_FILES, OPTIONAL_FILES, MANIFEST_NAME_PATTERN, CONFIG_TYPES, TRUST_LEVELS, } from './types.ts';
/**
 * Lint a skill package directory. Runs all applicable checks.
 */
export function lint(skillDir) {
    const start = performance.now();
    const checks = {};
    // 1. Structure checks
    checks['structure'] = checkStructure(skillDir);
    // 2. Manifest checks (only if manifest.yaml exists)
    const manifestPath = join(skillDir, 'manifest.yaml');
    if (existsSync(manifestPath)) {
        const yamlContent = readFileSync(manifestPath, 'utf-8');
        checks['manifest'] = parseAndValidateManifest(yamlContent);
    }
    // If manifest doesn't exist, structure check already flagged it
    // Aggregate results
    let errors = 0, warnings = 0, info = 0;
    for (const result of Object.values(checks)) {
        for (const finding of result.findings) {
            if (finding.severity === 'error')
                errors++;
            else if (finding.severity === 'warning')
                warnings++;
            else
                info++;
        }
    }
    const duration_ms = Math.round(performance.now() - start);
    return {
        pass: errors === 0,
        score: { errors, warnings, info },
        checks,
        duration_ms,
    };
}
