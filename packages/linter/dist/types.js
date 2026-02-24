/**
 * Kithkit Linter — Core Types
 *
 * Data model for skill manifests, linter results, and package structure.
 */
// --- Package Structure ---
export const REQUIRED_FILES = ['manifest.yaml', 'SKILL.md'];
export const OPTIONAL_FILES = ['reference.md', 'CHANGELOG.md'];
export const LOCAL_ONLY_FILES = ['config.yaml', '.kithkit'];
export const MANIFEST_NAME_PATTERN = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;
export const MANIFEST_NAME_MIN_LENGTH = 2;
export const MANIFEST_NAME_MAX_LENGTH = 64;
export const CONFIG_TYPES = ['credential', 'string', 'number', 'boolean', 'enum'];
export const TRUST_LEVELS = ['first-party', 'verified', 'community'];
