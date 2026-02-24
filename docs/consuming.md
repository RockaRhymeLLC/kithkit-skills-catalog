# Skill Consumer Guide

This guide covers discovering, verifying, installing, and managing skills from the Kithkit Skills Catalog.

## Overview

The consumer workflow:

```
Fetch index.json → Verify signature → Search/browse → Review skill → Install → Manage
```

Every step involves cryptographic verification. No unsigned code is installed.

## Prerequisites

- Node.js 20+
- The `@kithkit/client` package

## 1. Fetch and Verify the Catalog Index

The catalog index (`index.json`) is a signed JSON document listing all available skills. Always verify before trusting.

```typescript
import { verifyAndParseIndex } from '@kithkit/client';

// The catalog authority public key (from catalog-authority.pub)
const CATALOG_PUBLIC_KEY = 'MCowBQYDK2VwAyEA...'; // base64 SPKI DER

// Fetch the signed index
const response = await fetch(
  'https://raw.githubusercontent.com/RockaRhymeLLC/kithkit-skills-catalog/main/index.json'
);
const signedIndex = await response.json();

// Verify Ed25519 signature
const result = verifyAndParseIndex(signedIndex, CATALOG_PUBLIC_KEY);
if (!result.valid) {
  throw new Error(`Index verification failed: ${result.error}`);
}

const index = result.index;
```

### Caching

Use `CatalogCache` to avoid fetching on every operation:

```typescript
import { CatalogCache } from '@kithkit/client';

const cache = new CatalogCache('.cache/kithkit', 60 * 60 * 1000); // 1 hour TTL
const index = await cache.getIndex(async () => {
  const res = await fetch('https://...index.json');
  return res.json();
});
```

## 2. Search

```typescript
import { searchCatalog, formatSearchResults } from '@kithkit/client';

// Text search (name or description)
const results = searchCatalog(index, { text: 'weather' });

// Filter by tag
const utilities = searchCatalog(index, { tag: 'utility' });

// Filter by required capability
const webSkills = searchCatalog(index, { capability: 'web_fetch' });

// Combine filters (AND logic)
const specific = searchCatalog(index, { text: 'check', tag: 'weather' });

// Human-readable output
console.log(formatSearchResults(results));
```

## 3. Security Review

Before installing any skill, run it through the two-layer security review.

### Layer 1: Pattern-Based Scanner

Deterministic regex detection — fast, no LLM needed:

```typescript
import { patternBasedReview, formatSelftestReport, runSelftest } from '@kithkit/client';

const findings = patternBasedReview(skillContent, declaredCapabilities);
// Returns ReviewFinding[] — empty array means no concerns detected
```

### Layer 2: LLM-Mediated Review

The agent reads SKILL.md content *as data* (not as instructions) and evaluates against the security rubric:

```typescript
import { buildReviewContext, getReviewPrompt, createReviewReport, formatReviewForHuman } from '@kithkit/client';

// Build context for the reviewing agent
const context = buildReviewContext(skillContent, manifest, trustLevel);

// The review prompt (send to your LLM)
const prompt = getReviewPrompt();

// After the LLM returns findings...
const report = createReviewReport(skillName, version, trustLevel, findings);
const humanSummary = formatReviewForHuman(report);
```

### Self-Test

Validate your review pipeline against adversarial test cases:

```typescript
import { runSelftest, patternBasedReview, formatSelftestReport } from '@kithkit/client';

const summary = runSelftest(patternBasedReview);
console.log(formatSelftestReport(summary));
// Target: Tier 1 = 100% catch, Tier 2 ≥ 80%
```

## 4. Install

```typescript
import { installSkill } from '@kithkit/client';

const result = await installSkill({
  skillName: 'weather-check',
  version: '1.0.0',              // Optional — defaults to latest
  index: verifiedIndex,
  publicKeyBase64: CATALOG_PUBLIC_KEY,
  fetchArchive: async (archiveUrl) => {
    const baseUrl = 'https://raw.githubusercontent.com/RockaRhymeLLC/kithkit-skills-catalog/main/';
    const res = await fetch(baseUrl + archiveUrl);
    return Buffer.from(await res.arrayBuffer());
  },
  skillsDir: '.claude/skills/',
  revocationList: signedRevocationList,  // Optional but recommended
});

if (result.success) {
  console.log(`Installed ${result.skillName} v${result.version} to ${result.installDir}`);
} else {
  console.error(`Install failed: ${result.error}`);
}
```

**Install steps (internal):**

1. Find skill in the verified index
2. Resolve version (latest if not specified)
3. Check revocation list
4. Fetch archive via your `fetchArchive` callback
5. Verify archive integrity (SHA-256 hash + Ed25519 signature)
6. Check for duplicate installation
7. Extract archive with path-traversal protection
8. Write `.kithkit` metadata file
9. Generate `config.yaml` from manifest schema

## 5. Check Revocation

Always check the revocation list before installing or using a skill:

```typescript
import { verifyRevocationList, isRevoked } from '@kithkit/client';

// Fetch and verify
const revokedRes = await fetch('https://.../revoked.json');
const revokedList = await revokedRes.json();
const valid = verifyRevocationList(revokedList, CATALOG_PUBLIC_KEY);

// Check a specific skill
const { revoked, entry } = isRevoked(revokedList, 'some-skill', '1.0.0');
if (revoked) {
  console.error(`REVOKED: ${entry.reason} (severity: ${entry.severity})`);
}
```

## 6. Lifecycle Management

### Check for Updates

```typescript
import { checkForUpdate, checkAllUpdates } from '@kithkit/client';

// Single skill
const update = await checkForUpdate('weather-check', skillsDir, index);
if (update.hasUpdate) {
  console.log(`Update available: ${update.currentVersion} → ${update.latestVersion}`);
}

// All installed skills
const allUpdates = await checkAllUpdates(skillsDir, index);
const available = allUpdates.filter(u => u.hasUpdate);
```

### Update a Skill

```typescript
import { updateSkill } from '@kithkit/client';

const result = await updateSkill({
  skillName: 'weather-check',
  skillsDir: '.claude/skills/',
  index: verifiedIndex,
  publicKeyBase64: CATALOG_PUBLIC_KEY,
  fetchArchive: archiveFetcher,
});
// Existing config.yaml is preserved and merged with new schema
```

### Uninstall

```typescript
import { uninstallSkill } from '@kithkit/client';

const result = await uninstallSkill('weather-check', skillsDir);
// config.yaml is backed up to .kithkit-backups/ before removal
```

### List Installed

```typescript
import { listInstalled } from '@kithkit/client';

const skills = await listInstalled(skillsDir, index);
for (const skill of skills) {
  const updateNote = skill.hasUpdate ? ` (update: ${skill.latestVersion})` : '';
  console.log(`${skill.name} v${skill.version} [${skill.trust_level}]${updateNote}`);
}
```

### Restore Config Backup

```typescript
import { restoreConfigBackup } from '@kithkit/client';

const backup = await restoreConfigBackup('weather-check', skillsDir);
if (backup) {
  // Re-apply the saved config.yaml content
}
```

## Config Generation

When a skill is installed, the client generates a `config.yaml` from the manifest's config schema:

- Default values are pre-filled
- Required fields without defaults get `# TODO` comments
- Credential fields include Keychain storage hints
- On update, existing config values are preserved and new fields are merged in

The config file is **local only** — it is never uploaded or included in archives.
