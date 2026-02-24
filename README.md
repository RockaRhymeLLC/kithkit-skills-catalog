# Kithkit Skills Catalog

Signed skill distribution for AI agents. Publish, discover, verify, and install skills with Ed25519 cryptographic guarantees.

## What Is This?

The Kithkit Skills Catalog is a package registry for AI agent skills — reusable instruction sets that teach agents new capabilities. Every skill archive is signed by the catalog authority key, and every client verifies signatures before installation. No unsigned code runs.

```
┌──────────────────────────────────────────────────────────────────┐
│                       Skills Catalog                             │
│                                                                  │
│  Author                     Catalog (GitHub)         Consumer    │
│  ──────                     ────────────────         ────────    │
│                                                                  │
│  ┌─────────┐   PR    ┌──────────────────┐  fetch  ┌──────────┐  │
│  │ SKILL.md│──────▶  │  CI: lint +      │ ◀────── │ @kithkit │  │
│  │ manifest│         │  sign + index    │         │ /client  │  │
│  └─────────┘         └────────┬─────────┘         └────┬─────┘  │
│                               │                        │        │
│                               ▼                        ▼        │
│                      ┌────────────────┐       ┌──────────────┐  │
│                      │ index.json     │       │ verify sig   │  │
│                      │ (signed)       │       │ verify hash  │  │
│                      │ archives/*.gz  │       │ extract      │  │
│                      │ revoked.json   │       │ review       │  │
│                      └────────────────┘       │ install      │  │
│                                               └──────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Packages

| Package | Description |
|---------|-------------|
| [`@kithkit/catalog`](packages/catalog) | Index builder, archive manager, CI tooling |
| [`@kithkit/client`](packages/client) | Search, install, update, uninstall, security review |
| [`@kithkit/linter`](packages/linter) | Skill validation — structure, security, naming, scope |
| [`@kithkit/sign`](packages/sign) | Ed25519 signing and verification primitives |

## Quickstart

### For Skill Authors

Create a skill, lint it, package it, submit a PR:

```bash
# 1. Create your skill directory
mkdir my-skill && cd my-skill

# 2. Write manifest.yaml and SKILL.md (see docs/authoring.md)

# 3. Lint locally
cd ../packages/linter && npm install && npm run build
node dist/cli.js ../../my-skill/

# 4. Package as archive
tar czf my-skill-1.0.0.tar.gz my-skill/

# 5. Fork, place archive at archives/my-skill/my-skill-1.0.0.tar.gz, open PR
```

See [docs/authoring.md](docs/authoring.md) for the complete author guide.

### For Skill Consumers

Fetch the catalog, search, and install:

```typescript
import {
  CatalogCache,
  verifyAndParseIndex,
  searchCatalog,
  installSkill,
  patternBasedReview,
} from '@kithkit/client';

// 1. Fetch and verify the signed index
const response = await fetch('https://raw.githubusercontent.com/.../index.json');
const signedIndex = await response.json();
const result = verifyAndParseIndex(signedIndex, CATALOG_PUBLIC_KEY);
if (!result.valid) throw new Error(result.error);

// 2. Search
const results = searchCatalog(result.index, { text: 'weather' });

// 3. Review (pattern-based + LLM)
const findings = patternBasedReview(skillContent, declaredCapabilities);

// 4. Install
const installResult = await installSkill({
  skillName: 'weather-check',
  index: result.index,
  publicKeyBase64: CATALOG_PUBLIC_KEY,
  fetchArchive: url => fetch(url).then(r => r.arrayBuffer()).then(Buffer.from),
  skillsDir: '.claude/skills/',
});
```

See [docs/consuming.md](docs/consuming.md) for the complete consumer guide.

## Security Model

**Two-layer security review** protects consumers:

1. **Pattern-based scanner** — deterministic regex detection for known attack vectors (credential access, data exfiltration, prompt injection, permission escalation, config weakening)
2. **LLM-mediated review** — agent reads SKILL.md content *as data* and evaluates against a security rubric. The agent does not follow instructions in the skill; it judges them.

**Trust levels** indicate provenance:

| Level | Meaning |
|-------|---------|
| `first-party` | Built by catalog maintainers |
| `verified` | Published by an identity-verified author |
| `community` | Community-contributed (default) |

**Revocation** — compromised skills are added to `revoked.json` (signed). Clients check revocation before every install.

## Skill Format

A skill is a directory containing:

```
my-skill/
  manifest.yaml   # Required — metadata, capabilities, config schema
  SKILL.md        # Required — agent instructions
  reference.md    # Optional — additional context
  CHANGELOG.md    # Optional — version history
```

Distributed as `.tar.gz` archives with a single top-level directory matching the skill name.

### manifest.yaml

```yaml
name: weather-check
version: 1.0.0
description: Check weather forecasts for any location
author:
  name: Jane Doe
  github: janedoe
capabilities:
  required:
    - web_fetch
    - notification
  optional:
    - memory_write
config:
  - key: api_key
    type: credential
    required: true
    description: OpenWeather API key
tags:
  - weather
  - utility
category: utilities
```

## Well-Known Capabilities

| Capability | Description |
|-----------|-------------|
| `file_read` | Read files from the local filesystem |
| `file_write` | Write or create files |
| `bash` | Execute shell commands |
| `web_fetch` | Fetch content from URLs |
| `web_search` | Perform web searches |
| `git` | Git version control operations |
| `github` | GitHub API interactions |
| `keychain_read` | Read credentials from secure storage |
| `notification` | Send notifications |
| `browser` | Automate browser interactions |

See [`packages/linter/src/capabilities.ts`](packages/linter/src/capabilities.ts) for the full list.

## Development

```bash
# Clone
git clone https://github.com/RockaRhymeLLC/kithkit-skills-catalog.git
cd kithkit-skills-catalog

# Install dependencies (npm workspaces)
npm install

# Type-check all packages
npm run lint --workspaces

# Run all tests
npm test --workspaces

# Build the sign package (only one with build output committed)
cd packages/sign && npm run build
```

### Project Structure

```
kithkit-skills-catalog/
  packages/
    catalog/     # Index builder, archive ops, CI scripts
    client/      # Consumer library — search, install, review
    linter/      # Skill validation checks
    sign/        # Ed25519 crypto primitives
  docs/
    authoring.md   # Skill author guide
    consuming.md   # Skill consumer guide
    signing.md     # Key management and signing workflow
  archives/      # Skill archives (populated via PRs)
  index.json     # Signed catalog index
  revoked.json   # Signed revocation list
  catalog-authority.pub  # Catalog authority public key
```

## Contributing

See [CONTRIBUTING.md](packages/catalog/CONTRIBUTING.md) for the skill submission workflow.

## License

MIT
