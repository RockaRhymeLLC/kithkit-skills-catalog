# Skill Author Guide

This guide walks through creating, linting, packaging, and submitting a skill to the Kithkit Skills Catalog.

## Prerequisites

- Node.js 20+
- Git
- A GitHub account (your identity for v1)

## 1. Create Your Skill

A skill is a directory with two required files:

```
my-skill/
  manifest.yaml   # Metadata, capabilities, config schema
  SKILL.md        # Instructions for the AI agent
  reference.md    # Optional — additional context
  CHANGELOG.md    # Optional — version history
```

### manifest.yaml

The manifest declares your skill's metadata, what capabilities it needs, and any configuration the consumer must provide.

```yaml
name: my-skill
version: 1.0.0
description: One-line description of what your skill does
author:
  name: Your Name
  github: your-github-username
capabilities:
  required:
    - web_fetch          # Capabilities the skill cannot work without
  optional:
    - memory_write       # Nice-to-have capabilities
config:
  - key: api_key
    type: credential     # Stored in Keychain, never in config file
    required: true
    description: API key for the external service
  - key: units
    type: enum
    required: false
    default: metric
    description: Measurement units
    enum_values:
      - metric
      - imperial
tags:
  - utility              # Searchable tags
  - weather
category: utilities      # One category
```

**Field reference:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Lowercase, hyphens only. 2-64 chars. Must match directory name. |
| `version` | Yes | Semver (e.g., `1.0.0`) |
| `description` | Yes | One-line summary |
| `author.name` | Yes | Display name |
| `author.github` | Yes | GitHub username |
| `capabilities.required` | Yes | Array of well-known capability names |
| `capabilities.optional` | No | Capabilities used if available |
| `config` | No | Array of config field definitions |
| `tags` | No | Searchable tags |
| `category` | No | Single category string |
| `trust_level` | No | Set by maintainers, not authors |

**Config field types:**

| Type | Description |
|------|-------------|
| `string` | Plain text |
| `number` | Numeric value |
| `boolean` | true/false |
| `enum` | One of `enum_values` |
| `credential` | Sensitive — stored in Keychain, not config file |

### SKILL.md

The agent instructions file. This is what the AI agent reads when the skill is activated. Write it as if you're briefing a capable assistant:

```markdown
# Weather Check

Check weather forecasts for any location using the OpenWeather API.

## Usage

/weather <location>

## How It Works

1. Takes a location name or coordinates
2. Fetches current weather from OpenWeather API
3. Formats results in a readable summary
```

**Guidelines:**

- Be specific and concrete — agents follow instructions literally
- Declare all external endpoints the skill will contact
- Don't include instructions that exceed your declared capabilities
- Don't reference credentials by name in SKILL.md — use config field references

### reference.md (optional)

Additional context documents. Use for API schemas, detailed protocol specs, or large reference tables that would bloat SKILL.md.

### CHANGELOG.md (optional)

Track changes across versions:

```markdown
# Changelog

## 1.1.0 — 2026-03-01
- Added 5-day forecast support
- Fixed temperature unit conversion

## 1.0.0 — 2026-02-20
- Initial release
```

## 2. Lint Locally

The linter validates structure, manifest, security, naming, and scope:

```bash
# From the repo root
cd packages/linter
npm install
npm run build

# Lint your skill
node dist/cli.js /path/to/my-skill/

# JSON output (for CI)
node dist/cli.js --json /path/to/my-skill/
```

**Checks performed:**

| Check | What it validates |
|-------|-------------------|
| `structure` | Required files exist, no unexpected files |
| `manifest` | Valid YAML, required fields, correct types |
| `security` | Pattern scan for credential access, exfiltration, injection |
| `scope` | Capabilities used in SKILL.md match manifest declarations |
| `naming` | Name follows convention, no reserved words, no typosquatting |
| `unicode` | No invisible characters, homoglyph detection |

Fix all **errors** before submitting. **Warnings** are reviewed by maintainers.

## 3. Package as Archive

```bash
# From the parent directory of your skill
tar czf my-skill-1.0.0.tar.gz my-skill/
```

**Archive requirements:**

- Format: `.tar.gz` (gzipped tar)
- Single top-level directory matching the skill name
- Naming: `{name}-{version}.tar.gz` (lowercase, hyphens)

## 4. Submit via Pull Request

1. Fork `RockaRhymeLLC/kithkit-skills-catalog`
2. Place your archive at `archives/my-skill/my-skill-1.0.0.tar.gz`
3. Open a pull request to `main`
4. CI automatically runs the linter on your submission
5. If checks pass, a maintainer reviews and merges

## 5. After Merge

Once your PR is merged, CI will:

1. Sign your archive with the catalog authority key (Ed25519)
2. Rebuild `index.json` with your skill's metadata
3. Your skill is now discoverable and installable by any Kithkit consumer

## Security Review

Submitted skills go through two-layer review:

1. **Automated pattern scan** — the linter's security check catches known attack vectors
2. **Maintainer review** — human review of SKILL.md instructions and declared capabilities

Skills that request `keychain_read`, `bash`, or `file_write` receive extra scrutiny.

## Trust Levels

| Level | Description |
|-------|-------------|
| `first-party` | Built by catalog maintainers |
| `verified` | Author identity verified (planned for v2) |
| `community` | Default for all submissions |

Authors cannot set their own trust level. It is assigned by maintainers.

## Version Updates

To publish a new version:

1. Update `manifest.yaml` with the new version
2. Update CHANGELOG.md
3. Create a new archive: `my-skill-1.1.0.tar.gz`
4. Submit a PR placing it alongside the existing version at `archives/my-skill/my-skill-1.1.0.tar.gz`

Both versions remain in the catalog. Consumers can pin specific versions.
