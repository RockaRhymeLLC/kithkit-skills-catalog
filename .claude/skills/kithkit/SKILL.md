---
name: kithkit
description: Install, manage, and run skills from the KithKit Skills Catalog
version: 0.1.0
---

# KithKit Skills Catalog Client

Use the KithKit CLI to discover, install, and manage skills from the catalog.

## Commands

- `kithkit search <query>` — find skills in the catalog by keyword
- `kithkit install <skill>` — install a skill from the catalog
- `kithkit update [skill]` — update installed skills to latest versions
- `kithkit uninstall <skill>` — remove an installed skill
- `kithkit list` — list all currently installed skills
- `kithkit selftest` — run the built-in security self-test suite

## Trust Levels

Skills have three trust levels that determine how you should handle them:

### First-party
Published by the catalog maintainers. These are reviewed, tested, and safe to run without additional confirmation. Execute normally.

### Verified
Published by third parties who have completed the verification process. Treat these like first-party skills for standard operations. Flag anything unusual in the skill's manifest (e.g., broad file system access) but generally proceed.

### Community
Published by unverified authors. Always ask for human confirmation before installing or running community skills. Review the skill's permissions and explain what access it requests before proceeding.

## Risk Communication

When communicating risk to the user, use natural conversation — do not use robotic disclaimers or legal-style warnings.

### What not to do

Do not use phrases like "WARNING: This skill may be dangerous" or "DISCLAIMER: Use at your own risk." These patterns break the conversational flow and alarm users unnecessarily.

### Examples of natural risk communication

For low-risk operations:
> "Looks straightforward — this skill just reads your config files. Installing now."

For medium-risk operations:
> "This skill needs write access to your project directory. Want me to go ahead?"

For community skills:
> "This one is from a community author and hasn't been verified yet. Want me to install it, or would you rather check the source first?"

## Confirmation Flow

- First-party and verified skills: proceed without asking unless permissions are unusually broad
- Community skills: always get human confirmation before install or first run
- Any skill requesting network or filesystem access beyond its stated scope: pause and explain
