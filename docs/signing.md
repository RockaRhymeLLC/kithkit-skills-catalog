# Signing and Key Management

The Kithkit Skills Catalog uses Ed25519 digital signatures for integrity verification. This document covers key generation, custody, signing workflows, and rotation procedures.

## Key Format

- **Algorithm**: Ed25519
- **Private key**: PKCS8 DER, base64-encoded
- **Public key**: SPKI DER, base64-encoded
- **Signatures**: Raw Ed25519 (64 bytes), base64-encoded

Node.js `crypto.generateKeyPairSync('ed25519')` produces keys in this format natively.

## Key Generation

### Via CLI

```bash
cd packages/catalog
node --experimental-strip-types src/ci.ts keygen
```

Output:

```
Public key:  MCowBQYDK2VwAyEA...
Private key: MC4CAQAwBQYDK2Vw...
```

### Via Code

```typescript
import { generateCatalogAuthority } from '@kithkit/sign';
// or
import { generateKeyPair } from '@kithkit/catalog';

const { publicKey, privateKey } = generateCatalogAuthority();
```

## Key Custody

### Production Keys

| Key | Location | Access |
|-----|----------|--------|
| Private key | GitHub Actions secret `KITHKIT_CATALOG_PRIVATE_KEY` | Repository maintainers only |
| Private key (backup) | macOS Keychain `credential-kithkit-catalog-authority` | Operator machine only |
| Public key | `catalog-authority.pub` in repo root | Public |

### Storing the Private Key

**GitHub Actions:**

```bash
# Set as repository secret (Settings → Secrets → Actions)
# Name: KITHKIT_CATALOG_PRIVATE_KEY
# Value: The base64-encoded private key string
```

**macOS Keychain (operator backup):**

```bash
security add-generic-password \
  -s credential-kithkit-catalog-authority \
  -a kithkit \
  -w "MC4CAQAwBQYDK2Vw..." \
  -T "" \
  2>/dev/null || security delete-generic-password \
    -s credential-kithkit-catalog-authority \
    2>/dev/null && security add-generic-password \
    -s credential-kithkit-catalog-authority \
    -a kithkit \
    -w "MC4CAQAwBQYDK2Vw..."
```

### Publishing the Public Key

The public key is committed to the repo as `catalog-authority.pub` (plain text, base64 encoded). Clients read this file to verify signatures.

## What Gets Signed

### Archive Signatures

Each `.tar.gz` skill archive is signed:

1. Compute SHA-256 hash of the archive bytes
2. Sign the raw hash bytes (32 bytes) with Ed25519
3. Store signature in `index.json` under `versions[version].signature`

### Index Signature

The catalog index (`index.json`) is signed:

1. Remove the `signature` field from the index object
2. Serialize the remaining `{version, updated, skills}` to canonical JSON (sorted keys, no whitespace)
3. Sign the canonical JSON bytes with Ed25519
4. Store signature as the `signature` field in the top-level object

### Revocation List Signature

The revocation list (`revoked.json`) is signed:

1. Sort entries by `(name, version)` for determinism
2. Serialize entries array to canonical JSON
3. Sign the canonical JSON bytes with Ed25519
4. Store as the `signature` field

### Canonical JSON

Canonical JSON ensures that signing is deterministic — the same data always produces the same bytes:

- Object keys are sorted alphabetically at all nesting levels
- No whitespace between tokens
- Arrays preserve element order but elements are recursively sorted

## CI Signing Workflow

On PR merge (when archives change):

```yaml
# .github/workflows/ci.yml — sign-on-merge job
- name: Sign and rebuild index
  env:
    KITHKIT_CATALOG_PRIVATE_KEY: ${{ secrets.KITHKIT_CATALOG_PRIVATE_KEY }}
  run: |
    node --experimental-strip-types packages/catalog/src/ci.ts build archives/ index.json
```

The CI script:

1. Scans `archives/` for all `.tar.gz` files
2. Extracts `manifest.yaml` from each archive
3. Computes SHA-256 hash of each archive
4. Signs each hash with the private key
5. Builds the index with all skill entries
6. Signs the complete index
7. Writes `index.json`

## Manual Operations

### Sign a Single Archive

```bash
KITHKIT_CATALOG_PRIVATE_KEY="..." \
  node --experimental-strip-types packages/catalog/src/ci.ts sign path/to/archive.tar.gz
```

### Rebuild Entire Index

```bash
KITHKIT_CATALOG_PRIVATE_KEY="..." \
  node --experimental-strip-types packages/catalog/src/ci.ts build archives/ index.json
```

### Verify Index

```bash
KITHKIT_CATALOG_PUBLIC_KEY="$(cat catalog-authority.pub)" \
  node --experimental-strip-types packages/catalog/src/ci.ts verify index.json
```

## Key Rotation

If the private key is compromised or needs rotation:

1. **Generate new keypair** using `keygen` command
2. **Re-sign all archives** by running `build` with the new private key
3. **Update `catalog-authority.pub`** with the new public key
4. **Update GitHub Actions secret** with the new private key
5. **Update Keychain backup** with the new private key
6. **Announce rotation** — consumers must update their cached public key

Key rotation does not invalidate installed skills — they were verified at install time. Only new fetches and installs use the new key.

## Verification (Consumer Side)

Clients verify at multiple points:

1. **Index verification** — on every fetch, verify `index.json` signature against the public key
2. **Archive verification** — on every install, verify archive hash matches index entry AND signature is valid
3. **Revocation check** — on every install, verify `revoked.json` signature and check for revoked versions

If any verification fails, the operation is aborted with a clear error message.
