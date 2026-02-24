# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Kithkit Skills Catalog, please report it through **GitHub's private vulnerability reporting**:

1. Go to the [**Security Advisories**](https://github.com/RockaRhymeLLC/kithkit-skills-catalog/security/advisories/new) page, or click the **Security** tab on the repository and select **Report a vulnerability**.
2. Fill out the advisory form with the details listed below.

Do not open a public GitHub issue for security vulnerabilities.

Include as much detail as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions or components
- Any suggested mitigations, if you have them

## Scope

This policy covers:

- **Catalog infrastructure** — the index builder, signing pipeline, and CI workflows in this repository
- **Signing and verification** — the `@kithkit/sign` package and Ed25519 signature chain
- **Published skills** — malicious or compromised skill archives in the `archives/` directory
- **Client-side security** — vulnerabilities in `@kithkit/client` that could allow unsafe skill installation

Out of scope: vulnerabilities in third-party dependencies (report those upstream), or issues that require physical access to the signing key.

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within 48 hours |
| Initial triage and severity assessment | Within 7 days |
| Resolution or mitigation plan communicated | Depends on severity |

We will keep you informed throughout the process. Critical vulnerabilities (e.g., signature bypass, malicious skill distribution) will be prioritized immediately.

## Disclosure

We follow coordinated disclosure. Please give us a reasonable window to remediate before publishing details publicly. We will credit researchers who report valid vulnerabilities unless they prefer to remain anonymous.
