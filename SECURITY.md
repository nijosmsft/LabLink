# Security Policy

## Supported versions

Use the latest released version of LabLink, or the current default branch if you are validating unreleased changes.

## Reporting a vulnerability

If this repository is hosted on GitHub, please use **private vulnerability reporting / GitHub Security Advisories** for sensitive reports when that feature is enabled.

If private reporting is not available:

1. **Do not** open a public issue for a security vulnerability.
2. Contact the repository maintainers through a private channel provided by the hosting organization.
3. Include the affected version, reproduction details, impact, and any relevant logs or configuration notes.

## Recommended secure deployment

For public or shared environments, the recommended LabLink configuration is:

- `scripts\bootstrap-operator.ps1`
- `scripts\bootstrap-windows-node.ps1`
- `LABLINK_TRANSPORT=mtls`
- `LABLINK_AGENT_TOKEN_FILE`
- generated client/server certificates from `lablink-ca.exe`

Avoid:

- `LABLINK_TRANSPORT=insecure` outside migration scenarios
- committing token files, private keys, or issued certificates to source control
- reusing the same PKI material across unrelated environments

## Secret handling notes

The recommended public path uses **token files plus local filesystem ACLs** instead of placing shared tokens directly in `.mcp.json`.

`save_credential` remains available as an operator convenience feature, but on shared operator machines you should prefer:

- interactive `PSCredential` prompts
- the bootstrap scripts
- or an external secret-management workflow

## Scope

This document covers vulnerabilities in the LabLink codebase and the recommended bootstrap/deployment flow that ships with it.
