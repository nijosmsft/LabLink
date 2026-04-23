# LabLink mTLS and Self-Managed Certificate Plan

## Goal

Add mutually authenticated TLS to the LabLink MCP-server-to-agent gRPC channel without relying on any external PKI product or third-party Go dependencies.

The end state should:

- make `mtls` the default transport
- keep the current plaintext gRPC path only as an explicit migration fallback
- use LabLink-managed certificates
- keep node private keys on the node
- support a practical rollout across real lab machines

## Constraints

- No external certificate authority or PKI service such as Vault, step-ca, or AD CS
- No third-party Go packages for x509, TLS, or enrollment
- The MCP stdio transport does not change; this plan covers only MCP-to-agent gRPC
- Existing plaintext secret-at-rest issues are not solved by this plan and remain separate work

## Recommended scope

This plan is intentionally phased.

### Phase 1

Ship mTLS with operator-provided or LabLink-generated PEM files and support manual or deploy-time certificate issuance.

### Phase 2

Add self-managed certificate automation within LabLink itself so deployment and renewal do not depend on external tooling.

The first release does **not** need a full enterprise PKI feature set. It needs a secure transport, a stable certificate model, and a manageable operator workflow.

## Recommended architecture

### 1. Transport modes

LabLink should support two transport modes:

- `mtls` - default and preferred
- `insecure` - explicit fallback for migration only

The current `LABLINK_ALLOW_INSECURE` behavior should remain as a compatibility bridge, but the long-term config surface should move to an explicit transport mode rather than a growing set of booleans.

### 2. Core components

Recommended components inside the repo:

- `internal\security`
  - transport-mode resolution
  - shared gRPC credential construction
  - TLS config loading and validation
- `internal\pki`
  - certificate and key generation using the Go standard library
  - CSR creation and signing helpers
  - PEM loading and saving
  - serial number generation and issuance metadata
- `cmd\lablink-ca`
  - LabLink-managed CA utility
  - bootstrap commands for root/intermediate creation
  - client certificate issuance
  - server CSR signing
  - optional future enrollment service mode
- `cmd\agent`
  - mTLS server startup
  - local key generation and CSR creation
  - optional future renewal helper
- `cmd\server`
  - mTLS client configuration
  - connection-pool construction using shared TLS settings

## Certificate model

### Recommended v1 hierarchy

For a lab-friendly first release, use:

- one self-managed **root CA**
- one self-managed **issuing CA**

The issuing CA signs day-to-day certificates. The root CA is used only to sign the issuing CA and should be touched rarely.

### Why not a single CA cert?

A single CA is simpler, but splitting root and issuing CA gives cleaner future rotation and better operational hygiene with only modest extra code.

### Certificate types

1. **Client certificates**
   - used by the MCP side when dialing agents
   - EKU: `clientAuth`
   - one certificate per operator or MCP profile

2. **Server certificates**
   - used by each LabLink agent
   - EKU: `serverAuth`
   - SAN must match the identity the MCP verifies for that node

### Key algorithm

Use ECDSA P-256 by default.

Reasons:

- supported by the Go standard library
- small keys and certificates
- fast enough for this workload
- simpler than maintaining multiple algorithms in v1

### Certificate lifetimes

Recommended defaults:

- root CA: 5 years
- issuing CA: 1 year
- client cert: 90 days
- server cert: 30 days

Short-lived leaf certificates reduce the need for revocation infrastructure in the first version.

## Identity and name verification

This is the most important correctness detail in the plan.

LabLink often connects to nodes by IP address, but certificate identity should not depend on the dial string alone. The plan should therefore add explicit per-node metadata:

- `transport_mode`
- `tls_server_name`

Recommended additions to `registry.Node`:

```json
{
  "address": "10.100.0.25:9091",
  "transport_mode": "mtls",
  "tls_server_name": "server-25.lablink"
}
```

The MCP client should be able to dial `10.100.0.25:9091` while verifying the certificate against `server-25.lablink`.

## Configuration model

### Shared transport config

Replace the current global `allowInsecure bool` shape with a transport config object.

Recommended fields:

- `Mode`: `mtls` or `insecure`
- `CACertPath`
- `ClientCertPath`
- `ClientKeyPath`
- `ServerCertPath`
- `ServerKeyPath`
- `DefaultServerName`

### Environment variables

Recommended names:

- `LABLINK_TRANSPORT=mtls|insecure`
- `LABLINK_TLS_CA_CERT`
- `LABLINK_TLS_CLIENT_CERT`
- `LABLINK_TLS_CLIENT_KEY`
- `LABLINK_TLS_SERVER_CERT`
- `LABLINK_TLS_SERVER_KEY`
- `LABLINK_TLS_SERVER_NAME`

Compatibility behavior:

- continue accepting `LABLINK_ALLOW_INSECURE=true`
- continue accepting the legacy `DEVICE_INTERACTION_ALLOW_INSECURE`

### Command-line flags

Recommended agent flags:

- `--transport mtls|insecure`
- `--tls-ca <path>`
- `--tls-cert <path>`
- `--tls-key <path>`
- `--generate-server-csr`
- `--csr-out <path>`

Recommended helper and admin commands in `cmd\lablink-ca`:

- `lablink-ca init`
- `lablink-ca issue-client`
- `lablink-ca sign-server-csr`
- `lablink-ca show-cert`

Future optional commands:

- `lablink-ca serve`
- `LabLinkAgent.exe --renew-cert`

## File layout

### Operator machine

Recommended default layout under `~\.lablink\pki\`:

```text
~/.lablink/pki/
  root/
    root.crt
    root.key
  issuing/
    issuing.crt
    issuing.key
  ca-bundle/
    ca.crt
  clients/
    default/
      client.crt
      client.key
  issued/
    servers/
      server-25/
        server-25.crt
        server-25.csr
  db/
    issued.json
```

### Managed nodes

Windows:

```text
C:\LabLink\tls\
  ca.crt
  server.crt
  server.key
  server.csr
```

Linux:

```text
/var/lib/lablink/tls/
  ca.crt
  server.crt
  server.key
  server.csr
```

Private keys should be stored with restrictive permissions:

- `0600` on Unix
- explicit ACL tightening on Windows deployment scripts

## Self-managed issuance workflow

### Recommended v1: deploy-time CSR signing

This is the simplest fully self-managed workflow with no external service dependency.

1. Operator initializes the LabLink CA locally.
2. Operator issues a client certificate locally for the MCP side.
3. `deploy_agent` copies the agent binary and CA bundle to the node.
4. The node generates its own private key locally and writes a CSR.
5. The deployment flow pulls the CSR back to the operator machine.
6. `lablink-ca sign-server-csr` signs the CSR locally.
7. The deployment flow pushes `server.crt` back to the node.
8. The node starts the agent in `mtls` mode.
9. The node is registered with `transport_mode=mtls` and the chosen `tls_server_name`.

This model avoids shipping the server private key from the operator to the node.

### Manual path for non-WinRM or Linux nodes

For nodes not bootstrapped by WinRM:

1. Install `LabLinkAgent.exe` or the Linux agent binary manually.
2. Run `LabLinkAgent --generate-server-csr`.
3. Move the CSR to the operator machine.
4. Run `lablink-ca sign-server-csr`.
5. Copy `ca.crt` and `server.crt` back to the node.
6. Start the agent in `mtls` mode.

This keeps the same certificate model while avoiding external dependencies.

## Future automation path

### Optional Phase 2: built-in LabLink enrollment service

Once the basic CLI-driven flow is stable, add an optional local CA service mode:

- `lablink-ca serve`

This service can expose a narrow enrollment API built only with `net/http`, `crypto/tls`, and `crypto/x509`.

Recommended use:

- initial bootstrap still happens with WinRM or manual installation
- renewal can use LabLink's own enrollment API

### Why this should be phase 2

Auto-renewal introduces policy and authentication questions:

- how a node authenticates to the CA before it already has a valid cert
- how to constrain allowed SANs
- how to revoke or replace compromised identities

Those are solvable in pure Go, but they add operational complexity that is not required for the first secure transport release.

## Issuance policy

The CA should enforce simple, explicit policy in v1.

### Client cert policy

- subject CN or URI should identify the operator or MCP profile
- EKU must contain only `clientAuth`
- SANs are optional unless the design later wants identity matching on the client side

### Server cert policy

- EKU must contain only `serverAuth`
- SANs must come from an explicit requested identity
- the requested `tls_server_name` must be validated by the deployment flow

The signing command should not accept arbitrary SANs without checks.

## CA state and metadata

`internal\pki` should maintain a small local metadata store, for example `issued.json`, that records:

- serial number
- subject
- SANs
- certificate type (`client` or `server`)
- not-before / not-after
- fingerprint
- node name or profile name
- status (`issued`, `revoked`, `expired`)

This does not need to be a full PKI database. It only needs enough metadata for auditability and safe re-issuance.

## Revocation strategy

### v1

Do not build CRL or OCSP first.

Instead:

- use short-lived leaf certificates
- rotate regularly
- support manual re-issue
- keep the issuing CA replaceable

### Future

If revocation becomes necessary, add one of:

- a denylist of serial numbers on the MCP side
- a CRL file generated by `lablink-ca`

But this should not block the initial mTLS rollout.

## Recommended repository changes

### `internal\security`

- create a transport config type rather than passing a boolean
- add TLS credential builders for client and server
- make token credential requirements depend on transport mode

### `internal\registry`

Add:

- `transport_mode`
- `tls_server_name`

Optionally later:

- `cert_profile`
- `certificate_expires_at`

### `internal\agentclient`

- replace `insecure.NewCredentials()` with mode-aware credential construction
- move per-node server-name handling into the pool or a shared helper

### `cmd\agent`

- load mTLS config
- serve gRPC with `RequireAndVerifyClientCert`
- add CSR generation helper
- keep insecure mode as explicit fallback only

### `cmd\server`

- load shared transport config
- fail early if `mtls` is selected but the required PEMs are missing

### `cmd\lablink-ca`

Add a new stdlib-only binary for:

- CA initialization
- client cert issuance
- server CSR signing
- certificate inspection

### `internal\mcptools\deploy.go`

- update `deploy_agent` to handle mTLS inputs
- support `tls_server_name`
- auto-register nodes with `transport_mode=mtls`

### `scripts\deploy-agent.ps1`

Extend to:

- generate server CSR remotely
- pull CSR back
- push signed server cert and CA bundle
- create `C:\LabLink\tls\`
- tighten key ACLs
- install the service with `--transport mtls --tls-ca ... --tls-cert ... --tls-key ...`

### `scripts\install-agent.ps1`

Extend to:

- install from existing local PEM inputs
- enforce restrictive file permissions
- install the service in `mtls` mode

## Phased implementation plan

### Phase 0 - transport refactor

- introduce a transport config object
- replace the global `allowInsecure` shape
- support per-node transport metadata

### Phase 1 - static mTLS

- add TLS credential helpers
- wire MCP and agent to use PEM files
- add `tls_server_name`
- keep insecure mode as explicit fallback

### Phase 2 - self-managed CA CLI

- add `internal\pki`
- add `cmd\lablink-ca`
- support CA init, client issue, and server CSR signing

### Phase 3 - deploy-time certificate automation

- update WinRM deployment to generate CSR on the node
- sign locally on the operator machine
- push back signed certs and CA bundle
- auto-register node in `mtls` mode

### Phase 4 - renewal workflow

- add operator-driven renewal commands first
- consider an optional `lablink-ca serve` mode later
- leave revocation infrastructure out until the basic renewal path is proven

## Testing plan

### Unit tests

- transport config resolution
- invalid config combinations
- PEM loading failures
- SAN matching and server-name override behavior
- CSR creation and certificate signing helpers

### Integration tests

- successful client-to-agent mTLS handshake
- handshake failure for unknown CA
- handshake failure when the client cert is missing
- handshake failure when the server cert SAN does not match `tls_server_name`
- fallback insecure mode still works only when explicitly enabled

### Deployment tests

- WinRM deployment with remote CSR generation
- remote service start in `mtls` mode
- agent probe success after registration

## Open questions

1. Should the first CA release include a root + issuing CA split immediately, or should the repo ship a simpler single-CA mode first and migrate later?
2. Should `transport_mode` be stored per node only, or also have a global default in the MCP config?
3. Should the PSK remain enabled over mTLS in the first release, or should mTLS alone be considered sufficient for initial rollout?
4. How much operator UX should `cmd\lablink-ca` provide in v1 versus keeping it as a low-level admin utility?

## Recommendation

Build the first secure release in this order:

1. static mTLS with PEM files
2. self-managed LabLink CA CLI
3. deploy-time CSR signing with WinRM automation
4. optional enrollment service later

That sequence delivers a secure transport quickly, keeps the implementation fully inside Go and the LabLink repo, and avoids over-designing PKI features before the basic mTLS path is proven in the lab.
