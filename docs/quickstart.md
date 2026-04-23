# LabLink Quickstart

This document describes the supported setup flow for connecting LabLink to an AI client.

## Recommended flow

1. Download the latest release zip (see below).
2. Run `scripts\bootstrap-operator.ps1`.
3. Run `scripts\bootstrap-windows-node.ps1` for each Windows node.

That path is the easiest way to get:

- local PKI bootstrapped
- client and server certificates issued
- a shared token generated
- the remote Windows agent deployed with mTLS
- a local MCP config snippet generated
- the node pre-registered in `~\.lablink\nodes.json`

## Get the binaries

Download `lablink-vX.Y.Z-windows-amd64.zip` from the [Releases page](https://github.com/nijosmsft/LabLink/releases/latest), verify its SHA256 against the published `SHA256SUMS.txt`, and unzip it somewhere stable like `C:\LabLink`. The archive bundles every binary, every bootstrap script, and the example MCP config — there's nothing extra to install.

If you'd rather build from source, run `make build-all` from a clone; the rest of this document applies unchanged.

## Operator bootstrap

Run this once on the operator machine:

```powershell
.\scripts\bootstrap-operator.ps1
```

### What it creates

By default:

```text
~/.lablink/
  agent.token
  mcp.example.json
  pki/
    ca-bundle/ca.crt
    clients/default/client.crt
    clients/default/client.key
    root/...
    issuing/...
```

### Useful options

```powershell
.\scripts\bootstrap-operator.ps1 `
  -HomeDir C:\lablink-home `
  -ClientName copilot `
  -RotateToken `
  -RotateClientCert
```

## Windows node bootstrap

Run this for each Windows node you want to manage:

```powershell
.\scripts\bootstrap-windows-node.ps1 -Machine WIN-NODE-01 -Role server
```

Multiple machines can be bootstrapped in one call; they share the WinRM credential and run sequentially:

```powershell
.\scripts\bootstrap-windows-node.ps1 -Machine WIN-NODE-01,WIN-NODE-02 -Role server
```

If a name resolves over DNS the IPv4 address is auto-detected. Otherwise pass them positionally with `-IPv4Address 10.0.0.10,10.0.0.11`.

### What it does

1. Ensures the operator assets exist.
2. Generates a server key + CSR for the node.
3. Signs the server certificate locally.
4. Deploys `LabLinkAgent.exe` over WinRM.
5. Installs the **LabLink Agent** Windows service on port `9091`.
6. Verifies the node with `LabLinkProbe.exe` when available.
7. Writes the node entry to `~\.lablink\nodes.json`.

### Useful options

```powershell
.\scripts\bootstrap-windows-node.ps1 `
  -Machine build-node-01 `
  -IPv4Address 10.0.0.25 `
  -Role builder `
  -TlsServerName build-node-01.lab.example `
  -Port 9091 `
  -RotateServerCert
```

Use `-SkipRegister` if you only want deployment and verification without touching the local registry.

## AI client integration

The generated `~\.lablink\mcp.example.json` is the recommended starting point.

It uses:

- `LABLINK_AGENT_TOKEN_FILE`
- `LABLINK_TRANSPORT=mtls`
- `LABLINK_TLS_CA`
- `LABLINK_TLS_CERT`
- `LABLINK_TLS_KEY`

This avoids embedding the shared token directly in the `.mcp.json` file.

## Manual flow

If you prefer the lower-level manual setup (no bootstrap scripts):

### 1. Get the binaries

Either download a release zip (see [Get the binaries](#get-the-binaries)) or build from source:

```powershell
make build-all
```

### 2. Initialize PKI

```powershell
.\bin\lablink-ca.exe init -pki-dir C:\lablink-pki
.\bin\lablink-ca.exe issue-client -pki-dir C:\lablink-pki -name operator
```

### 3. Generate and sign a server certificate

```powershell
.\bin\LabLinkAgent.exe --generate-server-csr `
  --tls-server-name WIN-NODE-01 `
  --csr-out C:\lablink-pki\WIN-NODE-01\server.csr `
  --key-out C:\lablink-pki\WIN-NODE-01\server.key

.\bin\lablink-ca.exe sign-server-csr `
  -pki-dir C:\lablink-pki `
  -csr C:\lablink-pki\WIN-NODE-01\server.csr `
  -cert-out C:\lablink-pki\WIN-NODE-01\server.crt
```

### 4. Deploy the agent

```powershell
$cred = Get-Credential
$tokenBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($tokenBytes)
$rng.Dispose()
$token = [Convert]::ToBase64String($tokenBytes)

.\scripts\deploy-agent.ps1 `
  -Machines WIN-NODE-01 `
  -Credential $cred `
  -Token $token `
  -Transport mtls `
  -Port 9091 `
  -TlsCA C:\lablink-pki\ca-bundle\ca.crt `
  -TlsCert C:\lablink-pki\WIN-NODE-01\server.crt `
  -TlsKey C:\lablink-pki\WIN-NODE-01\server.key
```

### 5. Configure the MCP server

```json
{
  "mcpServers": {
    "lablink": {
      "type": "stdio",
      "command": "C:\\git\\LabLink\\bin\\LabLinkServer.exe",
      "args": [],
      "env": {
        "LABLINK_AGENT_TOKEN_FILE": "C:\\Users\\you\\.lablink\\agent.token",
        "LABLINK_TRANSPORT": "mtls",
        "LABLINK_TLS_CA": "C:\\lablink-pki\\ca-bundle\\ca.crt",
        "LABLINK_TLS_CERT": "C:\\lablink-pki\\clients\\operator\\client.crt",
        "LABLINK_TLS_KEY": "C:\\lablink-pki\\clients\\operator\\client.key"
      }
    }
  }
}
```

### 6. Register the node from your AI client

```text
register_node name=WIN-NODE-01 address=10.0.0.10:9091 role=server transport_mode=mtls tls_server_name=WIN-NODE-01
```

## Operational notes

- `LabLinkProbe.exe` is the easiest binary for validating agent connectivity outside MCP.
- `save_credential` is still available inside MCP, but the public bootstrap scripts are the recommended flow when you do not want to persist WinRM credentials as a reusable profile.
- `LabLinkAgent.exe --set-token ...` remains for legacy migration, but the public setup flow prefers `LABLINK_AGENT_TOKEN_FILE`.
