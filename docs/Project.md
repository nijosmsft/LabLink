# LabLink Project

## Overview

LabLink is a remote machine automation system built for AI-assisted engineering workflows. It combines a local MCP server with a lightweight remote node agent so an AI assistant can interact with Windows and Linux test machines through a consistent, tool-friendly interface.

The project started as **device-interaction** and was renamed to **LabLink** as the scope became clearer: it is a bridge between an AI agent and a fleet of lab machines.

At a high level, LabLink lets an AI assistant:

- execute commands and scripts on remote machines
- stream stdout and stderr back to the local session
- transfer files to and from nodes
- inspect and kill remote processes
- group machines into roles and topologies
- deploy agents to Windows nodes over WinRM
- collect diagnostics and perform lab-oriented machine operations

This makes LabLink useful for performance labs, distributed test environments, systems debugging, driver bring-up, and other workflows where one operator or one AI agent needs structured access to multiple machines.

## Why the project exists

Traditional remote access tools such as PowerShell Remoting and SSH are powerful, but they are not optimized for AI-driven workflows. They expose raw shell sessions rather than higher-level operations, and they leave a lot of state management, topology modeling, and multi-node orchestration to the caller.

LabLink exists to provide:

- a stable **MCP surface** for AI assistants
- a simple **remote execution agent** on each machine
- a persistent **node registry** and **topology model**
- repeatable **deployment and diagnostics workflows**
- a single place to improve reliability, safety, and eventually production readiness

## Architecture

LabLink uses a two-part design:

```text
AI assistant <-> MCP server (local, stdio) <-> node agent (remote, gRPC)
```

### 1. Local MCP server

The MCP server runs on the operator machine and exposes LabLink tools to an AI client such as Copilot or Claude. It is responsible for:

- loading the node registry and saved credentials
- exposing the automation tools
- tracking command history and audit data
- maintaining node topology and context
- connecting to remote node agents over gRPC

### 2. Remote node agent

The node agent is a single binary deployed to each managed machine. It is responsible for:

- running commands and scripts
- streaming output back to the MCP server
- enforcing command timeouts
- transferring files
- listing and killing processes
- reporting basic machine metadata

### 3. Supporting scripts and local state

LabLink also includes:

- WinRM deployment scripts for Windows agent installation
- local registry files for nodes, credentials, and history
- helper logic for diagnostics, package deployment, patching, and orchestration

By default, local state lives under `~/.lablink`.

## Main components in the repository

### `cmd/server`

The local MCP server entrypoint. This is the part configured in `.mcp.json` and launched by the AI client.

### `cmd/agent`

The remote gRPC agent. This is the binary that runs as a background service or standalone process on managed machines.

### `internal/mcptools`

The MCP tool implementations. This package contains the logic behind features such as:

- node registration and inventory
- command execution
- file transfer
- process management
- topology and role-based orchestration
- deployment
- diagnostics
- package operations
- Windows-specific patching and reboot flows

### `internal/registry`

Persistent node and topology storage.

### `internal/agentclient`

The gRPC client connection layer used by the MCP server to talk to remote agents.

### `proto/agent`

The gRPC contract shared by the MCP server and node agent.

### `scripts`

Operational scripts, especially for deploying and installing the Windows agent.

## What LabLink can do today

LabLink already supports a useful lab automation workflow:

1. Deploy the node agent to a machine.
2. Register the machine in the LabLink inventory.
3. Run commands or scripts remotely with streamed output.
4. Push and pull files.
5. Set persistent node context such as working directories or environment variables.
6. Group machines into named topologies with roles like `server` and `client`.
7. Run role-based or multi-node operations across a test environment.
8. Collect history and diagnostics.

It also includes several Windows-specific workflows that are important in systems and networking labs, such as service installation, test-signing support, reboot helpers, and binary patch/restore flows.

## Typical use cases

LabLink is aimed at scenarios such as:

- UDP / networking performance test labs
- Windows systems validation and experimentation
- multi-machine benchmark orchestration
- remote process and file management for AI-assisted debugging
- test machine setup and maintenance

It is especially useful when a single AI session needs controlled access to a set of machines with known roles.

## Current maturity

LabLink is functional and has already gone through a significant reliability-hardening phase. Recent work improved areas such as:

- timeout handling for long-running and infinite commands
- streaming behavior for large output and child-process launch patterns
- file transfer correctness
- diagnostics pull reliability
- scheduled command behavior
- topology consistency
- remote agent rollout and service replacement

The project has also been migrated from the older **device-interaction** identity to **LabLink**, with compatibility kept for some legacy environment variables and registry paths during the transition.

## Security and production-readiness posture

LabLink now ships with a **public-friendly recommended setup path**:

- bootstrap scripts for the operator machine and Windows nodes
- mTLS as the default transport
- token-file based MCP integration
- generated MCP config snippets for AI infrastructure
- a security policy document and clearer public setup guidance

That moves the project much closer to a usable public baseline.

LabLink should still be treated as an **admin/operator tool** rather than a hardened zero-trust control plane. Important notes remain:

- mTLS and token files are the recommended public path, but advanced flows still require operator care
- the shared-token layer still exists on top of transport security
- convenience features such as stored WinRM credential profiles are more admin-oriented than multi-tenant hardened

The remaining production-hardening work is now more about deeper lifecycle/security polish than basic bring-up:

- certificate rotation and fleet ergonomics
- stronger secret-management integrations
- clearer release packaging and versioned binaries
- longer-term updater and service-management improvements

## Project direction

LabLink is intended to evolve from a useful internal lab tool into a more polished and safer remote automation platform for AI-assisted workflows.

Near-term priorities are:

- security hardening
- public-repo cleanup
- better deployment and upgrade workflows
- clearer documentation and project packaging

Longer-term, the goal is for LabLink to be a reliable machine-control plane for engineering labs where AI agents need structured, auditable access to a fleet of test systems.

## Summary

LabLink is the control layer between an AI assistant and a set of remote lab machines. It gives AI workflows a practical way to execute commands, move files, inspect processes, and orchestrate multiple nodes through a consistent MCP and gRPC design.

In short: **LabLink is a remote lab automation bridge for AI agents.**
