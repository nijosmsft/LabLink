# File transfers in LabLink

## Overview

LabLink provides two tools for moving files between the operator machine and a node:

- push_file: local -> node, streamed over a client-streaming gRPC RPC at 1 MiB chunks. The receiver writes a temporary file (`.di-upload-*`) and atomically renames on success.
- pull_file: node -> local, streamed over a server-streaming gRPC RPC at 1 MiB chunks. The receiver writes a temporary file (`.di-download-*`) and atomically renames on success.
- Each call is one transactional stream. If the connection drops at byte N, the partial temp file is discarded and the retry starts from byte 0. Suitable for small-to-medium files; see the envelope below for large transfers and the "Future work" section for the planned resumable path.

---

## Throughput envelope (illustrative)

Real throughput depends on link speed, NIC, disk I/O on both ends, CPU load, and concurrency.
The numbers below are rule-of-thumb figures for sizing `timeout_seconds`. Measure your own
environment with `iperf3` before locking in any value.

| File size | 1 GbE line-rate | 10 GbE line-rate | Loopback |
|-----------|-----------------|------------------|----------|
| 100 MiB   | ~1s             | <1s              | <1s      |
| 1 GiB     | ~9s             | ~1s              | <1s      |
| 5 GiB     | ~45s            | ~5s              | ~2s      |
| 10 GiB    | ~90s            | ~10s             | ~4s      |

> Numbers above are physical line-rate. Real LabLink throughput is typically 30-60% of line-rate
> after gRPC framing, mTLS, 1 MiB chunk handling, and disk on both ends. Size `timeout_seconds`
> for at least 3x the line-rate estimate.

---

## Recommended size classes

| Class      | Size range        | 1 GbE guideline             | 10 GbE guideline            |
|------------|-------------------|-----------------------------|-----------------------------|
| Small      | <= 100 MiB        | Default timeout is fine.    | Default timeout is fine.    |
| Medium     | 100 MiB - 1 GiB   | `timeout_seconds = 120`     | `timeout_seconds = 60`      |
| Large      | 1 GiB - 10 GiB    | `timeout_seconds = 600`     | `timeout_seconds = 120`     |
| Very large | > 10 GiB          | Use the workaround below.   | Use the workaround below.   |

For the Large class on a 1 GbE link, confirm that no other heavy traffic is competing on the
link before you start the transfer.

---

## timeout_seconds

`timeout_seconds` is an integer argument accepted by both `push_file` and `pull_file`.

- **Type:** int (seconds)
- **Default:** 600
- **Minimum:** 0 (0 = no LabLink-side deadline)
- Negative values are rejected with a validation error.
- There is no maximum, but values above ~3600 are rarely useful -- measure with `iperf3` instead.

When the MCP client supplies a `progressToken` in the request's `_meta`, the LabLink MCP server
sends a `notifications/progress` message every ~5 seconds with `progress` and `total` (per MCP spec). This
keeps the MCP transport's idle-timeout from firing on long transfers. The Copilot CLI client sets
`progressToken` automatically.

If no `progressToken` is supplied, the transfer still runs to completion, but the client must be
willing to wait the full `timeout_seconds` without intermediate signals.

Example: pulling a 3 GiB ETL trace over a 10 GbE link

```json
{
  "tool": "pull_file",
  "arguments": {
    "node": "lab-server-01",
    "remote_path": "C:\\traces\\capture.etl",
    "local_path": "C:\\local\\capture.etl",
    "timeout_seconds": 300
  }
}
```

---

## Workaround for very large transfers

For files too large for a single uninterrupted stream, use one of the following approaches.

### Compress and split on the node, then pull chunks

1. Use `execute_command` to compress or split on the node:

   Windows (7-Zip, splits into 1 GiB volumes):

   ```powershell
   7z a -v1g C:\stage\trace.7z C:\traces\big.etl
   ```

   Linux (splits into 1 GiB chunks):

   ```bash
   split -b 1G /path/to/big.bin /tmp/big.bin.part_
   ```

2. Use `pull_file` on each chunk individually.

3. Reassemble locally:

   Windows:

   PowerShell (use cmd /c for copy /b):
   ```powershell
   cmd /c "copy /b chunk1+chunk2+chunk3 reassembled.bin"
   ```
   Or for 7z volumes:
   ```powershell
   7z x trace.7z.001
   ```

   Linux:

   ```bash
   cat big.bin.part_* > big.bin
   ```

### push_file mirror

Same pattern for very-large push_file. Split locally, push each chunk, reassemble and verify on
the node:

1. Split the local file into chunks (Windows or Linux as appropriate).
2. `push_file` each chunk to a staging directory on the node.
3. Use `execute_command` to reassemble on the node:

   Windows:
   ```powershell
   cmd /c "copy /b chunk1+chunk2+chunk3 C:\stage\reassembled.bin"
   ```
   Linux:
   ```bash
   cat /stage/chunk_* > /stage/reassembled.bin
   ```

4. Verify hash on both ends (see "Verifying the reassembled file" below).

### Copy node-to-node without going through the dev machine

If source and destination nodes can reach each other directly, avoid staging through the operator
machine entirely. Use `execute_command` on the destination node:

Windows (Robocopy over a UNC share):

**Warning:** `/MIR` mirrors the source -- it deletes anything in the destination not present in
the source. Use `robocopy <src> <dst> <file> /Z` for a single-file safe copy.

```powershell
robocopy \\source-node\c$\traces \\dest-node\c$\traces /MIR /Z
```

Linux (rsync or scp):

```bash
rsync -avz --progress source-node:/path/to/big.bin /dest/path/
scp source-node:/path/to/big.bin /dest/path/
```

---

## Verifying the reassembled file

After reassembly, compare hashes on both ends:

```powershell
# Local (Windows)
(Get-FileHash -Algorithm SHA256 .\reassembled.bin).Hash
```

```bash
# Node (Linux)
sha256sum /path/to/reassembled.bin
```

```powershell
# Node (Windows, via execute_command)
(Get-FileHash -Algorithm SHA256 C:\path\to\reassembled.bin).Hash
```

Hashes must match exactly. If they differ, the underlying split/transfer/reassembly sequence has
a bug -- re-run.

---

## Future work

Chunked transfer with resumable progress is being tracked separately. Until that lands, the
workarounds above are the recommended path for files larger than roughly 10 GiB.

The design memo lives at `manager-log/lablink-chunked-transfer-design.md` (in the wpr-mcp-poc-staging workspace) and proposes a switchover-by-size design with per-chunk CRC32C + end-of-file SHA-256 integrity, a SQLite-backed resume token store on both server and agent, and Option C wire protocol (`StartTransfer` / `(Put|Get)Chunks` / `CompleteTransfer`).

---

## Troubleshooting

| Error | Likely cause | Fix |
|-------|--------------|-----|
| `MCP error -32001 Request timed out` | `timeout_seconds` exceeded, or the default 600 s is too short for the file size | Pass an explicit `timeout_seconds` value sized to the transfer (see table above). |
| Transfer fails partway through a multi-GiB file | Network blip, MCP-server restart, or agent restart between byte 0 and byte N discards the partial temp file. | Pass `timeout_seconds` sized for the full transfer; transfer over a stable link; or use the very-large-transfer workaround above. Resumable transfer is in design -- see Future work. |
| Slow throughput | CPU saturation on either side, or competing traffic on the link | Measure with `iperf3`. If the link is busy, schedule the transfer during an idle window. |
| Transfer hangs and never times out | MCP transport keepalive misconfigured, or running a LabLink version without the heartbeat | Confirm you are on a LabLink version that includes `timeout_seconds` and the ~5 s heartbeat. |
