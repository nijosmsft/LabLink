# File transfers in LabLink

## Overview

LabLink provides two tools for moving files between the operator machine and a node:

- `push_file`: transfers a local file to the node. The file body is buffered in memory on both
  sides and sent as a single gRPC RPC.
- `pull_file`: transfers a file from the node to the local machine. Same in-memory, single-RPC
  model as push_file.

Both tools are suitable for small-to-medium files. For files larger than roughly 10 GiB, see the
workaround section below.

---

## Throughput envelope (illustrative)

Real throughput depends on link speed, NIC, disk I/O on both ends, CPU load, and concurrency.
The numbers below are rule-of-thumb figures for sizing `timeout_seconds`. Measure your own
environment with `iperf3` before locking in any value.

| File size | 1 GbE link | 10 GbE link | Loopback |
|-----------|-----------|-------------|----------|
| 100 MiB   | ~10 s     | ~2 s        | <1 s     |
| 1 GiB     | ~90 s     | ~10 s       | ~3 s     |
| 5 GiB     | ~450 s    | ~50 s       | ~15 s    |
| 10 GiB    | ~900 s    | ~100 s      | ~30 s    |

Numbers are illustrative. Confirm with `iperf3` between the dev box and the lab node before
tuning timeouts.

---

## Recommended size classes

| Class      | Size range        | 1 GbE guideline             | 10 GbE guideline            |
|------------|-------------------|-----------------------------|-----------------------------|
| Small      | <= 100 MiB        | Default timeout is fine.    | Default timeout is fine.    |
| Medium     | 100 MiB - 1 GiB   | `timeout_seconds = 300`     | `timeout_seconds = 60`      |
| Large      | 1 GiB - 10 GiB    | `timeout_seconds = 1800`    | `timeout_seconds = 300`     |
| Very large | > 10 GiB          | Use the workaround below.   | Use the workaround below.   |

For the Large class on a 1 GbE link, confirm that no other heavy traffic is competing on the
link before you start the transfer.

---

## timeout_seconds

`timeout_seconds` is an integer argument accepted by both `push_file` and `pull_file`.

- **Type:** int (seconds)
- **Default:** 600
- **Range:** 1 - 86400

The agent emits a heartbeat to the operation registry approximately every 5 seconds during the
transfer. This keeps the MCP transport aware that the call is alive and prevents the underlying
connection from being treated as stalled. Without the heartbeat, long transfers would trigger
"MCP error -32001 Request timed out" even when data is flowing normally.

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

The current in-memory single-RPC model imposes practical limits. If a file is too large, use one
of the following approaches.

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

   ```powershell
   copy /b chunk1 + chunk2 + chunk3 reassembled.bin
   # or, if you used 7-Zip:
   7z x trace.7z.001
   ```

   Linux:

   ```bash
   cat big.bin.part_* > big.bin
   ```

### Copy node-to-node without going through the dev machine

If source and destination nodes can reach each other directly, avoid staging through the operator
machine entirely. Use `execute_command` on the destination node:

Windows (Robocopy over a UNC share):

```powershell
robocopy \\source-node\c$\traces \\dest-node\c$\traces /MIR /Z
```

Linux (rsync or scp):

```bash
rsync -avz --progress source-node:/path/to/big.bin /dest/path/
scp source-node:/path/to/big.bin /dest/path/
```

---

## Future work

Chunked transfer with resumable progress is being tracked separately. Until that lands, the
workarounds above are the recommended path for files larger than roughly 10 GiB.

---

## Troubleshooting

| Error | Likely cause | Fix |
|-------|--------------|-----|
| `MCP error -32001 Request timed out` | `timeout_seconds` exceeded, or the default 600 s is too short for the file size | Pass an explicit `timeout_seconds` value sized to the transfer (see table above). |
| gRPC `ResourceExhausted: trying to send message larger than max` | File body exceeds the gRPC max message size configured on the agent or server | Use the workaround above: split the file or copy node-to-node. |
| Slow throughput | CPU saturation on either side, or competing traffic on the link | Measure with `iperf3`. If the link is busy, schedule the transfer during an idle window. |
| Transfer hangs and never times out | MCP transport keepalive misconfigured, or running a LabLink version without the heartbeat | Confirm you are on a LabLink version that includes `timeout_seconds` and the ~5 s heartbeat. |
