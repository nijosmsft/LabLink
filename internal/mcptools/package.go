package mcptools

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
)

func RegisterPackage(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool) {
	s.AddTool(
		mcp.NewTool("install_package",
			mcp.WithDescription("Push a local directory or zip file to a remote node. Directories are zipped automatically, transferred, and extracted on the node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("local_path", mcp.Required(), mcp.Description("Local directory or .zip file to push")),
			mcp.WithString("remote_dir", mcp.Required(), mcp.Description("Destination directory on the node")),
		),
		installPackageHandler(reg, pool),
	)
}

func installPackageHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		localPath := request.GetString("local_path", "")
		remoteDir := request.GetString("remote_dir", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		// Determine if local_path is a directory or zip.
		info, err := os.Stat(localPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("stat %s: %v", localPath, err)), nil
		}

		var zipPath string
		var tempZip bool

		if info.IsDir() {
			// Zip the directory.
			tmpFile, err := os.CreateTemp("", "di-package-*.zip")
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("create temp zip: %v", err)), nil
			}
			tmpFile.Close()
			zipPath = tmpFile.Name()
			tempZip = true

			if err := zipDirectory(localPath, zipPath); err != nil {
				os.Remove(zipPath)
				return mcp.NewToolResultError(fmt.Sprintf("zip: %v", err)), nil
			}
		} else if strings.HasSuffix(strings.ToLower(localPath), ".zip") {
			zipPath = localPath
		} else {
			return mcp.NewToolResultError("local_path must be a directory or .zip file"), nil
		}

		if tempZip {
			defer os.Remove(zipPath)
		}

		// Use a unique staging path so concurrent installs on the same node do not collide.
		remoteZip := fmt.Sprintf(`C:\LabLink\staging\package-%d.zip`, timeNow().UnixNano())
		pushBytes, err := pushFileToNode(ctx, client, zipPath, remoteZip)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("push zip: %v", err)), nil
		}

		// Extract on node.
		extractCmd := fmt.Sprintf(`
if (-not (Test-Path '%s')) { New-Item -ItemType Directory -Path '%s' -Force | Out-Null }
try {
    Expand-Archive -Path '%s' -DestinationPath '%s' -Force
    $count = (Get-ChildItem '%s' -Recurse -File).Count
    "Extracted $count files to %s"
} finally {
    Remove-Item '%s' -Force -ErrorAction SilentlyContinue
}
`, remoteDir, remoteDir, remoteZip, remoteDir, remoteDir, remoteDir, remoteZip)

		output, exitCode, _, err := executeAndCollect(ctx, client, extractCmd, "powershell", "", nil, 60)
		if err != nil || exitCode != 0 {
			return mcp.NewToolResultError(fmt.Sprintf("extract failed (exit %d):\n%s\nerr: %v", exitCode, output, err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("**Installed package on %s**\n- Transferred: %s\n- %s",
			nodeName, formatBytes(pushBytes), strings.TrimSpace(output))), nil
	}
}

func zipDirectory(srcDir, destZip string) error {
	f, err := os.Create(destZip)
	if err != nil {
		return err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		// Use forward slashes in zip.
		relPath = filepath.ToSlash(relPath)

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		header.Method = zip.Deflate

		writer, err := w.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})
}
