package mcptools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

// activeForward tracks one local listener that is being forwarded to a node.
type activeForward struct {
	ID         string
	Node       string
	RemoteAddr string
	LocalAddr  string
	ln         net.Listener
	created    time.Time
	cancel     context.CancelFunc
}

type forwardRegistry struct {
	mu      sync.Mutex
	entries map[string]*activeForward
}

// global forward registry; one per LabLinkServer process.
var forwards = &forwardRegistry{entries: make(map[string]*activeForward)}

func (r *forwardRegistry) add(f *activeForward) {
	r.mu.Lock()
	r.entries[f.ID] = f
	r.mu.Unlock()
}

func (r *forwardRegistry) remove(id string) *activeForward {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.entries[id]
	if !ok {
		return nil
	}
	delete(r.entries, id)
	return f
}

func (r *forwardRegistry) list() []*activeForward {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*activeForward, 0, len(r.entries))
	for _, f := range r.entries {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].created.Before(out[j].created) })
	return out
}

func newForwardID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "fwd_" + hex.EncodeToString(b[:])
}

// RegisterForward wires the forward_port / stop_forward / list_forwards tools.
func RegisterForward(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, leaseCfg LeaseGateConfig) {
	addTool(s,
		mcp.NewTool("forward_port",
			mcp.WithDescription("Open a local TCP listener that tunnels bytes to a target address on a remote node via the node agent's existing mTLS channel. Use to reach a service that is bound to localhost on the node (for example a debugger MCP server). Returns the bound local address and a forward_id."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from the registry")),
			mcp.WithString("remote_addr", mcp.Required(), mcp.Description("Target host:port on the node, e.g. 127.0.0.1:8765")),
			mcp.WithNumber("local_port", mcp.Description("Local TCP port to bind, 0 = ephemeral")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), forwardPortHandler(reg, pool)),
	)

	addTool(s,
		mcp.NewTool("stop_forward",
			mcp.WithDescription("Close a previously-opened TCP forward."),
			mcp.WithString("forward_id", mcp.Required(), mcp.Description("ID returned by forward_port")),
		),
		stopForwardHandler(),
	)

	addTool(s,
		mcp.NewTool("list_forwards",
			mcp.WithDescription("List all active TCP forwards opened by this server process."),
		),
		listForwardsHandler(),
	)
}

func forwardPortHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		remoteAddr := request.GetString("remote_addr", "")
		localPort := int(request.GetFloat("local_port", 0))

		if nodeName == "" || remoteAddr == "" {
			return mcp.NewToolResultError("node and remote_addr are required"), nil
		}

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("listen: %v", err)), nil
		}

		fwdCtx, cancel := context.WithCancel(context.Background())
		fwd := &activeForward{
			ID:         newForwardID(),
			Node:       nodeName,
			RemoteAddr: remoteAddr,
			LocalAddr:  ln.Addr().String(),
			ln:         ln,
			created:    time.Now(),
			cancel:     cancel,
		}
		forwards.add(fwd)

		go runForwardAcceptLoop(fwdCtx, fwd, client)

		text := fmt.Sprintf("**Forward opened**\n- forward_id: `%s`\n- node: %s\n- local: %s\n- remote: %s",
			fwd.ID, nodeName, fwd.LocalAddr, remoteAddr)
		return mcp.NewToolResultText(text), nil
	}
}

func stopForwardHandler() server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := request.GetString("forward_id", "")
		if id == "" {
			return mcp.NewToolResultError("forward_id is required"), nil
		}
		fwd := forwards.remove(id)
		if fwd == nil {
			return mcp.NewToolResultError(fmt.Sprintf("forward %q not found", id)), nil
		}
		fwd.cancel()
		_ = fwd.ln.Close()
		return mcp.NewToolResultText(fmt.Sprintf("forward %s closed (local=%s)", id, fwd.LocalAddr)), nil
	}
}

func listForwardsHandler() server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		entries := forwards.list()
		if len(entries) == 0 {
			return mcp.NewToolResultText("no active forwards"), nil
		}
		out := "**Active forwards:**\n"
		for _, f := range entries {
			out += fmt.Sprintf("- `%s` node=%s local=%s remote=%s age=%s\n",
				f.ID, f.Node, f.LocalAddr, f.RemoteAddr, time.Since(f.created).Round(time.Second))
		}
		return mcp.NewToolResultText(out), nil
	}
}

// runForwardAcceptLoop is the listener loop: each accepted local connection
// gets its own gRPC Forward stream and a pair of byte-shuttling goroutines.
func runForwardAcceptLoop(ctx context.Context, fwd *activeForward, client pb.NodeAgentClient) {
	defer fwd.ln.Close()
	for {
		conn, err := fwd.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			runForwardConn(ctx, fwd, client, c)
		}(conn)
	}
}

func runForwardConn(ctx context.Context, fwd *activeForward, client pb.NodeAgentClient, conn net.Conn) {
	stream, err := client.Forward(ctx)
	if err != nil {
		return
	}
	if err := stream.Send(&pb.ForwardChunk{TargetAddr: fwd.RemoteAddr}); err != nil {
		_ = stream.CloseSend()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// local -> stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for {
			if streamCtx.Err() != nil {
				return
			}
			n, rerr := conn.Read(buf)
			if n > 0 {
				if serr := stream.Send(&pb.ForwardChunk{Data: append([]byte(nil), buf[:n]...)}); serr != nil {
					cancel()
					return
				}
			}
			if rerr != nil {
				_ = stream.Send(&pb.ForwardChunk{Close: true})
				_ = stream.CloseSend()
				return
			}
		}
	}()

	// stream -> local
	go func() {
		defer wg.Done()
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					cancel()
				}
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				return
			}
			if len(msg.Data) > 0 {
				if _, werr := conn.Write(msg.Data); werr != nil {
					cancel()
					return
				}
			}
			if msg.Close {
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				return
			}
		}
	}()

	wg.Wait()
}

// CloseAllForwards releases all active forwards. Safe to call during shutdown.
func CloseAllForwards() {
	forwards.mu.Lock()
	defer forwards.mu.Unlock()
	for id, f := range forwards.entries {
		f.cancel()
		_ = f.ln.Close()
		delete(forwards.entries, id)
	}
}
