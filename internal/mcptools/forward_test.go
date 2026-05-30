package mcptools

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// minAgent is a tiny NodeAgent server that implements just Forward, used by
// the forward_port unit tests.
type minAgent struct {
	pb.UnimplementedNodeAgentServer
}

func (minAgent) Forward(stream pb.NodeAgent_ForwardServer) error {
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "recv: %v", err)
	}
	if first.TargetAddr == "" {
		return status.Error(codes.InvalidArgument, "target_addr required")
	}
	conn, err := net.DialTimeout("tcp", first.TargetAddr, 2*time.Second)
	if err != nil {
		return status.Errorf(codes.Unavailable, "dial: %v", err)
	}
	defer conn.Close()

	if len(first.Data) > 0 {
		_, _ = conn.Write(first.Data)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			msg, err := stream.Recv()
			if err != nil {
				if tcp, ok := conn.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				return
			}
			if len(msg.Data) > 0 {
				if _, err := conn.Write(msg.Data); err != nil {
					return
				}
			}
			if msg.Close {
				if tcp, ok := conn.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				if serr := stream.Send(&pb.ForwardChunk{Data: append([]byte(nil), buf[:n]...)}); serr != nil {
					return
				}
			}
			if rerr != nil {
				_ = stream.Send(&pb.ForwardChunk{Close: true})
				return
			}
		}
	}()
	wg.Wait()
	return nil
}

func startMinAgent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterNodeAgentServer(srv, minAgent{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); ln.Close() })
	return ln.Addr().String()
}

func startEchoListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func newTestRegistry(t *testing.T, nodeAddr string) *registry.Registry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write nodes.json: %v", err)
	}
	reg := registry.Load(path)
	if err := reg.SetNode(&registry.Node{
		Name:          "node1",
		Address:       nodeAddr,
		TransportMode: string(internalsec.TransportModeInsecure),
	}); err != nil {
		t.Fatalf("SetNode: %v", err)
	}
	return reg
}

func TestForwardPortHandlerEndToEnd(t *testing.T) {
	agentAddr := startMinAgent(t)
	echoAddr := startEchoListener(t)

	reg := newTestRegistry(t, agentAddr)
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	open := forwardPortHandler(reg, pool)
	stop := stopForwardHandler()
	list := listForwardsHandler()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	openReq := mcp.CallToolRequest{}
	openReq.Params.Arguments = map[string]any{"node": "node1", "remote_addr": echoAddr}

	res, err := open(ctx, openReq)
	if err != nil || res == nil || res.IsError {
		t.Fatalf("forward_port: err=%v res=%#v", err, res)
	}

	entries := forwards.list()
	if len(entries) != 1 {
		t.Fatalf("want 1 forward, got %d", len(entries))
	}
	fwd := entries[0]
	defer forwards.remove(fwd.ID)
	t.Logf("forward: id=%s local=%s remote=%s", fwd.ID, fwd.LocalAddr, fwd.RemoteAddr)

	// Round-trip a payload through the forward.
	conn, err := net.DialTimeout("tcp", fwd.LocalAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	payload := []byte("forward_port works")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	listRes, err := list(ctx, mcp.CallToolRequest{})
	if err != nil || listRes == nil || listRes.IsError {
		t.Fatalf("list_forwards: err=%v res=%#v", err, listRes)
	}
	if !strings.Contains(toolResultText(listRes), fwd.ID) {
		t.Fatalf("list_forwards missing %s: %s", fwd.ID, toolResultText(listRes))
	}

	stopReq := mcp.CallToolRequest{}
	stopReq.Params.Arguments = map[string]any{"forward_id": fwd.ID}
	stopRes, err := stop(ctx, stopReq)
	if err != nil || stopRes == nil || stopRes.IsError {
		t.Fatalf("stop_forward: err=%v res=%#v", err, stopRes)
	}
	if len(forwards.list()) != 0 {
		t.Fatalf("forward not cleaned up after stop_forward")
	}
}

func TestForwardPortMissingNode(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "empty.json"))
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	open := forwardPortHandler(reg, pool)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"node": "ghost", "remote_addr": "127.0.0.1:1"}
	res, err := open(context.Background(), req)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError for missing node, got %#v", res)
	}
}
