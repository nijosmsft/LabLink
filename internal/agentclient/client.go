package agentclient

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/keepalive"
)

const dialTimeout = 5 * time.Second

// Pool manages cached gRPC connections to node agents.
type Pool struct {
	mu        sync.Mutex
	conns     map[string]*grpc.ClientConn
	token     string
	transport security.ClientTransportConfig
}

// NewPool creates a new connection pool with the given auth token.
func NewPool(token string, transport security.ClientTransportConfig) *Pool {
	return &Pool{
		conns:     make(map[string]*grpc.ClientConn),
		token:     token,
		transport: transport,
	}
}

// GetClient returns a NodeAgent client for the given address, reusing connections.
// Automatically reconnects if the cached connection is in a failed state.
func (p *Pool) GetClient(address string, serverNameOverride ...string) (pb.NodeAgentClient, error) {
	conn, err := p.getConn(address, serverNameOverride...)
	if err != nil {
		return nil, err
	}
	return pb.NewNodeAgentClient(conn), nil
}

// ResetConnection drops the cached connection for an address, forcing a fresh dial on next use.
func (p *Pool) ResetConnection(address string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix := address + "|"
	for cacheKey, conn := range p.conns {
		if strings.HasPrefix(cacheKey, prefix) {
			conn.Close()
			delete(p.conns, cacheKey)
		}
	}
}

func (p *Pool) getConn(address string, serverNameOverride ...string) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	serverName := ""
	if len(serverNameOverride) > 0 {
		serverName = serverNameOverride[0]
	}
	resolvedServerName := security.ResolveServerName(address, serverName, p.transport.ServerName)
	cacheKey := fmt.Sprintf("%s|%s", address, resolvedServerName)

	if conn, ok := p.conns[cacheKey]; ok {
		state := conn.GetState()
		if state == connectivity.Shutdown || state == connectivity.TransientFailure {
			conn.Close()
			delete(p.conns, cacheKey)
		} else {
			return conn, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(16*1024*1024), // 16MB max recv
			grpc.MaxCallSendMsgSize(16*1024*1024), // 16MB max send
		),
		// Keepalive: detect dead connections, but be tolerant during large transfers.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // ping every 30s if idle
			Timeout:             15 * time.Second, // wait 15s for ping ack
			PermitWithoutStream: true,
		}),
	}
	transportCreds, err := security.NewClientCredentials(p.transport, resolvedServerName)
	if err != nil {
		return nil, err
	}
	opts = append(opts, grpc.WithTransportCredentials(transportCreds))
	if p.token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(security.TokenCredentials{
			Token:      p.token,
			RequireTLS: p.transport.Mode == security.TransportModeMTLS,
		}))
	}

	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		return nil, err
	}

	p.conns[cacheKey] = conn
	return conn, nil
}

// Close closes all cached connections.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, conn := range p.conns {
		conn.Close()
		delete(p.conns, addr)
	}
}
