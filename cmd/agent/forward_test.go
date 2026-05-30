package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// startEcho stands up a tiny TCP echo listener and returns its address.
// The listener stops when the test exits.
func startEcho(t *testing.T) string {
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

// startAgentForTest spins up an in-memory gRPC server with only the Forward
// RPC wired and returns a client.
func startAgentForTest(t *testing.T) pb.NodeAgentClient {
	t.Helper()

	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	pb.RegisterNodeAgentServer(srv, &agentServer{})

	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() { srv.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufnet: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pb.NewNodeAgentClient(conn)
}

func TestForwardRoundTrip(t *testing.T) {
	echo := startEcho(t)
	cli := startAgentForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := cli.Forward(ctx)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}

	if err := stream.Send(&pb.ForwardChunk{TargetAddr: echo}); err != nil {
		t.Fatalf("send first: %v", err)
	}

	payload := []byte("hello, forward")
	if err := stream.Send(&pb.ForwardChunk{Data: payload}); err != nil {
		t.Fatalf("send data: %v", err)
	}

	// Read until we accumulate len(payload) bytes from the echo.
	var got []byte
	for len(got) < len(payload) {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		got = append(got, msg.Data...)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	if err := stream.Send(&pb.ForwardChunk{Close: true}); err != nil {
		t.Fatalf("send close: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}

	// Drain remaining messages (echo half-close should arrive).
	for {
		_, err := stream.Recv()
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		// Other errors (e.g. canceled) are acceptable here.
		break
	}
}

func TestForwardBadFirstChunk(t *testing.T) {
	cli := startAgentForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := cli.Forward(ctx)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if err := stream.Send(&pb.ForwardChunk{Data: []byte("nope")}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = stream.CloseSend()

	if _, err := stream.Recv(); err == nil {
		t.Fatalf("expected error for missing target_addr, got nil")
	}
}

func TestForwardDialFailure(t *testing.T) {
	cli := startAgentForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := cli.Forward(ctx)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	// Port 1 is virtually guaranteed to be closed.
	if err := stream.Send(&pb.ForwardChunk{TargetAddr: "127.0.0.1:1"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = stream.CloseSend()

	if _, err := stream.Recv(); err == nil {
		t.Fatalf("expected dial-failure error, got nil")
	}
}

// TestForwardLargePayload streams ~1 MiB through and verifies it echoes back
// byte-for-byte to ensure the chunking is correct.
func TestForwardLargePayload(t *testing.T) {
	echo := startEcho(t)
	cli := startAgentForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := cli.Forward(ctx)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if err := stream.Send(&pb.ForwardChunk{TargetAddr: echo}); err != nil {
		t.Fatalf("send first: %v", err)
	}

	const total = 1 << 20
	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var sendErr error
	go func() {
		defer wg.Done()
		const chunk = 32 * 1024
		for off := 0; off < total; off += chunk {
			end := off + chunk
			if end > total {
				end = total
			}
			if err := stream.Send(&pb.ForwardChunk{Data: payload[off:end]}); err != nil {
				sendErr = err
				return
			}
		}
		_ = stream.Send(&pb.ForwardChunk{Close: true})
	}()

	got := make([]byte, 0, total)
	for len(got) < total {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv after %d bytes: %v", len(got), err)
		}
		got = append(got, msg.Data...)
	}
	wg.Wait()
	if sendErr != nil {
		t.Fatalf("send: %v", sendErr)
	}
	for i := 0; i < total; i++ {
		if got[i] != payload[i] {
			t.Fatalf("mismatch at %d: got %d want %d", i, got[i], payload[i])
		}
	}
	_ = stream.CloseSend()
}

func init() {
	// Silence noisy gRPC logs in test output by overriding the writer if needed.
	_ = fmt.Sprintf("") // keep fmt import for future debugging
}
