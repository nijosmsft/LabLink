package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	forwardDialTimeout = 5 * time.Second
	forwardMaxAddrLen  = 256
)

// Forward implements pb.NodeAgentServer Forward: it accepts the first
// ForwardChunk to learn the target TCP address, dials it, and then byte-
// shuttles in both directions until either side half-closes.
func (s *agentServer) Forward(stream pb.NodeAgent_ForwardServer) error {
	return handleForward(stream)
}

func handleForward(stream pb.NodeAgent_ForwardServer) error {
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return status.Errorf(codes.InvalidArgument, "forward: receive first chunk: %v", err)
	}
	if first.TargetAddr == "" {
		return status.Error(codes.InvalidArgument, "forward: first chunk must set target_addr")
	}
	if len(first.TargetAddr) > forwardMaxAddrLen {
		return status.Error(codes.InvalidArgument, "forward: target_addr too long")
	}

	dialer := net.Dialer{Timeout: forwardDialTimeout}
	conn, err := dialer.DialContext(stream.Context(), "tcp", first.TargetAddr)
	if err != nil {
		return status.Errorf(codes.Unavailable, "forward: dial %s: %v", first.TargetAddr, err)
	}
	defer conn.Close()

	// If the very first message also carried payload bytes, write them.
	if len(first.Data) > 0 {
		if _, werr := conn.Write(first.Data); werr != nil {
			return status.Errorf(codes.Internal, "forward: initial write: %v", werr)
		}
	}
	if first.Close {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}

	return shuttle(stream, conn)
}

// shuttle bridges a server stream (operator side) and an already-connected
// TCP socket (target side) until both directions close or one side errors.
func shuttle(stream pb.NodeAgent_ForwardServer, conn net.Conn) error {
	const chunk = 64 * 1024

	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// stream -> tcp
	go func() {
		defer wg.Done()
		for {
			msg, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					if tcp, ok := conn.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					return
				}
				errCh <- err
				cancel()
				return
			}
			if len(msg.Data) > 0 {
				if _, werr := conn.Write(msg.Data); werr != nil {
					errCh <- werr
					cancel()
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

	// tcp -> stream
	go func() {
		defer wg.Done()
		buf := make([]byte, chunk)
		for {
			if ctx.Err() != nil {
				return
			}
			n, rerr := conn.Read(buf)
			if n > 0 {
				if serr := stream.Send(&pb.ForwardChunk{Data: append([]byte(nil), buf[:n]...)}); serr != nil {
					errCh <- serr
					cancel()
					return
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					_ = stream.Send(&pb.ForwardChunk{Close: true})
					return
				}
				errCh <- rerr
				cancel()
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)

	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return status.Errorf(codes.Internal, "forward: %v", fmt.Errorf("shuttle: %w", firstErr))
	}
	return nil
}
