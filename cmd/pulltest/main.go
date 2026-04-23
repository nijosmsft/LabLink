package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: pulltest <host:port> <token> <remote_path> [local_path]\n")
		os.Exit(1)
	}
	address := os.Args[1]
	token := os.Args[2]
	remotePath := os.Args[3]
	localPath := "pulled_file"
	if len(os.Args) > 4 {
		localPath = os.Args[4]
	}

	allowInsecure, err := security.AllowInsecure(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "transport config: %v\n", err)
		os.Exit(1)
	}
	transportCfg, err := security.ResolveClientTransport(
		security.FirstPresentEnv("LABLINK_TRANSPORT"),
		allowInsecure,
		security.FirstPresentEnv("LABLINK_TLS_CA", "LABLINK_TLS_CA_CERT"),
		security.FirstPresentEnv("LABLINK_TLS_CERT", "LABLINK_TLS_CLIENT_CERT"),
		security.FirstPresentEnv("LABLINK_TLS_KEY", "LABLINK_TLS_CLIENT_KEY"),
		security.FirstPresentEnv("LABLINK_TLS_SERVER_NAME"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "transport config: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	transportCreds, err := security.NewClientCredentials(transportCfg, security.ResolveServerName(address, "", transportCfg.ServerName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "transport credentials: %v\n", err)
		os.Exit(1)
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(100 * 1024 * 1024)), // 100MB max message
	}
	if token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(security.TokenCredentials{
			Token:      token,
			RequireTLS: transportCfg.Mode == security.TransportModeMTLS,
		}))
	}

	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewNodeAgentClient(conn)

	fmt.Printf("Pulling %s from %s...\n", remotePath, address)
	start := time.Now()

	stream, err := client.PullFile(ctx, &pb.PullFileRequest{RemotePath: remotePath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pull: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create: %v\n", err)
		os.Exit(1)
	}

	var totalBytes int64
	var totalSize int64
	chunks := 0
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			fmt.Fprintf(os.Stderr, "\nrecv error after %d bytes, %d chunks: %v\n", totalBytes, chunks, err)
			os.Exit(1)
		}
		if resp.TotalSize > 0 {
			totalSize = resp.TotalSize
		}
		if len(resp.Chunk) > 0 {
			n, err := f.Write(resp.Chunk)
			if err != nil {
				f.Close()
				fmt.Fprintf(os.Stderr, "write: %v\n", err)
				os.Exit(1)
			}
			totalBytes += int64(n)
			chunks++
			if chunks%100 == 0 {
				pct := ""
				if totalSize > 0 {
					pct = fmt.Sprintf(" (%.1f%%)", float64(totalBytes)/float64(totalSize)*100)
				}
				fmt.Printf("\r  %d MB received, %d chunks%s", totalBytes/(1024*1024), chunks, pct)
			}
		}
	}
	f.Close()
	elapsed := time.Since(start)

	fmt.Printf("\nDone: %d bytes (%.1f MB) in %s, %d chunks\n", totalBytes, float64(totalBytes)/(1024*1024), elapsed.Round(time.Millisecond), chunks)
	fmt.Printf("Speed: %.1f MB/s\n", float64(totalBytes)/(1024*1024)/elapsed.Seconds())
}
