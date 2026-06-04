package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
)

var probeVersion = "0.3.0"

func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("lablink-probe v%s\n", probeVersion)
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: probe <host:port> [token]\n")
		os.Exit(1)
	}
	address := os.Args[1]
	tokenArg := ""
	if len(os.Args) > 2 {
		tokenArg = os.Args[2]
	}

	token, _, err := security.ResolveToken(
		tokenArg,
		"",
		[]string{"LABLINK_AGENT_TOKEN", "DEVICE_AGENT_TOKEN"},
		[]string{"LABLINK_AGENT_TOKEN_FILE"},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token config: %v\n", err)
		os.Exit(1)
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "token config: set a token argument, LABLINK_AGENT_TOKEN, or LABLINK_AGENT_TOKEN_FILE")
		os.Exit(1)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	transportCreds, err := security.NewClientCredentials(transportCfg, security.ResolveServerName(address, "", transportCfg.ServerName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "transport credentials: %v\n", err)
		os.Exit(1)
	}

	opts := []grpc.DialOption{grpc.WithTransportCredentials(transportCreds)}
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

	// Test GetInfo
	fmt.Println("--- GetInfo ---")
	info, err := client.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetInfo: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Hostname: %s\nOS: %s/%s\nCPUs: %d\nMemory: %d MB\nAgent: %s\n",
		info.Hostname, info.Os, info.Arch, info.CpuCount,
		info.MemoryBytes/(1024*1024), info.AgentVersion)

	// Test Execute
	fmt.Println("\n--- Execute: hostname ---")
	stream, err := client.Execute(ctx, &pb.ExecuteRequest{Command: "hostname"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Execute: %v\n", err)
		os.Exit(1)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		if len(resp.Data) > 0 {
			fmt.Print(string(resp.Data))
		}
		if resp.Done {
			fmt.Printf("(exit code: %d)\n", resp.ExitCode)
			break
		}
	}

	fmt.Println("\nProbe OK")
}
