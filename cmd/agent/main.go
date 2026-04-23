package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"github.com/shirou/gopsutil/v4/mem"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

var agentVersion = "0.1.0"

var (
	listenAddr        = flag.String("listen", ":9091", "gRPC listen address")
	authToken         = flag.String("auth-token", "", "pre-shared key for authentication")
	authTokenFile     = flag.String("auth-token-file", "", "path to a file containing the shared auth token")
	transportMode     = flag.String("transport", "", "transport mode: mtls or insecure")
	allowInsecure     = flag.Bool("allow-insecure", false, "explicitly allow the legacy plaintext gRPC transport until mTLS is configured")
	tlsCAPath         = flag.String("tls-ca", "", "path to the CA certificate bundle for mTLS")
	tlsCertPath       = flag.String("tls-cert", "", "path to the TLS certificate chain for mTLS")
	tlsKeyPath        = flag.String("tls-key", "", "path to the TLS private key for mTLS")
	tlsServerName     = flag.String("tls-server-name", "", "server certificate identity used for CSR generation")
	generateServerCSR = flag.Bool("generate-server-csr", false, "generate a server private key and CSR for mTLS and exit")
	csrOut            = flag.String("csr-out", "", "path to write the generated server CSR")
	keyOut            = flag.String("key-out", "", "path to write the generated server private key")
	install           = flag.Bool("install", false, "install as Windows service")
	uninstall         = flag.Bool("uninstall", false, "uninstall Windows service")
	setToken          = flag.String("set-token", "", "write auth token to registry and exit")
)

func main() {
	flag.Parse()

	// Service management commands (run and exit).
	if *setToken != "" {
		if err := writeTokenToRegistry(*setToken); err != nil {
			log.Fatalf("failed to write token to registry: %v", err)
		}
		log.Printf("Auth token written to registry")
		return
	}
	if *generateServerCSR {
		if err := generateServerCSRAction(); err != nil {
			log.Fatalf("generate CSR failed: %v", err)
		}
		return
	}
	if *install {
		port := 9091
		// Parse port from listen address if provided.
		if _, p, err := net.SplitHostPort(*listenAddr); err == nil {
			if n, err := net.LookupPort("tcp", p); err == nil {
				port = n
			}
		}

		cfg, err := resolveServerTransportConfig()
		if err != nil {
			log.Fatalf("install failed: %v", err)
		}
		tokenFile := resolveTokenFilePath()
		if tokenFile == "" && readTokenFromRegistry() == "" {
			log.Fatalf("install failed: provide --auth-token-file (or LABLINK_AGENT_TOKEN_FILE) or pre-load a registry token with --set-token")
		}
		if err := installService("", port, cfg, tokenFile); err != nil {
			log.Fatalf("install failed: %v", err)
		}
		return
	}
	if *uninstall {
		if err := uninstallService(); err != nil {
			log.Fatalf("uninstall failed: %v", err)
		}
		return
	}

	// If running as a Windows service, hand off to the service handler.
	if isWindowsService() {
		if err := runAsService(); err != nil {
			log.Fatalf("service failed: %v", err)
		}
		return
	}

	// Normal foreground mode.
	if err := runServer(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

// resolveToken returns the auth token from flags, env vars, token files, or
// registry (in that order).
func resolveToken() (string, string, error) {
	token, source, err := security.ResolveToken(
		*authToken,
		*authTokenFile,
		[]string{"LABLINK_AGENT_TOKEN", "DEVICE_AGENT_TOKEN"},
		[]string{"LABLINK_AGENT_TOKEN_FILE"},
	)
	if err != nil {
		return "", "", err
	}
	if token != "" {
		return token, source, nil
	}
	if token = readTokenFromRegistry(); token != "" {
		return token, "registry", nil
	}
	return "", "none", nil
}

func resolveTokenFilePath() string {
	return firstNonEmpty(*authTokenFile, os.Getenv("LABLINK_AGENT_TOKEN_FILE"))
}

func resolveServerTransportConfig() (security.ServerTransportConfig, error) {
	allowPlaintext, err := security.AllowInsecure(*allowInsecure)
	if err != nil {
		return security.ServerTransportConfig{}, err
	}

	return security.ResolveServerTransport(
		firstNonEmpty(*transportMode, os.Getenv("LABLINK_TRANSPORT")),
		allowPlaintext,
		firstNonEmpty(*tlsCAPath, os.Getenv("LABLINK_TLS_CA"), os.Getenv("LABLINK_TLS_CA_CERT")),
		firstNonEmpty(*tlsCertPath, os.Getenv("LABLINK_TLS_CERT"), os.Getenv("LABLINK_TLS_SERVER_CERT")),
		firstNonEmpty(*tlsKeyPath, os.Getenv("LABLINK_TLS_KEY"), os.Getenv("LABLINK_TLS_SERVER_KEY")),
	)
}

func resolveTLSServerName() string {
	return firstNonEmpty(*tlsServerName, os.Getenv("LABLINK_TLS_SERVER_NAME"))
}

func firstNonEmpty(values ...string) string {
	return security.FirstNonEmpty(values...)
}

// runServer starts the gRPC server. Used by both foreground and service modes.
func runServer() error {
	transportCfg, err := resolveServerTransportConfig()
	if err != nil {
		return err
	}

	token, tokenSource, err := resolveToken()
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("shared auth token is required; set --auth-token, --auth-token-file, LABLINK_AGENT_TOKEN, LABLINK_AGENT_TOKEN_FILE, or a legacy registry token")
	}

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return err
	}

	var opts []grpc.ServerOption
	opts = append(opts,
		grpc.MaxRecvMsgSize(16*1024*1024), // 16MB max message
		grpc.MaxSendMsgSize(16*1024*1024),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second, // ping client every 30s
			Timeout: 15 * time.Second, // wait 15s for ping ack
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second, // allow client pings as often as 10s
			PermitWithoutStream: true,
		}),
	)
	if transportCfg.Mode == security.TransportModeMTLS {
		transportCreds, err := security.NewServerCredentials(transportCfg)
		if err != nil {
			return err
		}
		opts = append(opts, grpc.Creds(transportCreds))
	} else {
		log.Printf("WARNING: %v", security.InsecureTransportOptInError(true))
	}
	opts = append(opts,
		grpc.UnaryInterceptor(security.UnaryServerInterceptor(token)),
		grpc.StreamInterceptor(security.StreamServerInterceptor(token)),
	)
	log.Printf("authentication enabled (source: %s)", tokenSource)

	srv := grpc.NewServer(opts...)
	pb.RegisterNodeAgentServer(srv, &agentServer{})

	hostname, _ := os.Hostname()
	log.Printf("LabLink agent transport: %s", transportCfg.Mode)
	log.Printf("LabLink agent %s starting on %s (host=%s, os=%s/%s, cpus=%d)",
		agentVersion, *listenAddr, hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	return srv.Serve(lis)
}

// tokenSource returns a human-readable description of where the token came from.
func tokenSource() string {
	if *authToken != "" {
		return "command-line flag"
	}
	if *authTokenFile != "" {
		return "token file flag"
	}
	if os.Getenv("LABLINK_AGENT_TOKEN") != "" {
		return "LABLINK_AGENT_TOKEN env var"
	}
	if os.Getenv("DEVICE_AGENT_TOKEN") != "" {
		return "DEVICE_AGENT_TOKEN env var"
	}
	if os.Getenv("LABLINK_AGENT_TOKEN_FILE") != "" {
		return "LABLINK_AGENT_TOKEN_FILE env var"
	}
	if readTokenFromRegistry() != "" {
		return "registry"
	}
	return "none"
}

type agentServer struct {
	pb.UnimplementedNodeAgentServer
}

func (s *agentServer) GetInfo(_ context.Context, _ *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	hostname, _ := os.Hostname()
	var memTotal int64
	if v, err := mem.VirtualMemory(); err == nil {
		memTotal = int64(v.Total)
	}
	return &pb.GetInfoResponse{
		Hostname:     hostname,
		Os:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		CpuCount:     int32(runtime.NumCPU()),
		MemoryBytes:  memTotal,
		AgentVersion: agentVersion,
	}, nil
}

func (s *agentServer) Execute(req *pb.ExecuteRequest, stream pb.NodeAgent_ExecuteServer) error {
	return executeCommand(stream.Context(), req.Command, req.Shell, req.WorkingDir, req.Env, req.TimeoutSeconds, req.Detach, stream)
}

func (s *agentServer) ExecuteScript(req *pb.ExecuteScriptRequest, stream pb.NodeAgent_ExecuteScriptServer) error {
	return executeScript(stream.Context(), req.ScriptBody, req.Shell, req.WorkingDir, req.Env, req.TimeoutSeconds, req.Args, stream)
}

func (s *agentServer) PushFile(stream pb.NodeAgent_PushFileServer) error {
	return handlePushFile(stream)
}

func (s *agentServer) PullFile(req *pb.PullFileRequest, stream pb.NodeAgent_PullFileServer) error {
	return handlePullFile(req.RemotePath, stream)
}

func (s *agentServer) ListProcesses(ctx context.Context, req *pb.ListProcessesRequest) (*pb.ListProcessesResponse, error) {
	return listProcesses(ctx, req.NameFilter)
}

func (s *agentServer) KillProcess(ctx context.Context, req *pb.KillProcessRequest) (*pb.KillProcessResponse, error) {
	return killProcess(ctx, req.Pid, req.Force)
}
