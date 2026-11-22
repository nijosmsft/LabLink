package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/mcptools"
	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func hyperVMethodAllowed(method string) bool {
	return method == pb.NodeAgent_GetInfo_FullMethodName ||
		method == pb.NodeAgent_ManageVM_FullMethodName
}

func hyperVUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !hyperVMethodAllowed(info.FullMethod) {
		return nil, status.Error(codes.PermissionDenied, "operation unavailable in Hyper-V-only mode")
	}
	return handler(ctx, req)
}

func hyperVStreamInterceptor(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if !hyperVMethodAllowed(info.FullMethod) {
		return status.Error(codes.PermissionDenied, "operation unavailable in Hyper-V-only mode")
	}
	return handler(srv, stream)
}

type hyperVAgent struct {
	pb.UnimplementedNodeAgentServer
	host *mcptools.LocalVMHost
}

func (s *hyperVAgent) GetInfo(ctx context.Context, req *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	info, err := (&agentServer{}).GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	info.Capabilities = []string{mcptools.LocalHyperVCapability}
	return info, nil
}

func (s *hyperVAgent) ManageVM(req *pb.ManageVMRequest, stream pb.NodeAgent_ManageVMServer) error {
	type outcome struct {
		result []byte
		nodes  []byte
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, nodes, err := s.host.Call(stream.Context(), req)
		if err != nil {
			done <- outcome{err: err}
			return
		}
		data, err := json.Marshal(result)
		if err != nil {
			done <- outcome{err: err}
			return
		}
		encodedNodes, err := json.Marshal(nodes)
		done <- outcome{result: data, nodes: encodedNodes, err: err}
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return status.FromContextError(stream.Context().Err()).Err()
		case <-ticker.C:
			if err := stream.Send(&pb.ManageVMResponse{Progress: "VM operation is running"}); err != nil {
				return err
			}
		case result := <-done:
			if result.err != nil {
				return status.Error(codes.FailedPrecondition, result.err.Error())
			}
			return stream.Send(&pb.ManageVMResponse{ResultJson: result.result, NodesJson: result.nodes})
		}
	}
}

func openHyperVAgent(token string, transport security.ServerTransportConfig) (*hyperVAgent, error) {
	host, _, err := net.SplitHostPort(*listenAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, fmt.Errorf("Hyper-V-only agent must listen on a numeric loopback address")
	}
	if transport.Mode != security.TransportModeMTLS {
		return nil, fmt.Errorf("Hyper-V-only agent requires mTLS")
	}
	if err := enableHyperVServicePrivileges(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(*hyperVPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load restricted Hyper-V policy: %w", err)
	}
	policy, err := mcptools.DecodeLocalVMPolicy(data)
	if err != nil {
		return nil, err
	}
	if err := os.Setenv("LABLINK_HYPERV_RESTRICTED", "1"); err != nil {
		return nil, err
	}
	for key, value := range map[string]string{
		"LABLINK_HYPERV_STATE_DIR": policy.StateDir,
		"TEMP":                     filepath.Join(policy.StateDir, "Temp"),
		"TMP":                      filepath.Join(policy.StateDir, "Temp"),
	} {
		if err := os.Setenv(key, value); err != nil {
			return nil, err
		}
	}
	clientTransport, err := security.ResolveClientTransport(
		"mtls", false, transport.CACertPath,
		firstNonEmpty(os.Getenv("LABLINK_HYPERV_CLIENT_CERT"), strings.TrimSuffix(transport.CertPath, "server.crt")+"client.crt"),
		firstNonEmpty(os.Getenv("LABLINK_HYPERV_CLIENT_KEY"), strings.TrimSuffix(transport.KeyPath, "server.key")+"client.key"),
		"",
	)
	if err != nil {
		return nil, err
	}
	vmHost, err := mcptools.NewLocalVMHost(policy, token, agentVersion, clientTransport)
	if err != nil {
		return nil, err
	}
	return &hyperVAgent{host: vmHost}, nil
}
