package main

import (
	"context"
	"net"
	"testing"

	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestHyperVOnlyAgentRejectsEveryNonVMMethod(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(hyperVUnaryInterceptor),
		grpc.StreamInterceptor(hyperVStreamInterceptor))
	pb.RegisterNodeAgentServer(server, &hyperVAgent{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := pb.NewNodeAgentClient(connection)
	info, err := client.GetInfo(context.Background(), &pb.GetInfoRequest{})
	if err != nil || len(info.GetCapabilities()) != 1 {
		t.Fatalf("restricted health probe failed: %+v %v", info, err)
	}
	for _, method := range pb.NodeAgent_ServiceDesc.Methods {
		full := "/" + pb.NodeAgent_ServiceDesc.ServiceName + "/" + method.MethodName
		if hyperVMethodAllowed(full) {
			continue
		}
		err := connection.Invoke(context.Background(), full, &pb.GetInfoRequest{}, &pb.GetInfoResponse{})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s returned %v, want PermissionDenied", full, err)
		}
	}
	for _, method := range pb.NodeAgent_ServiceDesc.Streams {
		full := "/" + pb.NodeAgent_ServiceDesc.ServiceName + "/" + method.StreamName
		if hyperVMethodAllowed(full) {
			continue
		}
		stream, err := connection.NewStream(context.Background(), &method, full)
		if err == nil {
			err = stream.SendMsg(&pb.GetInfoRequest{})
		}
		if err == nil {
			_ = stream.CloseSend()
			err = stream.RecvMsg(&pb.GetInfoResponse{})
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s returned %v, want PermissionDenied", full, err)
		}
	}
}
