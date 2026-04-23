package security

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const tokenHeader = "x-auth-token"

// UnaryServerInterceptor validates the PSK token on unary RPCs.
func UnaryServerInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := validateToken(ctx, token); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor validates the PSK token on streaming RPCs.
func StreamServerInterceptor(token string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := validateToken(ss.Context(), token); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func validateToken(ctx context.Context, expected string) error {
	if expected == "" {
		return status.Error(codes.Internal, "auth token not configured")
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get(tokenHeader)
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "missing auth token")
	}
	if values[0] != expected {
		return status.Error(codes.Unauthenticated, "invalid auth token")
	}
	return nil
}

// TokenCredentials implements grpc.PerRPCCredentials for the client side.
type TokenCredentials struct {
	Token      string
	RequireTLS bool
}

func (t TokenCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if t.Token == "" {
		return nil, fmt.Errorf("auth token not configured")
	}
	return map[string]string{tokenHeader: t.Token}, nil
}

func (t TokenCredentials) RequireTransportSecurity() bool {
	return t.RequireTLS
}
