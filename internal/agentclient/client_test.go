package agentclient

import "testing"

func TestEndpointValidateStrict(t *testing.T) {
	tests := []struct {
		name     string
		endpoint Endpoint
		wantErr  bool
	}{
		{name: "valid", endpoint: Endpoint{Address: "10.0.0.1:9091", TLSServerName: "node"}},
		{name: "missing address", endpoint: Endpoint{TLSServerName: "node"}, wantErr: true},
		{name: "missing identity", endpoint: Endpoint{Address: "10.0.0.1:9091"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.endpoint.ValidateStrict(); (err != nil) != test.wantErr {
				t.Fatalf("ValidateStrict() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
