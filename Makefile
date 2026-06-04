.PHONY: build proto clean build-server build-agent-windows build-agent-linux build-ca build-probe

BIN_DIR := bin

build: build-server build-agent-windows build-ca build-probe

build-server:
	go build -o $(BIN_DIR)/LabLinkServer.exe ./cmd/lablink-server/

build-agent-windows:
	GOOS=windows GOARCH=amd64 go build -o $(BIN_DIR)/LabLinkAgent.exe ./cmd/lablink-agent/

build-agent-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/LabLinkAgent-linux-amd64 ./cmd/lablink-agent/

build-ca:
	go build -o $(BIN_DIR)/lablink-ca.exe ./cmd/lablink-ca/

build-probe:
	go build -o $(BIN_DIR)/LabLinkProbe.exe ./cmd/lablink-probe/

build-all: build-server build-agent-windows build-agent-linux build-ca build-probe

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/agent/agent.proto

clean:
	rm -rf $(BIN_DIR)

tidy:
	go mod tidy
