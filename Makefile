all: generate

build:
	go build -o app cmd/nmap/main.go --config=./config/local_cfg.yaml

run:
	go run cmd/nmap/main.go --config=./config/local_cfg.yaml
	
generate:
	protoc -I proto proto/netvuln.proto --go_out=proto/gen --go_opt=paths=source_relative --go-grpc_out=proto/gen --go-grpc_opt=paths=source_relative