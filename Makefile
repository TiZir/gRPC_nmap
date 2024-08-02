.PHONY: all build run go generate tests clean lint

all: build run

build:
	go build -o app ./cmd/nmap/main.go

run:
	./app --config=./config/local_cfg.yaml

go:
	go run cmd/nmap/main.go --config=./config/local_cfg.yaml

generate:
	protoc -I proto proto/netvuln.proto --go_out=proto/gen --go_opt=paths=source_relative --go-grpc_out=proto/gen --go-grpc_opt=paths=source_relative

tests:
	go test -v -timeout 60m ./tests

clean:
	rm -rf app

lint:
	golangci-lint run