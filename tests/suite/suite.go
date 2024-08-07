package suite

import (
	"context"
	"net"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/TiZir/gRPC_nmap/internal/config"
	netvuln_v1 "github.com/TiZir/gRPC_nmap/pkg/gen"
)

const (
	grpcHost = "localhost"
)

type Suite struct {
	*testing.T
	Cfg     *config.Config
	Service netvuln_v1.NetVulnServiceClient
}

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()
	cfg := config.MustLoadByPath("../config/local_cfg.yaml")
	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
	})

	cc, err := grpc.NewClient(
		grpcAddress(cfg),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create gRPC client: %v", err)
	}

	return ctx, &Suite{
		T:       t,
		Cfg:     cfg,
		Service: netvuln_v1.NewNetVulnServiceClient(cc),
	}
}

func grpcAddress(cfg *config.Config) string {
	return net.JoinHostPort(grpcHost, strconv.Itoa(cfg.GRPC.Port))
}
