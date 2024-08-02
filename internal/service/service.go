package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	netvuln_v1 "github.com/TiZir/gRPC_nmap/proto/gen"
	"github.com/Ullaakut/nmap/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrScanner = errors.New("scanner cannot be created or started")
)

type Service struct {
	netvuln_v1.UnimplementedNetVulnServiceServer
	logger     *slog.Logger
	scanServer ScanServer
}

type ScanServer interface {
	Scan(ctx context.Context, targets []string, ports []int32) ([]nmap.Host, error)
	GetVulnerabilityData(in *nmap.Table) (string, float32, error)
}

func New(
	logger *slog.Logger,
	scanServer ScanServer,
) *Service {
	return &Service{
		logger:     logger,
		scanServer: scanServer,
	}
}

func Register(gRPC *grpc.Server, log *slog.Logger, scan ScanServer) {
	netvuln_v1.RegisterNetVulnServiceServer(gRPC, &Service{logger: log, scanServer: scan})
}

func (s *Service) CheckVuln(ctx context.Context, req *netvuln_v1.CheckVulnRequest) (*netvuln_v1.CheckVulnResponse, error) {
	s.logger.Info("starting CheckVuln")

	targets := req.GetTargets()
	if len(targets) == 0 {
		return nil, status.Error(codes.InvalidArgument, "targets are required")
	}
	ports := req.GetTcpPort()
	// for _, port := range ports {
	// 	if port < 1 || port > 65535 {
	// 		return nil, status.Error(codes.InvalidArgument, "tcp port are required")
	// 	}
	// }
	if len(ports) == 0 {
		return nil, status.Error(codes.InvalidArgument, "tcp port are required")
	}
	result, err := s.HandlerScan(ctx, targets, ports)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "check the host or port data")
	}
	s.logger.Info("CheckVuln completed")
	return &netvuln_v1.CheckVulnResponse{Results: result}, nil
}

func (s *Service) HandlerScan(ctx context.Context, targets []string, ports []int32) ([]*netvuln_v1.TargetResult, error) {
	s.logger.Info("starting HandlerScan")

	const op = "service.HandlerScan"
	log := s.logger.With(
		slog.String("op", op),
		slog.String("targets", fmt.Sprintf("%+v", targets)),
		slog.String("ports", fmt.Sprintf("%+v", ports)),
	)
	s.logger.Info("starting Scan")
	hosts, err := s.scanServer.Scan(ctx, targets, ports)
	if err != nil {
		log.Error(fmt.Sprintf("%s: %s", "scanner cannot be created or started: ", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, ErrScanner)
	}
	results := make([]*netvuln_v1.TargetResult, 0)
	s.logger.Info("vulnerability handling")
	for _, host := range hosts {
		s.logger.Info("Host %s\n", slog.String("host", host.Addresses[0].Addr))
		target := &netvuln_v1.TargetResult{
			Target:   host.Addresses[0].Addr,
			Services: make([]*netvuln_v1.Service, 0),
		}
		var service *netvuln_v1.Service
		for _, port := range host.Ports {
			s.logger.Info("Port %v\n", slog.Any("port", port))
			vulnerabilities := make([]*netvuln_v1.Vulnerability, 0)
			for _, script := range port.Scripts {
				for _, table := range script.Tables {
					for _, row := range table.Tables {
						id, cvssScore, err := s.scanServer.GetVulnerabilityData(&row)
						if err != nil {
							log.Warn(fmt.Sprintf("%s: %s", "cannot parse cvss: ", err.Error()))
							continue
						}
						vulnerability := &netvuln_v1.Vulnerability{
							Identifier: id,
							CvssScore:  cvssScore,
						}
						vulnerabilities = append(vulnerabilities, vulnerability)
					}
				}
			}
			service = &netvuln_v1.Service{
				Name:    port.Service.Name,
				Version: fmt.Sprintf("%s : %s", port.Service.Product, port.Service.Version),
				TcpPort: int32(port.ID),
				Vulns:   vulnerabilities,
			}
		}
		target.Services = append(target.Services, service)
		results = append(results, target)
	}
	s.logger.Info("HandlerScan completed")
	return results, nil
}
