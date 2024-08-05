package mocks

import (
	"context"

	netvuln_v1 "github.com/TiZir/gRPC_nmap/pkg/gen"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

type MockService struct {
	mock.Mock
}

func (m *MockService) CheckVuln(ctx context.Context, req *netvuln_v1.CheckVulnRequest, opts ...grpc.CallOption) (*netvuln_v1.CheckVulnResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*netvuln_v1.CheckVulnResponse), args.Error(1)
}

func (m *MockService) GetData() *netvuln_v1.CheckVulnResponse {
	return &netvuln_v1.CheckVulnResponse{
		Results: []*netvuln_v1.TargetResult{
			{
				Target: "192.168.1.1",
				Services: []*netvuln_v1.Service{
					{
						Name:    "http",
						Version: "Apache 2.4.41",
						TcpPort: 80,
						Vulns: []*netvuln_v1.Vulnerability{
							{
								Identifier: "CVE-2020-1234",
								CvssScore:  7.5,
							},
							{
								Identifier: "CVE-2021-5678",
								CvssScore:  5.4,
							},
						},
					},
					{
						Name:    "ssh",
						Version: "OpenSSH 7.9p1",
						TcpPort: 22,
						Vulns: []*netvuln_v1.Vulnerability{
							{
								Identifier: "CVE-2018-15473",
								CvssScore:  6.5,
							},
						},
					},
				},
			},
			{
				Target: "192.168.1.2",
				Services: []*netvuln_v1.Service{
					{
						Name:    "http",
						Version: "Nginx 1.18.0",
						TcpPort: 80,
						Vulns: []*netvuln_v1.Vulnerability{
							{
								Identifier: "CVE-2019-20372",
								CvssScore:  4.3,
							},
						},
					},
				},
			},
		},
	}
}
