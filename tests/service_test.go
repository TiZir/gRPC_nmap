package tests

import (
	"testing"

	netvuln_v1 "github.com/TiZir/gRPC_nmap/pkg/gen"
	"github.com/TiZir/gRPC_nmap/tests/mocks"
	"github.com/TiZir/gRPC_nmap/tests/suite"
	"github.com/stretchr/testify/require"
)

func TestCheckVuln_AdditionalCases(t *testing.T) {
	ctx, st := suite.New(t)

	mockService := new(mocks.MockService)
	st.Service = mockService

	tests := []struct {
		name        string
		req         *netvuln_v1.CheckVulnRequest
		mockResp    *netvuln_v1.CheckVulnResponse
		mockErr     error
		expectedErr string
	}{
		{
			name: "Single Target",
			req: &netvuln_v1.CheckVulnRequest{
				Targets: []string{"scanme.nmap.org"},
				TcpPort: []int32{22, 80},
			},
			mockResp: mockService.GetData(),
			mockErr:  nil,
		},
		{
			name: "Multiple Targets",
			req: &netvuln_v1.CheckVulnRequest{
				Targets: []string{"scanme.nmap.org", "google.com"},
				TcpPort: []int32{22, 80},
			},
			mockResp: mockService.GetData(),
			mockErr:  nil,
		},
		{
			name: "Single Port",
			req: &netvuln_v1.CheckVulnRequest{
				Targets: []string{"scanme.nmap.org"},
				TcpPort: []int32{22},
			},
			mockResp: mockService.GetData(),
			mockErr:  nil,
		},
		{
			name: "Multiple Ports",
			req: &netvuln_v1.CheckVulnRequest{
				Targets: []string{"scanme.nmap.org"},
				TcpPort: []int32{22, 80, 443},
			},
			mockResp: mockService.GetData(),
			mockErr:  nil,
		},
		{
			name: "Valid Port Range",
			req: &netvuln_v1.CheckVulnRequest{
				Targets: []string{"scanme.nmap.org"},
				TcpPort: []int32{1, 65535},
			},
			mockResp: mockService.GetData(),
			mockErr:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Устанавливаем ожидания мока
			mockService.On("CheckVuln", ctx, tt.req).Return(tt.mockResp, tt.mockErr)

			req, err := st.Service.CheckVuln(ctx, tt.req)
			require.NoError(t, err)
			require.NotEmpty(t, req)

			// Проверяем, что метод был вызван с ожидаемыми аргументами
			mockService.AssertCalled(t, "CheckVuln", ctx, tt.req)
		})
	}
}

func TestCheckVuln_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		req         *netvuln_v1.CheckVulnRequest
		expectedErr string
	}{
		{
			name: "Empty Targets",
			req: &netvuln_v1.CheckVulnRequest{
				Targets: nil,
				TcpPort: []int32{22, 80},
			},
			expectedErr: "targets are required",
		},
		{
			name: "Empty Ports",
			req: &netvuln_v1.CheckVulnRequest{
				Targets: []string{"scanme.nmap.org"},
				TcpPort: nil,
			},
			expectedErr: "tcp port are required",
		},
		{
			name: "Invalid Port",
			req: &netvuln_v1.CheckVulnRequest{
				Targets: []string{"scanme.nmap.org"},
				TcpPort: []int32{65536},
			},
			expectedErr: "check the host or port data",
		},
		{
			name:        "Nil Request",
			req:         nil,
			expectedErr: "targets are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.Service.CheckVuln(ctx, tt.req)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}
