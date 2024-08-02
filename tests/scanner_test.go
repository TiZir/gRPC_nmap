package tests

import (
	"context"
	"testing"

	"github.com/TiZir/gRPC_nmap/internal/service/scanner"
	"github.com/Ullaakut/nmap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_Scan(t *testing.T) {
	s := scanner.New("vulners")
	ctx := context.Background()
	targets := []string{"scanme.nmap.org"}
	ports := []int32{22, 80}

	hosts, err := s.Scan(ctx, targets, ports)
	require.NoError(t, err)
	require.NotEmpty(t, hosts)
}

func TestScanner_GetVulnerabilityData(t *testing.T) {
	s := scanner.New("vulners")
	table := &nmap.Table{
		Elements: []nmap.Element{
			{Key: "id", Value: "CVE-2021-1234"},
			{Key: "cvss", Value: "7.5"},
		},
	}

	id, cvssScore, err := s.GetVulnerabilityData(table)
	assert.NoError(t, err)
	assert.Equal(t, "CVE-2021-1234", id)
	assert.Equal(t, float32(7.5), cvssScore)
}

func TestScanner_GetVulnerabilityData_Error(t *testing.T) {
	tests := []struct {
		name     string
		table    *nmap.Table
		wantID   string
		wantCVSS float32
		wantErr  bool
	}{
		{
			name: "Invalid CVSS Data",
			table: &nmap.Table{
				Elements: []nmap.Element{
					{Key: "id", Value: "CVE-2021-1234"},
					{Key: "cvss", Value: "invalid"},
				},
			},
			wantID:   "",
			wantCVSS: 0,
			wantErr:  true,
		},
		{
			name: "Nill CVSS Data",
			table: &nmap.Table{
				Elements: []nmap.Element{
					{Key: "id", Value: "CVE-2021-1234"},
					{Key: "cvss", Value: ""},
				},
			},
			wantID:   "",
			wantCVSS: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := scanner.New("vulners")
			id, cvssScore, err := s.GetVulnerabilityData(tt.table)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVulnerabilityData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Error(t, err)
			require.Equal(t, tt.wantID, id)
			require.Equal(t, tt.wantCVSS, cvssScore)
		})
	}
}
