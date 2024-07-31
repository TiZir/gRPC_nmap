package scanner

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Ullaakut/nmap/v3"
)

type Scanner struct {
	scriptName string
}

func New(scriptName string) *Scanner {
	return &Scanner{
		scriptName: scriptName,
	}
}

func (s *Scanner) Scan(ctx context.Context, targets []string, ports []int32) ([]nmap.Host, error) {
	const op = "scanner.Scan"
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(targets...),
		nmap.WithPorts(convertPorts(ports)...),
		nmap.WithScripts(s.scriptName),
		nmap.WithServiceInfo(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithVersionAll(),
		nmap.WithFilterHost(func(h nmap.Host) bool {
			for idx := range h.Ports {
				if h.Ports[idx].Status() == "open" {
					return true
				}
			}
			return false
		}),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			return p.State.String() == "open"
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("(%s) %s: %w", op, "unable to create nmap scanner", err)
	}
	result, _, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("(%s) %s: %w", op, "unable to run nmap scan", err)

	}

	return result.Hosts, nil
}

func (s *Scanner) GetVulnerabilityData(in *nmap.Table) (string, float32, error) {
	const op = "scanner.GetVulnerabilityData"
	var id string
	var cvssScore float32
	for _, elem := range in.Elements {
		if elem.Key == "id" {
			id = elem.Value
		}
		if elem.Key == "cvss" {
			cvssScoreFloat64, err := strconv.ParseFloat(elem.Value, 32)
			if err != nil {
				return "", 0, fmt.Errorf("(%s) %s: %w", op, "not possible to convert data to floating", err)
			}
			cvssScore = float32(cvssScoreFloat64)
		}
	}
	return id, cvssScore, nil
}

func convertPorts(ports []int32) []string {
	portsStr := make([]string, len(ports))
	for i, port := range ports {
		portsStr[i] = strconv.Itoa(int(port))

	}
	return portsStr
}
