package checks

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const dialTimeout = 2 * time.Second

type NetworkCheck struct{}

func (n *NetworkCheck) Category() string { return "Network Isolation" }

func (n *NetworkCheck) Run() []Result {
	var results []Result

	results = append(results, checkMetadataService())
	results = append(results, checkDockerAPI())
	results = append(results, checkOutbound())
	results = append(results, checkDNS())
	results = append(results, checkGateway())

	return results
}

func checkMetadataService() Result {
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", dialTimeout)
	if err != nil {
		return Result{
			Name:     "metadata_service",
			Status:   Pass,
			Severity: Critical,
			Detail:   "Cloud metadata service (169.254.169.254) is not reachable",
		}
	}
	conn.Close()
	return Result{
		Name:     "metadata_service",
		Status:   Fail,
		Severity: Critical,
		Detail:   "Cloud metadata service (169.254.169.254) is reachable — credential theft possible",
	}
}

func checkDockerAPI() Result {
	gateway := detectGateway()
	if gateway == "" {
		return Result{
			Name:     "docker_api_network",
			Status:   Pass,
			Severity: High,
			Detail:   "No gateway detected — Docker API check skipped",
		}
	}

	for _, port := range []string{"2375", "2376"} {
		conn, err := net.DialTimeout("tcp", gateway+":"+port, dialTimeout)
		if err == nil {
			conn.Close()
			return Result{
				Name:     "docker_api_network",
				Status:   Fail,
				Severity: High,
				Detail:   fmt.Sprintf("Docker API accessible on gateway %s:%s — container escape possible", gateway, port),
			}
		}
	}
	return Result{
		Name:     "docker_api_network",
		Status:   Pass,
		Severity: High,
		Detail:   "Docker API not accessible on gateway",
	}
}

func checkOutbound() Result {
	targets := []string{"93.184.216.34:80", "1.1.1.1:443"}
	for _, target := range targets {
		conn, err := net.DialTimeout("tcp", target, dialTimeout)
		if err == nil {
			conn.Close()
			return Result{
				Name:     "outbound_internet",
				Status:   Fail,
				Severity: Medium,
				Detail:   fmt.Sprintf("Unrestricted outbound internet access (reached %s)", target),
			}
		}
	}
	return Result{
		Name:     "outbound_internet",
		Status:   Pass,
		Severity: Medium,
		Detail:   "Outbound internet access is restricted",
	}
}

func checkDNS() Result {
	addrs, err := net.LookupHost("example.com")
	if err != nil {
		return Result{
			Name:     "dns_resolution",
			Status:   Pass,
			Severity: Medium,
			Detail:   "External DNS resolution is blocked",
		}
	}
	return Result{
		Name:     "dns_resolution",
		Status:   Fail,
		Severity: Medium,
		Detail:   fmt.Sprintf("External DNS resolution works (example.com → %s)", strings.Join(addrs, ", ")),
	}
}

func checkGateway() Result {
	gateway := detectGateway()
	if gateway == "" {
		return Result{
			Name:     "gateway_reachable",
			Status:   Pass,
			Severity: Low,
			Detail:   "No default gateway detected",
		}
	}

	commonPorts := []string{"22", "80", "443", "5432", "6379", "8080", "9090"}
	var openPorts []string
	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", gateway+":"+port, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}

	if len(openPorts) > 0 {
		return Result{
			Name:     "gateway_reachable",
			Status:   Warn,
			Severity: Medium,
			Detail:   fmt.Sprintf("Gateway %s has open ports: %s", gateway, strings.Join(openPorts, ", ")),
			Data:     map[string]any{"gateway": gateway, "open_ports": openPorts},
		}
	}
	return Result{
		Name:     "gateway_reachable",
		Status:   Pass,
		Severity: Low,
		Detail:   fmt.Sprintf("Gateway %s has no common ports open", gateway),
	}
}

func detectGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			hexGW := fields[2]
			return hexToIP(hexGW)
		}
	}
	return ""
}

func hexToIP(hex string) string {
	if len(hex) != 8 {
		return ""
	}
	var octets [4]byte
	for i := 0; i < 4; i++ {
		val := hexVal(hex[i*2])*16 + hexVal(hex[i*2+1])
		octets[i] = byte(val)
	}
	return fmt.Sprintf("%d.%d.%d.%d", octets[3], octets[2], octets[1], octets[0])
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}
