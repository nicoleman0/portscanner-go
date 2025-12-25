package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"portscanner-go/internal/output"
	"portscanner-go/internal/ports"
	"portscanner-go/internal/scanner"
)

// scanner, output, and top ports moved to internal packages

func parsePorts(spec string) ([]int, error) {
	if spec == "" || strings.HasPrefix(spec, "top:") {
		n := 100
		if strings.HasPrefix(spec, "top:") {
			val := strings.TrimPrefix(spec, "top:")
			if val != "" {
				parsed, err := strconv.Atoi(val)
				if err != nil || parsed <= 0 {
					return nil, fmt.Errorf("invalid top count: %s", val)
				}
				n = parsed
			}
		}
		return ports.Top(n), nil
	}

	set := map[int]struct{}{}
	parts := strings.Split(spec, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			r := strings.SplitN(p, "-", 2)
			if len(r) != 2 {
				return nil, fmt.Errorf("invalid range: %s", p)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(r[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(r[1]))
			if err1 != nil || err2 != nil || start <= 0 || end <= 0 || end < start {
				return nil, fmt.Errorf("invalid range: %s", p)
			}
			for i := start; i <= end; i++ {
				if i <= 65535 {
					set[i] = struct{}{}
				}
			}
			continue
		}
		val, err := strconv.Atoi(p)
		if err != nil || val <= 0 || val > 65535 {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		set[val] = struct{}{}
	}
	res := make([]int, 0, len(set))
	for k := range set {
		res = append(res, k)
	}
	sort.Ints(res)
	return res, nil
}

func expandHosts(input string) ([]string, error) {
	if input == "" {
		return nil, errors.New("hosts required")
	}
	hosts := []string{}
	items := strings.Split(input, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			// CIDR expansion (IPv4)
			_, ipnet, err := net.ParseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s", item)
			}
			ip := ipnet.IP.To4()
			if ip == nil {
				return nil, fmt.Errorf("only IPv4 CIDR supported: %s", item)
			}
			mask := ipnet.Mask
			start := make(net.IP, len(ip))
			copy(start, ip)
			end := make(net.IP, len(ip))
			for i := 0; i < 4; i++ {
				end[i] = ip[i] | ^mask[i]
			}
			for cur := ipToUint32(start); cur <= ipToUint32(end); cur++ {
				hosts = append(hosts, uint32ToIP(cur).String())
			}
			continue
		}
		hosts = append(hosts, item)
	}
	if len(hosts) == 0 {
		return nil, errors.New("no valid hosts provided")
	}
	return hosts, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func main() {
	var hostsSpec string
	var portsSpec string
	var timeoutStr string
	var workers int
	var jsonOut bool
	var includeClosed bool
	var probeService bool
	var outFile string

	flag.StringVar(&hostsSpec, "hosts", "", "Target hosts: comma-separated or CIDR (IPv4)")
	flag.StringVar(&portsSpec, "ports", "top:1000", "Ports: e.g. 'top:1000' or '1-1024,80,443'")
	flag.StringVar(&timeoutStr, "timeout", "500ms", "Dial timeout per port, e.g. 500ms, 1s")
	flag.IntVar(&workers, "workers", 500, "Concurrent workers")
	flag.BoolVar(&jsonOut, "json", false, "Output JSON")
	flag.BoolVar(&includeClosed, "all", false, "Include closed ports in output")
	flag.BoolVar(&probeService, "service", false, "Probe service banners on open ports")
	flag.StringVar(&outFile, "o", "", "Write output to file (JSON if -json, else table)")
	flag.Parse()

	hosts, err := expandHosts(hostsSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	portsList, err := parsePorts(portsSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil || timeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: invalid timeout")
		os.Exit(1)
	}
	if workers <= 0 {
		workers = 100
	}

	allResults := []scanner.Result{}
	for _, h := range hosts {
		results := scanner.ScanHostPorts(h, portsList, timeout, workers, probeService)
		if !includeClosed {
			filtered := make([]scanner.Result, 0, len(results))
			for _, r := range results {
				if r.Open {
					filtered = append(filtered, r)
				}
			}
			results = filtered
		}
		allResults = append(allResults, results...)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(allResults)
		if outFile != "" {
			f, err := os.Create(outFile)
			if err == nil {
				defer f.Close()
				enc2 := json.NewEncoder(f)
				enc2.SetIndent("", "  ")
				_ = enc2.Encode(allResults)
			}
		}
		return
	}

	output.PrintTable(os.Stdout, allResults)
	if outFile != "" {
		if f, err := os.Create(outFile); err == nil {
			defer f.Close()
			output.PrintTable(f, allResults)
		}
	}
}

// Top() now provided by internal/ports
