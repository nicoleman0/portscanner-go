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
	"sync"
	"time"
)

type Result struct {
	Host    string        `json:"host"`
	Port    int           `json:"port"`
	Open    bool          `json:"open"`
	Latency time.Duration `json:"latency_ms"`
	Err     string        `json:"error,omitempty"`
}

func ScanHostPorts(host string, ports []int, timeout time.Duration, workers int) []Result {
	if workers <= 0 {
		workers = 100
	}
	jobs := make(chan int)
	results := make(chan Result)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for p := range jobs {
				start := time.Now()
				addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				lat := time.Since(start)
				if err == nil {
					_ = conn.Close()
					results <- Result{Host: host, Port: p, Open: true, Latency: lat}
				} else {
					results <- Result{Host: host, Port: p, Open: false, Latency: lat, Err: err.Error()}
				}
			}
		}()
	}

	go func() {
		for _, p := range ports {
			jobs <- p
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make([]Result, 0, len(ports))
	for r := range results {
		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			return out[i].Port < out[j].Port
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func PrintTable(results []Result) {
	if len(results) == 0 {
		fmt.Println("No results.")
		return
	}
	byHost := map[string][]Result{}
	for _, r := range results {
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		fmt.Printf("Host: %s\n", h)
		fmt.Println("PORT  STATE   LATENCY")
		fmt.Println("----  ------  --------")
		ports := byHost[h]
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		for _, r := range ports {
			state := "closed"
			if r.Open {
				state = "open"
			}
			fmt.Printf("%-5d %-7s %6.2fms\n", r.Port, state, float64(r.Latency.Microseconds())/1000.0)
		}
		fmt.Println()
	}
}

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
		return Top(n), nil
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

	flag.StringVar(&hostsSpec, "hosts", "", "Target hosts: comma-separated or CIDR (IPv4)")
	flag.StringVar(&portsSpec, "ports", "top:100", "Ports: e.g. 'top:100' or '1-1024,80,443'")
	flag.StringVar(&timeoutStr, "timeout", "500ms", "Dial timeout per port, e.g. 500ms, 1s")
	flag.IntVar(&workers, "workers", 500, "Concurrent workers")
	flag.BoolVar(&jsonOut, "json", false, "Output JSON")
	flag.BoolVar(&includeClosed, "all", false, "Include closed ports in output")
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

	allResults := []Result{}
	for _, h := range hosts {
		results := ScanHostPorts(h, portsList, timeout, workers)
		if !includeClosed {
			filtered := make([]Result, 0, len(results))
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
		return
	}

	PrintTable(allResults)
}

func Top(n int) []int {
	if n <= 0 {
		n = 1
	}
	list := []int{
		80, 443, 22, 21, 25, 53, 110, 995, 143, 993,
		587, 3306, 3389, 135, 139, 445, 8080, 8443, 5900, 23,
		8000, 1723, 111, 123, 500, 1433, 1521, 5432, 6379, 27017,
		11211, 389, 636, 554, 1720, 5060, 5061, 88, 1900, 5353,
		49152, 49153, 49154, 49155, 1025, 1026, 1027, 1028, 69, 161,
		162, 5000, 5001, 5985, 8081, 8082, 8083, 8444, 9000, 9090,
		3128, 1080, 6667, 7001, 7002, 8181, 8888, 8883, 2181, 2049,
		4190, 10000, 25565, 25575, 5901, 5902, 5903, 465, 9200, 25,
	}
	if n >= len(list) {
		return list
	}
	return list[:n]
}
