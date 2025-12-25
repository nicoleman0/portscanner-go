package scanner

import (
	"fmt"
	"net"
	"sort"
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

// ScanHostPorts performs a TCP connect scan with a worker pool.
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
