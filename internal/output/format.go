package output

import (
	"fmt"
	"sort"

	"portscanner-go/internal/scanner"
)

func PrintTable(results []scanner.Result) {
	if len(results) == 0 {
		fmt.Println("No results.")
		return
	}
	byHost := map[string][]scanner.Result{}
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
