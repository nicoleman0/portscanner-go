package output

import (
	"fmt"
	"io"
	"sort"

	"portscanner-go/internal/scanner"
)

func PrintTable(w io.Writer, results []scanner.Result) {
	if len(results) == 0 {
		fmt.Fprintln(w, "No results.")
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
		fmt.Fprintf(w, "Host: %s\n", h)
		fmt.Fprintln(w, "PORT  STATE   LATENCY  SERVICE")
		fmt.Fprintln(w, "----  ------  --------  ------------------------------")
		ports := byHost[h]
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		for _, r := range ports {
			state := "closed"
			if r.Open {
				state = "open"
			}
			fmt.Fprintf(w, "%-5d %-7s %6.2fms  %s\n", r.Port, state, float64(r.Latency.Microseconds())/1000.0, r.Banner)
		}
		fmt.Fprintln(w)
	}
}
