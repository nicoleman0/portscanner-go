package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"portscanner-go/internal/scanner"

	"golang.org/x/term"
)

// ansi color codes
const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
	ansiGray    = "\x1b[90m"
)

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func colorize(enabled bool, color string, s string) string {
	if !enabled {
		return s
	}
	return color + s + ansiReset
}

func PrintTable(w io.Writer, results []scanner.Result) {
	if len(results) == 0 {
		fmt.Fprintln(w, "No results.")
		return
	}
	useColor := isTTY(w)
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
		// Host header
		fmt.Fprintf(w, "%s%sHost:%s %s\n", ansiBold, ansiCyan, ansiReset, h)
		// Table header
		header := fmt.Sprintf("%-5s %-7s %-8s  %s", "PORT", "STATE", "LATENCY", "SERVICE")
		fmt.Fprintln(w, colorize(useColor, ansiGray, header))
		fmt.Fprintln(w, colorize(useColor, ansiGray, "----- ------- --------  ------------------------------"))
		ports := byHost[h]
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		for _, r := range ports {
			state := "closed"
			if r.Open {
				state = "open"
			}
			// Color state
			stateStr := state
			if useColor {
				if r.Open {
					stateStr = colorize(true, ansiGreen+ansiBold, state)
				} else {
					stateStr = colorize(true, ansiRed, state)
				}
			}
			// Latency coloring (fast < 5ms green, medium < 50ms yellow, else red)
			latMs := float64(r.Latency.Microseconds()) / 1000.0
			latStr := fmt.Sprintf("%6.2fms", latMs)
			if useColor {
				switch {
				case r.Latency < 5*time.Millisecond:
					latStr = colorize(true, ansiGreen, latStr)
				case r.Latency < 50*time.Millisecond:
					latStr = colorize(true, ansiYellow, latStr)
				default:
					latStr = colorize(true, ansiRed, latStr)
				}
			}
			banner := r.Banner
			if banner == "" {
				banner = ""
			} else if useColor {
				banner = colorize(true, ansiDim, banner)
			}
			fmt.Fprintf(w, "%-5d %-7s %8s  %s\n", r.Port, stateStr, latStr, banner)
		}
		fmt.Fprintln(w)
	}
}
