# portscanner-go

Lightweight and fast TCP port scanner written in Go. Designed for readability and speed, with simple CLI flags and clean table/JSON results.

## Features
- Concurrent TCP connect scanning with configurable worker pool
- Flexible port selection: `top:N` or ranges like `1-1024,80,443`
- Multiple targets: comma-separated hosts or IPv4 CIDR expansion
- Human-readable, colorized table output (auto-enabled on TTY) or JSON

## Install
```bash
go build -o portscan .
```

## Usage
```bash
# Scan top 100 ports on localhost
./portscan -hosts 127.0.0.1

# Scan specific ports and ranges
./portscan -hosts 192.168.1.10 -ports 1-1024,8080,8443

# Multiple hosts and CIDR
./portscan -hosts "192.168.1.10,192.168.1.20,192.168.1.0/30" -ports top:200

# JSON output
./portscan -hosts 10.0.0.5 -ports top:50 -json

# Include closed ports
./portscan -hosts example.com -ports top:100 -all

# Tune workers and timeout
./portscan -hosts example.com -ports top:100 -workers 800 -timeout 300ms

# Colorized output
# Table output uses ANSI colors when writing to a terminal.
# Colors are automatically disabled when output is redirected to a file.
# Example with file output:
./portscan -hosts 127.0.0.1 -ports top:50 -o scan.txt
```

## Notes
- This uses standard TCP connect scans (no raw SYN), so it runs without special privileges.
- Timeouts and worker pool size significantly impact speed and accuracy; adjust based on network conditions.
 - Colorized output is only applied when printing to an interactive terminal.
