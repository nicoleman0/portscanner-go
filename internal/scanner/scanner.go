package scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Host        string        `json:"host"`
	Port        int           `json:"port"`
	Open        bool          `json:"open"`
	Latency     time.Duration `json:"latency_ms"`
	Service     string        `json:"service,omitempty"`
	Banner      string        `json:"banner,omitempty"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	Err         string        `json:"error,omitempty"`
}

// ScanHostPorts performs a TCP connect scan with a worker pool.
func ScanHostPorts(host string, ports []int, timeout time.Duration, workers int, probe bool) []Result {
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
					service, banner, fp := "", "", ""
					if probe {
						service, banner, fp = fingerprintService(host, p, conn, timeout)
					}
					// Fallback to known service name if detection didn't yield one
					if service == "" {
						service = knownServiceForPort(p)
					}
					_ = conn.Close()
					results <- Result{Host: host, Port: p, Open: true, Latency: lat, Service: service, Banner: banner, Fingerprint: fp}
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

func sanitizeBanner(s string) string {
	res := make([]rune, 0, len(s))
	lastSpace := false
	for _, r := range s {
		if r < 32 || r > 126 {
			continue
		}
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			if !lastSpace {
				res = append(res, ' ')
				lastSpace = true
			}
			continue
		}
		lastSpace = false
		res = append(res, r)
	}
	return string(res)
}

func fingerprintService(host string, port int, conn net.Conn, timeout time.Duration) (string, string, string) {
	// Try to read any immediate banner
	_ = conn.SetReadDeadline(time.Now().Add(timeout / 3))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	banner := ""
	if n > 0 {
		banner = sanitizeBanner(string(buf[:n]))
	}

	// SSH banner
	if strings.HasPrefix(banner, "SSH-") || port == 22 {
		if banner == "" {
			// Some SSH daemons only send banner after a small delay; try again
			_ = conn.SetReadDeadline(time.Now().Add(timeout / 2))
			n2, _ := conn.Read(buf)
			if n2 > 0 {
				banner = sanitizeBanner(string(buf[:n2]))
			}
		}
		if banner != "" {
			return "ssh", banner, banner
		}
		return "ssh", "", ""
	}

	// SMTP/ESMTP
	if port == 25 || port == 587 || port == 465 {
		if strings.Contains(strings.ToUpper(banner), "SMTP") || strings.HasPrefix(banner, "220 ") {
			return "smtp", banner, banner
		}
	}

	// FTP
	if port == 21 {
		if strings.HasPrefix(banner, "220 ") || strings.Contains(strings.ToUpper(banner), "FTP") {
			return "ftp", banner, banner
		}
	}

	// POP3
	if port == 110 {
		if strings.HasPrefix(banner, "+OK") || strings.Contains(strings.ToUpper(banner), "POP3") {
			return "pop3", banner, banner
		}
	}

	// IMAP
	if port == 143 {
		if strings.HasPrefix(banner, "* OK") || strings.Contains(strings.ToUpper(banner), "IMAP") {
			return "imap", banner, banner
		}
	}

	// Try HTTP probe on common HTTP ports
	if isHTTPPort(port) {
		svc, b, fp := httpProbe(host, conn, timeout)
		if svc != "" {
			return svc, b, fp
		}
	}

	// Try TLS handshake on common TLS ports
	if isTLSPort(port) {
		svc, b, fp := tlsProbe(host, conn, timeout, port)
		if svc != "" {
			return svc, b, fp
		}
	}

	// Fallback: just return any banner we saw
	if banner != "" {
		return "", banner, ""
	}
	return "", "", ""
}

func isHTTPPort(p int) bool {
	switch p {
	case 80, 8000, 8080, 8081, 8888, 9000, 9090:
		return true
	}
	return false
}

func isTLSPort(p int) bool {
	switch p {
	case 443, 8443, 993, 995, 465, 9443:
		return true
	}
	return false
}

func httpProbe(host string, conn net.Conn, timeout time.Duration) (string, string, string) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout / 2))
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: portscanner-go\r\nConnection: close\r\n\r\n", host)
	_, _ = conn.Write([]byte(req))
	r := bufio.NewReader(conn)
	line, _ := r.ReadString('\n')
	line = sanitizeBanner(line)
	if strings.HasPrefix(line, "HTTP/") {
		// Collect Server header if present
		server := ""
		for i := 0; i < 20; i++ { // read limited headers
			h, err := r.ReadString('\n')
			if err != nil {
				break
			}
			hs := strings.TrimSpace(h)
			if hs == "" { // end of headers
				break
			}
			if strings.HasPrefix(strings.ToLower(hs), "server:") {
				server = sanitizeBanner(strings.TrimSpace(hs[7:]))
			}
		}
		fp := strings.TrimSpace(strings.Join([]string{line, server}, " "))
		return "http", line, fp
	}
	return "", "", ""
}

func tlsProbe(host string, baseConn net.Conn, timeout time.Duration, port int) (string, string, string) {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	tlsConn := tls.Client(baseConn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return "", "", ""
	}
	cs := tlsConn.ConnectionState()
	svc := "tls"
	switch port {
	case 443, 8443, 9443:
		svc = "https"
	case 993:
		svc = "imaps"
	case 995:
		svc = "pop3s"
	case 465:
		svc = "smtps"
	}
	fpParts := []string{}
	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		cn := cert.Subject.CommonName
		iss := cert.Issuer.CommonName
		if cn != "" {
			fpParts = append(fpParts, fmt.Sprintf("CN=%s", sanitizeBanner(cn)))
		}
		if iss != "" {
			fpParts = append(fpParts, fmt.Sprintf("Issuer=%s", sanitizeBanner(iss)))
		}
	}
	if cs.NegotiatedProtocol != "" {
		fpParts = append(fpParts, fmt.Sprintf("ALPN=%s", cs.NegotiatedProtocol))
	}
	fp := strings.Join(fpParts, ", ")
	// Optional: tiny HTTP HEAD to get server header on HTTPS
	if svc == "https" {
		_ = tlsConn.SetWriteDeadline(time.Now().Add(timeout / 2))
		_ = tlsConn.SetReadDeadline(time.Now().Add(timeout))
		_, _ = tlsConn.Write([]byte(fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host)))
		rd := bufio.NewReader(tlsConn)
		line, _ := rd.ReadString('\n')
		line = sanitizeBanner(line)
		if strings.HasPrefix(line, "HTTP/") {
			// Scan headers briefly for Server
			server := ""
			for i := 0; i < 20; i++ {
				h, err := rd.ReadString('\n')
				if err != nil {
					break
				}
				hs := strings.TrimSpace(h)
				if hs == "" {
					break
				}
				if strings.HasPrefix(strings.ToLower(hs), "server:") {
					server = sanitizeBanner(strings.TrimSpace(hs[7:]))
				}
			}
			if server != "" {
				if fp != "" {
					fp += ", "
				}
				fp += "Server=" + server
			}
			return svc, line, fp
		}
	}
	return svc, "", fp
}

// knownServiceForPort returns a best-effort service name for common ports.
func knownServiceForPort(p int) string {
	switch p {
	case 1:
		return "tcpmux"
	case 7:
		return "echo"
	case 13:
		return "daytime"
	case 19:
		return "chargen"
	case 20:
		return "ftp-data"
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 67:
		return "dhcp-server"
	case 68:
		return "dhcp-client"
	case 69:
		return "tftp"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 111:
		return "rpcbind"
	case 123:
		return "ntp"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 161:
		return "snmp"
	case 162:
		return "snmp-trap"
	case 389:
		return "ldap"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 465:
		return "smtps"
	case 500:
		return "isakmp"
	case 587:
		return "submission"
	case 631:
		return "ipp"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 1723:
		return "pptp"
	case 2049:
		return "nfs"
	case 2181:
		return "zookeeper"
	case 3128:
		return "proxy"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	case 7001:
		return "http-alt"
	case 8080:
		return "http-alt"
	case 8443:
		return "https-alt"
	case 8888:
		return "http-alt"
	case 9000:
		return "http-alt"
	case 9090:
		return "http-alt"
	case 9200:
		return "elasticsearch"
	case 27017:
		return "mongodb"
	case 11211:
		return "memcached"
	default:
		return ""
	}
}
