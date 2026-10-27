package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadConnectResponse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name: "success with headers",
			raw:  "HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n",
		},
		{
			name:    "proxy authentication failure",
			raw:     "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
			wantErr: "CONNECT failed",
		},
		{
			name:    "invalid status line",
			raw:     "garbage\r\n\r\n",
			wantErr: "invalid CONNECT response",
		},
		{
			name:    "truncated headers",
			raw:     "HTTP/1.1 200 OK\r\nX-Test: 1\r\n",
			wantErr: "CONNECT response headers",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := readConnectResponse(bufio.NewReader(strings.NewReader(tt.raw)))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadConnectResponseLeavesBufferedTunnelData(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\n\r\nTLS"))
	if err := readConnectResponse(br); err != nil {
		t.Fatal(err)
	}
	next := make([]byte, 3)
	if _, err := br.Read(next); err != nil {
		t.Fatal(err)
	}
	if string(next) != "TLS" {
		t.Fatalf("buffered tunnel data = %q, want TLS", next)
	}
}

func TestNormalizeProxyAddr(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"1.2.3.4:8080", "1.2.3.4:8080", false},
		{"http://1.2.3.4:8080", "1.2.3.4:8080", false},
		{"socks5://proxy.example.com:1080/", "proxy.example.com:1080", false},
		{"[::1]:1080", "[::1]:1080", false},
		{"1.2.3.4", "", true},
		{"1.2.3.4:99999", "", true},
		{"http://user:pass@1.2.3.4:8080", "", true},
		{"http://1.2.3.4:8080/?x=1", "", true},
		{"ftp://1.2.3.4:8080", "", true},
	}
	for _, tt := range tests {
		got, err := normalizeProxyAddr(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("normalizeProxyAddr(%q) expected error, got %q", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeProxyAddr(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizeProxyAddr(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadProxies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	content := "\ufeff" + `# proxies for testing
1.2.3.4:8080
1.2.3.4:8080
http://5.6.7.8:3128
[::1]:1080 # local IPv6

`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadProxies(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.2.3.4:8080", "5.6.7.8:3128", "[::1]:1080"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadProxies = %v, want %v", got, want)
	}
}

func TestLoadProxiesReportsLineNumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(path, []byte("1.2.3.4:8080\nbad-proxy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProxies(path)
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error = %v, want line 2", err)
	}
}

func TestIsProxyType(t *testing.T) {
	for _, s := range []string{"http", "https", "sock4", "sock5"} {
		if !isProxyType(s) {
			t.Errorf("isProxyType(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "socks5", "HTTP", "ftp"} {
		if isProxyType(s) {
			t.Errorf("isProxyType(%q) = true, want false", s)
		}
	}
}

// newTestProxyHandler returns a small forward proxy that supports
// absolute-form HTTP requests and CONNECT tunnels. It is used only by the
// integration tests.
func newTestProxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			dest, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				dest.Close()
				http.Error(w, "hijacking not supported", http.StatusInternalServerError)
				return
			}
			client, _, err := hj.Hijack()
			if err != nil {
				dest.Close()
				return
			}
			_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			go func() {
				_, _ = io.Copy(dest, client)
				_ = dest.Close()
			}()
			_, _ = io.Copy(client, dest)
			_ = client.Close()
			_ = dest.Close()
			return
		}

		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func newTestProxy(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(newTestProxyHandler())
}

func TestHTTPProxyForwardsPlainHTTP(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "proxied")
	}))
	defer target.Close()
	proxySrv := newTestProxy(t)
	defer proxySrv.Close()

	u, path, err := parseTarget(target.URL + "/path")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:    u,
		Port:      determinePort(u),
		Path:      path,
		ProxyType: "http",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := dialViaProxy(dialCtx, proxySrv.Listener.Addr().String(), cfg, newTLSConfig(requestServerName(cfg)))
	dialCancel()
	if err != nil {
		t.Fatal(err)
	}

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no requests through HTTP proxy")
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
	if hits.Load() == 0 {
		t.Error("target received no requests")
	}
}

func TestHTTPProxyCONNECTForTLS(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "secure")
	}))
	defer target.Close()
	proxySrv := newTestProxy(t)
	defer proxySrv.Close()

	u, path, err := parseTarget(target.URL + "/secure")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:    u,
		Port:      determinePort(u),
		Path:      path,
		ProxyType: "http",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := dialViaProxy(dialCtx, proxySrv.Listener.Addr().String(), cfg, newTLSConfig(requestServerName(cfg)))
	dialCancel()
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no requests through CONNECT tunnel")
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
	if hits.Load() == 0 {
		t.Error("TLS target received no requests")
	}
}

func TestHTTPSProxyForwardsPlainHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "https-proxy")
	}))
	defer target.Close()
	proxySrv := httptest.NewTLSServer(newTestProxyHandler())
	defer proxySrv.Close()

	u, path, err := parseTarget(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:    u,
		Port:      determinePort(u),
		Path:      path,
		ProxyType: "https",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := dialViaProxy(dialCtx, proxySrv.Listener.Addr().String(), cfg, newTLSConfig(requestServerName(cfg)))
	dialCancel()
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no requests through HTTPS proxy")
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
}

func TestHTTPSProxyCONNECTForTLS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "nested-tls")
	}))
	defer target.Close()
	proxySrv := httptest.NewTLSServer(newTestProxyHandler())
	defer proxySrv.Close()

	u, path, err := parseTarget(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:    u,
		Port:      determinePort(u),
		Path:      path,
		ProxyType: "https",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := dialViaProxy(dialCtx, proxySrv.Listener.Addr().String(), cfg, newTLSConfig(requestServerName(cfg)))
	dialCancel()
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no requests through nested TLS")
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
}

func startTestSOCKS5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSOCKS5(conn)
		}
	}()
	return ln.Addr().String()
}

func handleTestSOCKS5(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	var greeting [2]byte
	if _, err := io.ReadFull(br, greeting[:]); err != nil {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 { // version 5, CONNECT
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // domain
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		name := make([]byte, int(l))
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return
	}
	dest, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf[:])))))
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer dest.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(dest, br)
		_ = dest.Close()
	}()
	_, _ = io.Copy(conn, dest)
}

func startTestSOCKS4(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSOCKS4(conn)
		}
	}()
	return ln.Addr().String()
}

func handleTestSOCKS4(conn net.Conn) {
	defer conn.Close()

	var req [8]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return
	}
	if req[0] != 0x04 || req[1] != 0x01 {
		return
	}
	// USERID is null-terminated.
	for {
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return
		}
		if b[0] == 0 {
			break
		}
	}

	port := binary.BigEndian.Uint16(req[2:4])
	host := net.IP(req[4:8]).String()
	dest, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_, _ = conn.Write([]byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0})
		return
	}
	defer dest.Close()
	if _, err := conn.Write([]byte{0x00, 0x5a, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(dest, conn)
		_ = dest.Close()
	}()
	_, _ = io.Copy(conn, dest)
}

func TestSOCKS5Proxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "socks5")
	}))
	defer target.Close()

	u, path, err := parseTarget(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:    u,
		Port:      determinePort(u),
		Path:      path,
		ProxyType: "sock5",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := dialViaProxy(dialCtx, startTestSOCKS5(t), cfg, newTLSConfig(requestServerName(cfg)))
	dialCancel()
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no requests through SOCKS5")
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
}

func TestSOCKS4Proxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "socks4")
	}))
	defer target.Close()

	u, path, err := parseTarget(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:    u,
		Port:      determinePort(u),
		Path:      path,
		ProxyType: "sock4",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := dialViaProxy(dialCtx, startTestSOCKS4(t), cfg, newTLSConfig(requestServerName(cfg)))
	dialCancel()
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no requests through SOCKS4")
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
}

func TestSendOnlyThroughHTTPProxy(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "send-only-proxy")
	}))
	defer target.Close()
	proxySrv := newTestProxy(t)
	defer proxySrv.Close()

	u, path, err := parseTarget(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:    u,
		Port:      determinePort(u),
		Path:      path,
		ProxyType: "http",
		SendOnly:  true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := dialViaProxy(dialCtx, proxySrv.Listener.Addr().String(), cfg, newTLSConfig(requestServerName(cfg)))
	dialCancel()
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}

	var m Metrics
	m.sendOnly = true
	sent, _ := sendOnlyConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if sent == 0 {
		t.Fatal("sent no requests through HTTP proxy")
	}
	if s := m.snapshot(); s.sent != int64(sent) {
		t.Errorf("sent metric = %d, wrote %d requests", s.sent, sent)
	}
	if hits.Load() == 0 {
		t.Error("target received no requests")
	}
}
