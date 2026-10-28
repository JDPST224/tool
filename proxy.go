// Proxy-based stress test.
//
// Usage: go run . [--jitter <ms>] [--send-only] <URL> <THREADS> <DURATION_SEC> <PROXY_TYPE> [CUSTOM_HOST]
// Proxy types: http, https, sock4, sock5
// Proxies are loaded from proxies.txt (one host:port per line)
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// ─── Proxy Manager ────────────────────────────────────────────────────────────

// ProxyManager coordinates proxy usage, worker lifecycle, and metrics.
type ProxyManager struct {
	cfg     StressConfig
	metrics Metrics
	rotator *proxyRotator
	wg      sync.WaitGroup
}

func NewProxyManager(cfg StressConfig) *ProxyManager {
	return &ProxyManager{
		cfg:     cfg,
		metrics: Metrics{sendOnly: cfg.SendOnly},
		rotator: newProxyRotator(cfg.Proxies, cfg.ProxyRotation),
	}
}

// ─── Entry point ──────────────────────────────────────────────────────────────

func runProxy(rawURL string, threads int, duration time.Duration, proxyType string, customHost string, opts runOptions) {
	proxyType = strings.ToLower(proxyType)

	parsedURL, path, err := parseTarget(rawURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	customHost, err = validateCustomHost(customHost)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Load proxies from proxies.txt
	proxies, err := loadProxies("proxies.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load proxies.txt: %v\n", err)
		os.Exit(1)
	}
	if len(proxies) == 0 {
		fmt.Fprintf(os.Stderr, "No proxies found in proxies.txt\n")
		os.Exit(1)
	}
	slog.Info("loaded proxies", "count", len(proxies))

	cfg := StressConfig{
		Target:        parsedURL,
		Threads:       threads,
		Duration:      duration,
		CustomHost:    customHost,
		Port:          determinePort(parsedURL),
		Path:          path,
		ProxyType:     proxyType,
		Proxies:       proxies,
		JitterMs:      opts.JitterMs,
		SendOnly:      opts.SendOnly,
		CacheBust:     opts.CacheBust,
		XFF:           opts.XFF,
		Fingerprint:   opts.Fingerprint,
		HTTP2:         opts.HTTP2,
		ProxyRotation: opts.ProxyRotation,
		RotateEvery:   opts.RotateEvery,
	}

	mgr := NewProxyManager(cfg)

	// Root context: cancelled by duration or signal.
	rootCtx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			slog.Info("interrupt received; shutting down early")
			cancel()
		case <-rootCtx.Done():
		}
	}()

	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		mgr.metrics.runStats(rootCtx, statsInterval)
	}()

	start := time.Now()
	slog.Info("stress test starting",
		"url", rawURL,
		"threads", threads,
		"duration", cfg.Duration,
		"proxy_type", proxyType,
		"proxy_count", len(proxies),
		"proxy_rotation", cfg.ProxyRotation,
		"custom_host", cfg.CustomHost,
		"send_only", cfg.SendOnly,
		"cache_bust", cfg.CacheBust,
		"xff", cfg.XFF,
		"fingerprint", cfg.Fingerprint,
		"http2", cfg.HTTP2 && !strings.EqualFold(cfg.Fingerprint, "none"),
		"rotate_every", cfg.RotateEvery,
	)
	mgr.runProxyManager(rootCtx)
	<-statsDone
	mgr.metrics.logSummary(start)
}

// loadProxies reads proxies from a file. Blank lines and comments (#) are
// ignored. Both "host:port" and "scheme://host:port" entries are accepted.
func loadProxies(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var proxies []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if lineNo == 1 {
			line = strings.TrimPrefix(line, "\ufeff") // UTF-8 BOM
		}
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		proxyAddr, err := normalizeProxyAddr(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if _, ok := seen[proxyAddr]; ok {
			continue
		}
		seen[proxyAddr] = struct{}{}
		proxies = append(proxies, proxyAddr)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return proxies, nil
}

func normalizeProxyAddr(line string) (string, error) {
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil {
			return "", fmt.Errorf("invalid proxy URL: %w", err)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "sock4", "socks4", "sock5", "socks5":
		default:
			return "", fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
		}
		if u.User != nil {
			return "", fmt.Errorf("proxy authentication is not supported")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return "", fmt.Errorf("unexpected query or fragment in proxy address")
		}
		if u.Path != "" && u.Path != "/" {
			return "", fmt.Errorf("unexpected path in proxy address")
		}
		line = u.Host
	}

	host, portStr, err := net.SplitHostPort(line)
	if err != nil {
		return "", fmt.Errorf("expected host:port: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("missing host")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %q", portStr)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// ─── Proxy Manager: worker lifecycle ─────────────────────────────────────────

type proxyWorkerEntry struct{ cancel context.CancelFunc }

func (m *ProxyManager) runProxyManager(ctx context.Context) {
	workers := make(map[int][]proxyWorkerEntry)

	spawn := func(idx int) {
		wctx, wcancel := context.WithCancel(ctx)
		workers[idx] = append(workers[idx], proxyWorkerEntry{cancel: wcancel})
		m.wg.Add(1)
		go m.proxyWorkerLoop(wctx, idx)
	}

	// Spawn workers; each new connection picks a proxy from the rotator.
	for i := 0; i < m.cfg.Threads; i++ {
		spawn(i)
	}

	<-ctx.Done()
	for _, list := range workers {
		for _, w := range list {
			w.cancel()
		}
	}
	m.wg.Wait()
}

// ─── Proxy Worker ─────────────────────────────────────────────────────────────

func (m *ProxyManager) proxyWorkerLoop(ctx context.Context, workerID int) {
	defer m.wg.Done()

	cfg := m.cfg
	hostHdr := requestHost(cfg)
	serverName := requestServerName(cfg)
	backoff := initialBackoff

	for ctx.Err() == nil {
		proxyAddr := m.rotator.pick(workerID)

		// Rotate the browser identity (UA, client hints, cookies, TLS
		// ClientHello and HTTP/2 profile) for every new connection.
		cfg.session = newBrowserSessionFor(cfg.Fingerprint)

		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		conn, err := dialViaProxy(dialCtx, proxyAddr, cfg, newTLSConfig(serverName))
		cancel()

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.rotator.markFailure(proxyAddr)
			m.metrics.recordError(err)
			slog.Debug("proxy dial failed", "proxy", proxyAddr, "err", err, "backoff", backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		completed, serveErr := m.exchange(ctx, cfg, conn, hostHdr)
		_ = conn.Close()

		if ctx.Err() != nil {
			return
		}
		if serveErr != nil {
			m.metrics.recordError(serveErr)
			if completed > 0 {
				// The proxy carried traffic; the target or connection ended.
				m.rotator.markSuccess(proxyAddr)
				backoff = initialBackoff
			} else {
				m.rotator.markFailure(proxyAddr)
			}
			slog.Debug("proxy connection error", "proxy", proxyAddr, "err", serveErr, "backoff", backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		// The target closed a keep-alive connection cleanly or the connection
		// reached --rotate-every; re-dial through the next proxy immediately.
		m.rotator.markSuccess(proxyAddr)
		backoff = initialBackoff
	}
}

// exchange runs one connection in either response-aware or send-only mode.
func (m *ProxyManager) exchange(ctx context.Context, cfg StressConfig, conn net.Conn, hostHdr string) (int, error) {
	if isHTTP2Conn(conn) {
		return h2Exchange(ctx, cfg, conn, hostHdr, &m.metrics)
	}
	if cfg.SendOnly {
		return sendOnlyConnection(ctx, cfg, conn, hostHdr, &m.metrics)
	}
	return serveConnection(ctx, cfg, conn, hostHdr, &m.metrics)
}

// ─── Proxy Dialing ────────────────────────────────────────────────────────────

// dialViaProxy establishes a connection to the target through the specified proxy.
func dialViaProxy(ctx context.Context, proxyAddr string, cfg StressConfig, targetTLS *tls.Config) (net.Conn, error) {
	switch cfg.ProxyType {
	case "http":
		return dialHTTPProxy(ctx, proxyAddr, cfg, targetTLS)
	case "https":
		return dialHTTPSProxy(ctx, proxyAddr, cfg, targetTLS)
	case "sock4":
		return dialSOCKS4(ctx, proxyAddr, cfg, targetTLS)
	case "sock5":
		return dialSOCKS5(ctx, proxyAddr, cfg, targetTLS)
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", cfg.ProxyType)
	}
}

func newProxyNetDialer() *net.Dialer {
	return newNetDialer()
}

func targetServerName(cfg StressConfig, targetTLS *tls.Config) string {
	if targetTLS != nil && targetTLS.ServerName != "" {
		return targetTLS.ServerName
	}
	return requestServerName(cfg)
}

// dialHTTPProxy connects through an HTTP proxy.
// For HTTP targets: sends full URL in request line.
// For HTTPS targets: uses CONNECT tunnel.
func dialHTTPProxy(ctx context.Context, proxyAddr string, cfg StressConfig, targetTLS *tls.Config) (net.Conn, error) {
	conn, err := newProxyNetDialer().DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}

	if cfg.Target.Scheme != "https" {
		// For HTTP targets, return a raw connection to the proxy. Requests are
		// sent in absolute-form by buildRequest.
		return conn, nil
	}

	tunneled, err := establishTunnel(ctx, conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return tlsHandshake(ctx, tunneled, targetServerName(cfg, targetTLS), fingerprintForConfig(cfg), cfg.HTTP2)
}

// dialHTTPSProxy connects through an HTTPS proxy (proxy over TLS).
// Same as HTTP proxy but the connection to the proxy itself is TLS-encrypted.
func dialHTTPSProxy(ctx context.Context, proxyAddr string, cfg StressConfig, targetTLS *tls.Config) (net.Conn, error) {
	raw, err := newProxyNetDialer().DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTPS proxy: %w", err)
	}

	proxyHost, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		proxyHost = proxyAddr
	}
	proxyConn, err := tlsHandshake(ctx, raw, proxyHost, fingerprintForConfig(cfg), false)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTPS proxy: %w", err)
	}

	if cfg.Target.Scheme != "https" {
		return proxyConn, nil
	}

	tunneled, err := establishTunnel(ctx, proxyConn, cfg)
	if err != nil {
		_ = proxyConn.Close()
		return nil, err
	}

	return tlsHandshake(ctx, tunneled, targetServerName(cfg, targetTLS), fingerprintForConfig(cfg), cfg.HTTP2)
}

// establishTunnel performs an HTTP CONNECT handshake and returns a connection
// that also preserves any bytes the proxy sent after the response headers.
func establishTunnel(ctx context.Context, conn net.Conn, cfg StressConfig) (net.Conn, error) {
	hostPort := net.JoinHostPort(cfg.Target.Hostname(), strconv.Itoa(cfg.Port))

	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	stopWatch := watchConn(ctx, conn)
	defer stopWatch()

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", hostPort, hostPort)
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("CONNECT write: %w", err)
	}

	br := bufio.NewReaderSize(conn, 4096)
	if err := readConnectResponse(br); err != nil {
		return nil, err
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// readConnectResponse reads and validates an HTTP CONNECT response. It must not
// assume the whole response arrives in one Read call.
func readConnectResponse(br *bufio.Reader) error {
	const maxHeaderBytes = 64 << 10

	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("CONNECT response read: %w", err)
	}
	if len(line) > maxHeaderBytes {
		return fmt.Errorf("CONNECT response headers too large")
	}
	total := len(line)

	statusLine := strings.TrimRight(line, "\r\n")
	fields := strings.Fields(statusLine)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return fmt.Errorf("invalid CONNECT response: %q", truncate(statusLine, 200))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return fmt.Errorf("invalid CONNECT status: %q", truncate(statusLine, 200))
	}
	if code < 200 || code > 299 {
		return fmt.Errorf("CONNECT failed: %s", truncate(statusLine, 200))
	}

	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("CONNECT response headers: %w", err)
		}
		total += len(l)
		if total > maxHeaderBytes {
			return fmt.Errorf("CONNECT response headers too large")
		}
		if l == "\r\n" || l == "\n" {
			return nil
		}
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// dialSOCKS4 connects through a SOCKS4 proxy.
func dialSOCKS4(ctx context.Context, proxyAddr string, cfg StressConfig, targetTLS *tls.Config) (net.Conn, error) {
	conn, err := newProxyNetDialer().DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to SOCKS4 proxy: %w", err)
	}

	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	stopWatch := watchConn(ctx, conn)
	defer stopWatch()

	targetHost := cfg.Target.Hostname()
	targetPort := cfg.Port

	// Resolve target IP for SOCKS4 (SOCKS4 doesn't support domain names).
	targetIPs, err := net.DefaultResolver.LookupIP(ctx, "ip4", targetHost)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("resolve target for SOCKS4: %w", err)
	}
	var targetIP net.IP
	for _, ip := range targetIPs {
		if ip4 := ip.To4(); ip4 != nil {
			targetIP = ip4
			break
		}
	}
	if targetIP == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("no IPv4 address for SOCKS4 target: %s", targetHost)
	}

	// SOCKS4 request: [VN=4][CD=1][DSTPORT][DSTIP][USERID=0x00]
	req := make([]byte, 9)
	req[0] = 0x04 // VN
	req[1] = 0x01 // CD = CONNECT
	binary.BigEndian.PutUint16(req[2:4], uint16(targetPort))
	copy(req[4:8], targetIP.To4())
	req[8] = 0x00 // USERID null terminator

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS4 request write: %w", err)
	}

	// SOCKS4 response: [VN=0][CD][DSTPORT][DSTIP]
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS4 response read: %w", err)
	}
	if resp[0] != 0x00 || resp[1] != 0x5a {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS4 request rejected: status=0x%02x", resp[1])
	}

	// If target is HTTPS, upgrade to TLS.
	if cfg.Target.Scheme == "https" {
		return tlsHandshake(ctx, conn, targetServerName(cfg, targetTLS), fingerprintForConfig(cfg), cfg.HTTP2)
	}

	return conn, nil
}

// deadlineDialer sets a deadline on the proxy connection before the SOCKS5
// handshake, which bounds a stalled proxy even if it never responds.
type deadlineDialer struct {
	dialer  net.Dialer
	timeout time.Duration
}

func (d *deadlineDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *deadlineDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(d.timeout))
	return conn, nil
}

// dialSOCKS5 connects through a SOCKS5 proxy using golang.org/x/net/proxy.
func dialSOCKS5(ctx context.Context, proxyAddr string, cfg StressConfig, targetTLS *tls.Config) (net.Conn, error) {
	forward := &deadlineDialer{
		dialer:  *newProxyNetDialer(),
		timeout: handshakeTimeout,
	}
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, forward)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer does not support contexts")
	}

	targetHost := cfg.Target.Hostname()
	targetPort := cfg.Port
	addr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))

	conn, err := contextDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dial: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	// If target is HTTPS, upgrade to TLS.
	if cfg.Target.Scheme == "https" {
		return tlsHandshake(ctx, conn, targetServerName(cfg, targetTLS), fingerprintForConfig(cfg), cfg.HTTP2)
	}

	return conn, nil
}
