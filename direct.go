// Direct stress test (no proxy).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// ─── Config ───────────────────────────────────────────────────────────────────

const (
	dialTimeout        = 10 * time.Second
	handshakeTimeout   = 10 * time.Second
	requestTimeout     = 15 * time.Second
	initialBackoff     = 100 * time.Millisecond
	maxBackoff         = 5 * time.Second
	statsInterval      = 5 * time.Second
	dnsRefreshInterval = 30 * time.Second

	// Send-only batching: fewer syscalls, atomics, and TLS records per request.
	sendBatchRequests   = 64
	sendBatchBytes      = 64 << 10
	jitterBatchRequests = 1
	readBufferSize      = 32 << 10
)

type uaProfile struct {
	ua          string
	accept      string
	encoding    string
	mobile      bool
	chrome      bool
	firefox     bool
	chromeMajor string
	secChUa     string
	platform    string
	hasPriority bool
}

type browserSession struct {
	profile      uaProfile
	language     string
	cookieHeader string
}

const (
	acceptFirefox = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
	acceptChrome  = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
	acceptSafari  = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
)

type StressConfig struct {
	Target     *url.URL
	Threads    int
	Duration   time.Duration
	CustomHost string
	Port       int
	Path       string
	ProxyType  string
	Proxies    []string
	JitterMs   int  // max per-request jitter in milliseconds (0 = disabled)
	SendOnly   bool // do not wait for/parse responses
	CacheBust  bool // append a random cache-busting query parameter
	XFF        bool // add synthetic X-Forwarded-For headers
	session    *browserSession
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

var (
	// Mostly document navigations, with occasional form POSTs and fetch HEADs.
	httpMethods = []string{"GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET", "POST", "HEAD"}

	languages = []string{
		"en-US,en;q=0.9",
		"en-US,en;q=0.9,fr;q=0.5",
		"en-GB,en;q=0.8",
		"fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
		"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
		"es-ES,es;q=0.9,en;q=0.8",
		"pt-BR,pt;q=0.9,en-US;q=0.8",
		"ja-JP,ja;q=0.9,en-US;q=0.8",
		"zh-CN,zh;q=0.9,en;q=0.8",
		"ko-KR,ko;q=0.9,en-US;q=0.8",
		"ru-RU,ru;q=0.9,en-US;q=0.8",
		"tr-TR,tr;q=0.9,en-US;q=0.8",
	}

	// referers are external navigation sources. A direct navigation has no
	// Referer header and uses Sec-Fetch-Site: none. Origins only match the
	// default strict-origin-when-cross-origin referrer policy.
	referers = []string{
		"https://www.google.com/",
		"https://www.bing.com/",
		"https://duckduckgo.com/",
		"https://search.yahoo.com/",
		"https://www.facebook.com/",
		"https://t.co/",
		"https://www.reddit.com/",
		"https://www.youtube.com/",
		"https://www.instagram.com/",
		"https://www.linkedin.com/",
		"https://news.ycombinator.com/",
	}

	cacheBusterKeys = []string{"_", "v", "cb", "t", "r", "nocache", "ts", "rnd"}

	// chromeCipherSuites are the TLS 1.2 cipher suites offered by Chrome-like
	// profiles. A fixed order is used so each session looks consistent.
	chromeCipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}

	// bufPool avoids per-request header allocations.
	// IMPORTANT: buf.Bytes() must be consumed (written to conn) before Put().
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

	// bodyBufPool avoids per-request POST body allocations.
	bodyBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

	// sendBatchPool reuses large send-only batch buffers across reconnects.
	sendBatchPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

	// readBufPool provides large discard buffers for send-only response draining.
	readBufPool = sync.Pool{New: func() any {
		b := make([]byte, readBufferSize)
		return &b
	}}

	// Pre-generated User-Agent profiles with browser-specific headers.
	uaProfiles []uaProfile

	// defaultSession is used only by tests or configurations that do not set a
	// per-worker session explicitly.
	defaultSession *browserSession
)

func init() {
	// 500 profiles with diverse browser/OS/mobile combinations.
	uaProfiles = make([]uaProfile, 500)
	for i := range uaProfiles {
		ua := generateUserAgent()
		p := uaProfile{
			ua:      ua,
			mobile:  strings.Contains(ua, "Mobile"),
			chrome:  strings.Contains(ua, "Chrome/"),
			firefox: strings.Contains(ua, "Firefox/"),
		}
		switch {
		case p.firefox:
			p.accept = acceptFirefox
			p.encoding = "gzip, deflate, br, zstd"
		case p.chrome:
			p.accept = acceptChrome
			p.encoding = "gzip, deflate, br, zstd"
		default:
			p.accept = acceptSafari
			p.encoding = "gzip, deflate, br"
		}
		if p.chrome {
			p.chromeMajor = chromeMajorFromUA(ua)
			p.platform = platformFromUA(ua)
			p.secChUa = fmt.Sprintf("sec-ch-ua: \"Google Chrome\";v=\"%s\", \"Chromium\";v=\"%s\", \"Not_A Brand\";v=\"99\"\r\n",
				p.chromeMajor, p.chromeMajor)
			if major, err := strconv.Atoi(p.chromeMajor); err == nil && major >= 115 {
				p.hasPriority = true
			}
		}
		uaProfiles[i] = p
	}
	defaultSession = newBrowserSession()
}

func newBrowserSession() *browserSession {
	s := &browserSession{
		profile:  uaProfiles[rand.IntN(len(uaProfiles))],
		language: languages[rand.IntN(len(languages))],
	}
	// Roughly half of sessions represent a returning visitor with stable
	// analytics cookies. Cookies must not change between requests in a session.
	if rand.IntN(2) == 0 {
		now := time.Now().Unix()
		gaBase := rand.Int64N(1_999_999_999) + 1
		gidBase := rand.Int64N(1_999_999_999) + 1
		s.cookieHeader = fmt.Sprintf("Cookie: _ga=GA1.2.%d.%d; _gid=GA1.2.%d.%d\r\n",
			gaBase, now-rand.Int64N(90*24*3600), gidBase, now)
	}
	return s
}

// ─── Manager ──────────────────────────────────────────────────────────────────

// Manager coordinates DNS refresh, worker lifecycle, and metrics.
// All state that was previously package-global lives here.
type Manager struct {
	cfg StressConfig

	ipsMu sync.Mutex
	ips   []string

	// rebalanceCh carries new IP slices from dnsRefresh to runManager.
	// Buffered to 1; dnsRefresh blocks until the update is accepted so a newer
	// IP set is never silently dropped.
	rebalanceCh chan []string

	metrics Metrics
	wg      sync.WaitGroup
}

func NewManager(cfg StressConfig) *Manager {
	return &Manager{
		cfg:         cfg,
		metrics:     Metrics{sendOnly: cfg.SendOnly},
		rebalanceCh: make(chan []string, 1),
	}
}

func (m *Manager) updateIPs(newIPs []string) {
	m.ipsMu.Lock()
	m.ips = newIPs
	m.ipsMu.Unlock()
}

func (m *Manager) snapshotIPs() []string {
	m.ipsMu.Lock()
	defer m.ipsMu.Unlock()
	out := make([]string, len(m.ips))
	copy(out, m.ips)
	return out
}

// ─── Entry point ──────────────────────────────────────────────────────────────

func runDirect(rawURL string, threads int, duration time.Duration, customHost string, opts runOptions) {
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

	cfg := StressConfig{
		Target:     parsedURL,
		Threads:    threads,
		Duration:   duration,
		CustomHost: customHost,
		Port:       determinePort(parsedURL),
		Path:       path,
		JitterMs:   opts.JitterMs,
		SendOnly:   opts.SendOnly,
		CacheBust:  opts.CacheBust,
		XFF:        opts.XFF,
	}

	// Initial DNS lookup.
	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), dialTimeout)
	addrs, err := lookupIPv4(lookupCtx, parsedURL.Hostname())
	lookupCancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initial DNS lookup failed: %v\n", err)
		os.Exit(1)
	}
	slog.Info("resolved IPs", "ips", addrs)

	mgr := NewManager(cfg)
	mgr.updateIPs(addrs)

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
	go mgr.dnsRefresh(rootCtx, parsedURL.Hostname(), dnsRefreshInterval)

	start := time.Now()
	slog.Info("stress test starting",
		"url", rawURL,
		"threads", threads,
		"duration", cfg.Duration,
		"custom_host", cfg.CustomHost,
		"send_only", cfg.SendOnly,
		"cache_bust", cfg.CacheBust,
		"xff", cfg.XFF,
	)
	mgr.runManager(rootCtx)
	<-statsDone
	mgr.metrics.logSummary(start)
}

// ─── Manager: worker lifecycle ────────────────────────────────────────────────

type workerEntry struct{ cancel context.CancelFunc }

func (m *Manager) runManager(ctx context.Context) {
	workers := make(map[string][]workerEntry)

	spawn := func(ip string) {
		wctx, wcancel := context.WithCancel(ctx)
		workers[ip] = append(workers[ip], workerEntry{cancel: wcancel})
		m.wg.Add(1)
		go m.workerLoop(wctx, ip)
	}

	m.rebalance(m.snapshotIPs(), workers, spawn)

	for {
		select {
		case <-ctx.Done():
			for _, list := range workers {
				for _, w := range list {
					w.cancel()
				}
			}
			m.wg.Wait()
			return
		case newIPs := <-m.rebalanceCh:
			m.rebalance(newIPs, workers, spawn)
		}
	}
}

func (m *Manager) rebalance(ipsList []string, workers map[string][]workerEntry, spawn func(string)) {
	n := len(ipsList)
	if n == 0 {
		for ip, list := range workers {
			for _, w := range list {
				w.cancel()
			}
			delete(workers, ip)
		}
		slog.Warn("rebalance: no IPs available; all workers cancelled")
		return
	}

	base := m.cfg.Threads / n
	extra := m.cfg.Threads % n
	desired := make(map[string]int, n)
	for i, ip := range ipsList {
		desired[ip] = base
		if i < extra {
			desired[ip]++
		}
	}

	// Cancel workers for IPs no longer in the desired set.
	for ip, list := range workers {
		if _, ok := desired[ip]; !ok {
			for _, w := range list {
				w.cancel()
			}
			delete(workers, ip)
		}
	}

	// Spawn or cancel to hit the target count per IP.
	for ip, want := range desired {
		have := len(workers[ip])
		for i := 0; i < want-have; i++ {
			spawn(ip)
		}
		for i := 0; i < have-want; i++ {
			w := workers[ip][0]
			w.cancel()
			workers[ip] = workers[ip][1:]
		}
	}

	slog.Info("rebalance complete", "desired", desired, "running", mapCounts(workers))
}

// mapCounts builds a per-IP worker count for logging.
func mapCounts(workers map[string][]workerEntry) map[string]int {
	out := make(map[string]int, len(workers))
	for ip, list := range workers {
		out[ip] = len(list)
	}
	return out
}

// ─── Worker ───────────────────────────────────────────────────────────────────

func (m *Manager) workerLoop(ctx context.Context, ip string) {
	defer m.wg.Done()

	cfg := m.cfg
	cfg.session = newBrowserSession() // one browser identity per worker/connection
	hostHdr := requestHost(cfg)
	serverName := requestServerName(cfg)
	addr := net.JoinHostPort(ip, strconv.Itoa(cfg.Port))
	useTLS := cfg.Target.Scheme == "https"
	backoff := initialBackoff

	for ctx.Err() == nil {
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		var conn net.Conn
		var err error
		if useTLS {
			conn, err = dialConn(dialCtx, addr, true, newTLSConfig(serverName))
		} else {
			conn, err = dialConn(dialCtx, addr, false, nil)
		}
		cancel()

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.metrics.recordError(err)
			slog.Debug("dial failed", "addr", addr, "err", err, "backoff", backoff)
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
				backoff = initialBackoff
			}
			slog.Debug("connection error", "addr", addr, "err", serveErr, "backoff", backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		// The server closed a keep-alive connection cleanly; re-dial at once.
		backoff = initialBackoff
	}
}

// exchange runs one connection in either response-aware or send-only mode.
func (m *Manager) exchange(ctx context.Context, cfg StressConfig, conn net.Conn, hostHdr string) (int, error) {
	if cfg.SendOnly {
		return sendOnlyConnection(ctx, cfg, conn, hostHdr, &m.metrics)
	}
	return serveConnection(ctx, cfg, conn, hostHdr, &m.metrics)
}

// ─── Request building & response handling ─────────────────────────────────────

// serveConnection performs sequential keep-alive requests on conn until the
// server closes the connection, an error occurs, or ctx is cancelled.
//
// The previous implementation fired requests without reading complete
// responses. Unread response bodies eventually filled the socket buffers and
// stalled both client and server. This loop drains every response before
// sending the next request, which also makes the request rate and status
// counts meaningful.
//
// The returned count is the number of fully completed exchanges. A nil error
// means the server closed the connection cleanly after a response.
func serveConnection(ctx context.Context, cfg StressConfig, conn net.Conn, hostHdr string, metrics *Metrics) (completed int, err error) {
	stopWatch := watchConn(ctx, conn)
	defer stopWatch()

	br := bufio.NewReaderSize(conn, 4096)
	for {
		if ctx.Err() != nil {
			return completed, ctx.Err()
		}

		method := httpMethods[rand.IntN(len(httpMethods))]
		start := time.Now()

		if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
			return completed, err
		}
		if err := writeRequest(conn, cfg, method, hostHdr); err != nil {
			return completed, fmt.Errorf("write request: %w", err)
		}
		resp, err := readHTTPResponse(br, method)
		if err != nil {
			return completed, fmt.Errorf("read response: %w", err)
		}
		if err := drainResponse(resp); err != nil {
			return completed, fmt.Errorf("read response body: %w", err)
		}

		metrics.recordResponse(resp.StatusCode, time.Since(start))
		completed++
		_ = conn.SetDeadline(time.Time{})

		if resp.Close {
			return completed, nil
		}

		// Jitter: small random sleep between requests to avoid a zero-delay
		// request pattern.
		if cfg.JitterMs > 0 {
			jitter := time.Duration(rand.IntN(cfg.JitterMs)+1) * time.Millisecond
			select {
			case <-ctx.Done():
				return completed, ctx.Err()
			case <-time.After(jitter):
			}
		}
	}
}

// sendOnlyConnection writes requests back-to-back without waiting for or
// parsing responses. A background reader discards response bytes so that
// unread responses do not fill the socket buffers and block the writer.
//
// Requests are batched into a single write (up to sendBatchRequests or
// sendBatchBytes) to reduce syscalls, TLS records, and metric contention.
// "sent" counts successful request writes. The returned error is a transport
// error; a nil error is not expected because the loop only ends on error or
// cancellation.
func sendOnlyConnection(ctx context.Context, cfg StressConfig, conn net.Conn, hostHdr string, metrics *Metrics) (sent int, err error) {
	stopWatch := watchConn(ctx, conn)
	defer stopWatch()

	// Drain response bytes without inspecting them. A larger buffer reduces
	// read syscalls; closing conn when the reader exits also unblocks a writer
	// that is stuck on a full send buffer.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		bufp := readBufPool.Get().(*[]byte)
		buf := *bufp
		for {
			if _, err := conn.Read(buf); err != nil {
				break
			}
		}
		readBufPool.Put(bufp)
		_ = conn.Close()
	}()
	defer func() {
		_ = conn.Close()
		<-readerDone
	}()

	batchRequests := sendBatchRequests
	batchCap := sendBatchBytes
	if cfg.JitterMs > 0 {
		// Per-request jitter must not be diluted by batching.
		batchRequests = jitterBatchRequests
		batchCap = 4 << 10
	}
	batch := sendBatchPool.Get().(*bytes.Buffer)
	batch.Reset()
	if batch.Cap() < batchCap {
		batch.Grow(batchCap)
	}
	defer sendBatchPool.Put(batch)

	body := bodyBufPool.Get().(*bytes.Buffer)
	body.Reset()
	defer bodyBufPool.Put(body)

	for {
		if ctx.Err() != nil {
			return sent, ctx.Err()
		}

		batch.Reset()
		n := buildSendBatch(batch, body, cfg, hostHdr, batchRequests, sendBatchBytes)
		if n == 0 {
			continue
		}

		// Do not write a batch after the test has been cancelled.
		if ctx.Err() != nil {
			return sent, ctx.Err()
		}

		// SetWriteDeadline (not SetDeadline) so the discard reader is not
		// interrupted by the writer's timeout.
		if err := conn.SetWriteDeadline(time.Now().Add(requestTimeout)); err != nil {
			return sent, err
		}
		if err := writeAll(conn, batch.Bytes()); err != nil {
			return sent, fmt.Errorf("write requests: %w", err)
		}

		metrics.recordSentN(n)
		sent += n

		// Jitter: small random sleep between requests.
		if cfg.JitterMs > 0 {
			jitter := time.Duration(rand.IntN(cfg.JitterMs)+1) * time.Millisecond
			select {
			case <-ctx.Done():
				return sent, ctx.Err()
			case <-time.After(jitter):
			}
		}
	}
}

// buildSendBatch appends up to maxRequests requests (or maxBytes bytes) to
// batch and returns the request count. The caller resets batch first.
func buildSendBatch(batch, body *bytes.Buffer, cfg StressConfig, hostHdr string, maxRequests, maxBytes int) int {
	n := 0
	for n < maxRequests && batch.Len() < maxBytes {
		method := httpMethods[rand.IntN(len(httpMethods))]
		if method == "POST" && body != nil {
			body.Reset()
		}
		buildRequest(batch, cfg, method, hostHdr, body)
		n++
	}
	return n
}

// writeRequest serialises and writes one request. Pools are returned only
// after the write has consumed the buffer.
func writeRequest(conn net.Conn, cfg StressConfig, method, hostHdr string) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()

	var body *bytes.Buffer
	if method == "POST" {
		body = bodyBufPool.Get().(*bytes.Buffer)
		body.Reset()
	}

	buildRequest(buf, cfg, method, hostHdr, body)
	writeErr := writeAll(conn, buf.Bytes())

	bufPool.Put(buf) // safe: the buffer has been consumed by writeAll
	if body != nil {
		bodyBufPool.Put(body)
	}
	return writeErr
}

func writeAll(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

// readHTTPResponse reads the next final response, skipping 1xx informational
// responses.
func readHTTPResponse(br *bufio.Reader, method string) (*http.Response, error) {
	req := &http.Request{Method: method}
	for i := 0; i < 8; i++ {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			return nil, fmt.Errorf("unexpected 101 Switching Protocols response")
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 {
			if err := drainResponse(resp); err != nil {
				return nil, err
			}
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("too many informational responses")
}

// drainResponse consumes and closes a response body so the underlying
// connection can be reused.
func drainResponse(resp *http.Response) error {
	if resp.Body == nil {
		return nil
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return readErr
	}
	return closeErr
}

// buildRequest writes a browser-like HTTP/1.1 request into buf.
// bodyBuf is populated only for POST; the body is appended to buf at the end.
func buildRequest(buf *bytes.Buffer, cfg StressConfig, method, hostHdr string, bodyBuf *bytes.Buffer) {
	sess := cfg.session
	if sess == nil {
		sess = defaultSession
	}
	p := sess.profile

	isNavigation := method == "GET" || method == "POST"

	// Coherent navigation source: direct (no Referer), external (cross-site),
	// or same-origin. POST is a form submission; HEAD is a same-origin fetch.
	site := "same-origin"
	refererMode := 1 // 0 none, 1 same-origin, 2 external
	if method == "GET" {
		switch r := rand.IntN(10); {
		case r < 5:
			site, refererMode = "none", 0
		case r < 8:
			site, refererMode = "cross-site", 2
		}
	}
	var externalReferer string
	if refererMode == 2 {
		externalReferer = referers[rand.IntN(len(referers))]
	}

	buf.WriteString(method)
	buf.WriteByte(' ')
	writeRequestTarget(buf, cfg, method)
	buf.WriteString(" HTTP/1.1\r\nHost: ")
	buf.WriteString(hostHdr)
	buf.WriteString("\r\nConnection: keep-alive\r\n")

	if p.chrome {
		buf.WriteString(p.secChUa)
		if p.mobile {
			buf.WriteString("sec-ch-ua-mobile: ?1\r\n")
		} else {
			buf.WriteString("sec-ch-ua-mobile: ?0\r\n")
		}
		buf.WriteString("sec-ch-ua-platform: \"")
		buf.WriteString(p.platform)
		buf.WriteString("\"\r\n")
	}

	if isNavigation {
		buf.WriteString("Upgrade-Insecure-Requests: 1\r\n")
	}

	buf.WriteString("User-Agent: ")
	buf.WriteString(p.ua)
	buf.WriteString("\r\n")

	if method == "HEAD" {
		buf.WriteString("Accept: */*\r\n")
	} else {
		buf.WriteString(p.accept)
	}

	buf.WriteString("Sec-Fetch-Site: ")
	buf.WriteString(site)
	buf.WriteString("\r\nSec-Fetch-Mode: ")
	if isNavigation {
		buf.WriteString("navigate\r\n")
	} else {
		buf.WriteString("cors\r\n")
	}
	if isNavigation {
		buf.WriteString("Sec-Fetch-User: ?1\r\n")
	}
	buf.WriteString("Sec-Fetch-Dest: ")
	if isNavigation {
		buf.WriteString("document\r\n")
	} else {
		buf.WriteString("empty\r\n")
	}

	if p.chrome && isNavigation && p.hasPriority {
		buf.WriteString("Priority: u=0, i\r\n")
	}

	buf.WriteString("Accept-Encoding: ")
	buf.WriteString(p.encoding)
	buf.WriteString("\r\nAccept-Language: ")
	buf.WriteString(sess.language)
	buf.WriteString("\r\n")

	if sess.cookieHeader != "" {
		buf.WriteString(sess.cookieHeader)
	}

	switch refererMode {
	case 1:
		buf.WriteString("Referer: ")
		writePageURL(buf, cfg, hostHdr)
		buf.WriteString("\r\n")
	case 2:
		buf.WriteString("Referer: ")
		buf.WriteString(externalReferer)
		buf.WriteString("\r\n")
	}

	// Synthetic proxy/CDN hop header. Browsers do not send this; opt-in only.
	if cfg.XFF {
		buf.WriteString("X-Forwarded-For: ")
		writeRandomPublicIP(buf)
		if rand.IntN(3) > 0 {
			buf.WriteString(", ")
			writeRandomCDNEdgeIP(buf)
		}
		buf.WriteString("\r\n")
	}

	if method == "POST" {
		if bodyBuf == nil {
			bodyBuf = new(bytes.Buffer)
		}
		bodyBuf.Reset()
		createFormBody(bodyBuf)
		buf.WriteString("Origin: ")
		buf.WriteString(cfg.Target.Scheme)
		buf.WriteString("://")
		buf.WriteString(hostHdr)
		buf.WriteString("\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ")
		writeInt(buf, int64(bodyBuf.Len()))
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	if method == "POST" {
		buf.Write(bodyBuf.Bytes())
	}
}

// writePageURL writes the target page URL (without a cache-busting parameter)
// for same-origin Referer headers.
func writePageURL(buf *bytes.Buffer, cfg StressConfig, hostHdr string) {
	buf.WriteString(cfg.Target.Scheme)
	buf.WriteString("://")
	buf.WriteString(hostHdr)
	if cfg.Path == "" {
		buf.WriteByte('/')
	} else {
		buf.WriteString(cfg.Path)
	}
}

// writeRequestTarget writes origin-form for direct/SOCKS/CONNECT requests and
// absolute-form for plain HTTP requests sent through an HTTP(S) proxy.
func writeRequestTarget(buf *bytes.Buffer, cfg StressConfig, method string) {
	if (cfg.ProxyType == "http" || cfg.ProxyType == "https") && cfg.Target.Scheme == "http" {
		buf.WriteString(cfg.Target.Scheme)
		buf.WriteString("://")
		buf.WriteString(cfg.Target.Host)
	}

	if cfg.Path == "" {
		buf.WriteByte('/')
	} else {
		buf.WriteString(cfg.Path)
	}

	// Optional cache-busting parameter. This is not browser-like, so it is off
	// by default and enabled with --cache-bust.
	if cfg.CacheBust && (method == "GET" || method == "HEAD") {
		if strings.Contains(cfg.Path, "?") {
			buf.WriteByte('&')
		} else {
			buf.WriteByte('?')
		}
		buf.WriteString(cacheBusterKeys[rand.IntN(len(cacheBusterKeys))])
		buf.WriteByte('=')
		writeInt(buf, rand.Int64N(1_000_000_000))
	}
}

func writeInt(buf *bytes.Buffer, n int64) {
	var tmp [20]byte
	buf.Write(strconv.AppendInt(tmp[:0], n, 10))
}

func writeIP4(buf *bytes.Buffer, a, b, c, d int) {
	writeInt(buf, int64(a))
	buf.WriteByte('.')
	writeInt(buf, int64(b))
	buf.WriteByte('.')
	writeInt(buf, int64(c))
	buf.WriteByte('.')
	writeInt(buf, int64(d))
}

// writeRandomPublicIP appends a random routable IPv4 address without allocating.
func writeRandomPublicIP(buf *bytes.Buffer) {
	for {
		a := rand.IntN(222) + 1
		if a == 10 || a == 127 {
			continue
		}
		b := rand.IntN(256)
		if a == 172 && b >= 16 && b <= 31 {
			continue
		}
		if a == 192 && b == 168 {
			continue
		}
		writeIP4(buf, a, b, rand.IntN(256), rand.IntN(254)+1)
		return
	}
}

// writeRandomCDNEdgeIP appends a private intermediate hop without allocating.
func writeRandomCDNEdgeIP(buf *bytes.Buffer) {
	switch rand.IntN(3) {
	case 0:
		writeIP4(buf, 10, rand.IntN(256), rand.IntN(256), rand.IntN(254)+1)
	case 1:
		writeIP4(buf, 172, rand.IntN(16)+16, rand.IntN(256), rand.IntN(254)+1)
	default:
		writeIP4(buf, 192, 168, rand.IntN(256), rand.IntN(254)+1)
	}
}

// requestHost returns the value for the Host header, including a non-default
// target port when a custom Host is supplied without one.
func requestHost(cfg StressConfig) string {
	if cfg.CustomHost == "" {
		return cfg.Target.Host
	}
	h := cfg.CustomHost
	if !hostHasPort(h) && !isDefaultPort(cfg.Target.Scheme, cfg.Port) {
		host := strings.TrimPrefix(h, "[")
		host = strings.TrimSuffix(host, "]")
		return net.JoinHostPort(host, strconv.Itoa(cfg.Port))
	}
	return h
}

// requestServerName returns the TLS SNI name (never includes a port).
func requestServerName(cfg StressConfig) string {
	h := cfg.CustomHost
	if h == "" {
		return cfg.Target.Hostname()
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}

func hostHasPort(h string) bool {
	if strings.HasPrefix(h, "[") {
		end := strings.Index(h, "]")
		return end >= 0 && end+1 < len(h) && h[end+1] == ':'
	}
	return strings.Count(h, ":") == 1
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

// ─── DNS ──────────────────────────────────────────────────────────────────────

func (m *Manager) dnsRefresh(ctx context.Context, host string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lookupCtx, cancel := context.WithTimeout(ctx, dialTimeout)
			addrs, err := lookupIPv4(lookupCtx, host)
			cancel()
			if err != nil {
				// Log and keep using existing IPs.
				slog.Warn("DNS re-resolution failed", "host", host, "err", err)
				continue
			}
			// Only trigger rebalance if IPs actually changed.
			m.ipsMu.Lock()
			changed := !slicesEqual(m.ips, addrs)
			if changed {
				m.ips = addrs
			}
			m.ipsMu.Unlock()
			if !changed {
				slog.Debug("DNS unchanged", "host", host, "ips", addrs)
				continue
			}
			slog.Info("DNS refreshed", "host", host, "ips", addrs)
			// Block until runManager can accept the update; never silently drop
			// the newest IP set (a later refresh may see no change and stay quiet).
			select {
			case m.rebalanceCh <- addrs:
			case <-ctx.Done():
				return
			}
		}
	}
}

// slicesEqual compares two sorted string slices for equality.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lookupIPv4 resolves a host to sorted, unique IPv4 addresses.
// Returns an error if DNS fails or no IPv4 addresses are found.
func lookupIPv4(ctx context.Context, host string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		s := ip4.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found for %s", host)
	}
	sort.Strings(out) // deterministic order → stable rebalancing
	return out, nil
}

// ─── Dialling ─────────────────────────────────────────────────────────────────

// dialConn dials addr using a context-aware dialer. TLS is selected from the
// target URL scheme, not from the port number.
func dialConn(ctx context.Context, addr string, useTLS bool, tlsCfg *tls.Config) (net.Conn, error) {
	netDialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}
	if !useTLS {
		return netDialer.DialContext(ctx, "tcp", addr)
	}
	// tls.Dialer.DialContext honours ctx cancellation for both dial and handshake.
	return (&tls.Dialer{NetDialer: netDialer, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
}

// newTLSConfig builds a TLS config with a fixed Chrome-like cipher order.
// InsecureSkipVerify is intentional: the tool must be able to test home-lab
// servers with self-signed certificates.
func newTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // intentional for a stress tool
		MinVersion:         tls.VersionTLS12,
		CipherSuites:       chromeCipherSuites,
		NextProtos:         []string{"http/1.1"},
	}
}

// watchConn interrupts in-flight I/O and closes conn when ctx is cancelled.
func watchConn(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Deadlines interrupt TLS reads/writes even when Close cannot take
			// the connection's write lock immediately.
			_ = conn.SetDeadline(time.Now())
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

// ─── URL / custom host helpers ────────────────────────────────────────────────

func parseTarget(rawURL string) (*url.URL, string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if parsedURL.Scheme == "" || parsedURL.Hostname() == "" {
		return nil, "", fmt.Errorf("invalid URL %q", rawURL)
	}
	parsedURL.Scheme = strings.ToLower(parsedURL.Scheme)
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, "", fmt.Errorf("URL scheme must be http or https, got %q", parsedURL.Scheme)
	}
	if parsedURL.User != nil {
		return nil, "", fmt.Errorf("URL credentials are not supported; remove the user:password part")
	}
	if strings.HasSuffix(parsedURL.Host, ":") {
		return nil, "", fmt.Errorf("invalid URL %q: empty port", rawURL)
	}
	if !strings.HasPrefix(parsedURL.Host, "[") && strings.Count(parsedURL.Host, ":") > 1 {
		return nil, "", fmt.Errorf("invalid URL %q: IPv6 addresses must be enclosed in brackets", rawURL)
	}
	if port := determinePort(parsedURL); port < 1 || port > 65535 {
		return nil, "", fmt.Errorf("invalid URL port %d", port)
	}
	parsedURL.Fragment = ""

	path := parsedURL.RequestURI()
	if path == "" {
		path = "/"
	}
	return parsedURL, path, nil
}

func validateCustomHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", nil
	}

	for _, r := range host {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("invalid CUSTOM_HOST %q: contains whitespace or control characters", host)
		}
	}
	if strings.ContainsAny(host, "/\\@?#") {
		return "", fmt.Errorf("invalid CUSTOM_HOST %q: expected a host name or host:port", host)
	}

	switch {
	case strings.HasPrefix(host, "["):
		end := strings.Index(host, "]")
		if end < 0 {
			return "", fmt.Errorf("invalid CUSTOM_HOST %q: missing closing bracket", host)
		}
		if net.ParseIP(host[1:end]) == nil {
			return "", fmt.Errorf("invalid CUSTOM_HOST %q: invalid IPv6 address", host)
		}
		rest := host[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", fmt.Errorf("invalid CUSTOM_HOST %q", host)
			}
			if err := validatePort(rest[1:]); err != nil {
				return "", fmt.Errorf("invalid CUSTOM_HOST %q: %w", host, err)
			}
		}
	case strings.Count(host, ":") == 1:
		hostPart, portPart, err := net.SplitHostPort(host)
		if err != nil || hostPart == "" {
			return "", fmt.Errorf("invalid CUSTOM_HOST %q: expected host or host:port", host)
		}
		if err := validatePort(portPart); err != nil {
			return "", fmt.Errorf("invalid CUSTOM_HOST %q: %w", host, err)
		}
	case strings.Count(host, ":") > 1:
		// Bare IPv6 address: bracket it for use in a Host header.
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("invalid CUSTOM_HOST %q: invalid host name", host)
		}
		host = "[" + host + "]"
	}

	return host, nil
}

func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

func determinePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if i, err := strconv.Atoi(p); err == nil {
			return i
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

// ─── Randomisation helpers ────────────────────────────────────────────────────

// generateUserAgent produces a realistic UA from one of five browser/platform families.
func generateUserAgent() string {
	switch rand.IntN(10) {
	case 0, 1, 2, 3, 4: // 50% Chrome desktop
		return generateChromeDesktopUA()
	case 5, 6: // 20% Firefox desktop
		return generateFirefoxDesktopUA()
	case 7: // 10% Safari macOS
		return generateSafariDesktopUA()
	case 8: // 10% Chrome Android
		return generateChromeAndroidUA()
	default: // 10% Safari iOS
		return generateSafariIOSUA()
	}
}

func generateChromeDesktopUA() string {
	osList := []string{
		"Windows NT 10.0; Win64; x64",
		"Macintosh; Intel Mac OS X 10_15_7",
		"X11; Linux x86_64",
	}
	os := osList[rand.IntN(len(osList))]
	major := rand.IntN(14) + 140 // v140–v153
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36",
		os, major)
}

func generateFirefoxDesktopUA() string {
	osList := []string{
		"Windows NT 10.0; Win64; x64",
		"Macintosh; Intel Mac OS X 10.15",
		"X11; Linux x86_64",
		"X11; Ubuntu; Linux x86_64",
	}
	os := osList[rand.IntN(len(osList))]
	major := rand.IntN(13) + 140 // v140–v152
	return fmt.Sprintf("Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0", os, major, major)
}

func generateSafariDesktopUA() string {
	macVersions := []string{"10_15_7", "13_6_1", "14_6_1", "15_3_1"}
	mac := macVersions[rand.IntN(len(macVersions))]
	major := 18 + rand.IntN(2) // v18–v19
	return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X %s) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%d.%d Safari/605.1.15",
		mac, major, rand.IntN(7))
}

func generateChromeAndroidUA() string {
	// Chrome's reduced Android UA reports Android 10 and the device model as K.
	major := rand.IntN(14) + 140 // v140–v153
	return fmt.Sprintf("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/537.36",
		major)
}

func generateSafariIOSUA() string {
	versions := []string{
		"iPhone; CPU iPhone OS 18_6 like Mac OS X",
		"iPhone; CPU iPhone OS 19_0 like Mac OS X",
		"iPhone; CPU iPhone OS 19_2 like Mac OS X",
		"iPad; CPU OS 18_6 like Mac OS X",
		"iPad; CPU OS 19_0 like Mac OS X",
	}
	builds := []string{"604.1", "605.1.15"}
	v := versions[rand.IntN(len(versions))]
	sb := builds[rand.IntN(len(builds))]
	major := 18 + rand.IntN(2) // v18–v19
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%d.%d Mobile/15E148 Safari/%s",
		v, major, rand.IntN(7), sb)
}

// chromeMajorFromUA extracts the major version from a Chrome/xxx.y.z UA.
func chromeMajorFromUA(ua string) string {
	const marker = "Chrome/"
	i := strings.Index(ua, marker)
	if i < 0 {
		return "120"
	}
	rest := ua[i+len(marker):]
	if j := strings.IndexAny(rest, ". "); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" {
		return "120"
	}
	return rest
}

// platformFromUA keeps Sec-CH-UA-Platform consistent with the UA string.
func platformFromUA(ua string) string {
	switch {
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Mac OS X"):
		return "macOS"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "CPU OS"):
		return "iOS"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		return "Linux"
	default:
		return "Windows"
	}
}

const alphaLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func writeRandomAlpha(b *bytes.Buffer, n int) {
	for i := 0; i < n; i++ {
		b.WriteByte(alphaLetters[rand.IntN(len(alphaLetters))])
	}
}

// createFormBody writes a URL-encoded form submission body, as a browser would
// send for a form POST.
func createFormBody(b *bytes.Buffer) {
	for i := 0; i < 3; i++ {
		if i > 0 {
			b.WriteByte('&')
		}
		if rand.IntN(100) < 70 {
			switch rand.IntN(3) {
			case 0:
				b.WriteString("username=")
				writeRandomAlpha(b, 8)
			case 1:
				b.WriteString("email=")
				writeRandomAlpha(b, 6)
				b.WriteString("%40example.com")
			default:
				writeRandomAlpha(b, 5)
				b.WriteByte('=')
				writeRandomAlpha(b, 8)
			}
		} else {
			writeRandomAlpha(b, 5)
			b.WriteByte('=')
			writeRandomAlpha(b, 8)
		}
	}
}
