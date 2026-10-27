package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(t *testing.T, rawURL, customHost string) StressConfig {
	t.Helper()
	u, path, err := parseTarget(rawURL)
	if err != nil {
		t.Fatalf("parseTarget(%q): %v", rawURL, err)
	}
	customHost, err = validateCustomHost(customHost)
	if err != nil {
		t.Fatalf("validateCustomHost(%q): %v", customHost, err)
	}
	return StressConfig{
		Target:     u,
		Port:       determinePort(u),
		Path:       path,
		CustomHost: customHost,
	}
}

func TestRequestHost(t *testing.T) {
	tests := []struct {
		rawURL     string
		customHost string
		want       string
	}{
		{"http://example.com/", "", "example.com"},
		{"https://example.com:8443/", "", "example.com:8443"},
		{"https://example.com:8443/", "site.test", "site.test:8443"},
		{"https://example.com/", "site.test:9000", "site.test:9000"},
		{"http://example.com:443/", "", "example.com:443"},
		{"https://[::1]:8443/", "", "[::1]:8443"},
		{"https://example.com:8443/", "[::1]", "[::1]:8443"},
	}
	for _, tt := range tests {
		cfg := testConfig(t, tt.rawURL, tt.customHost)
		if got := requestHost(cfg); got != tt.want {
			t.Errorf("requestHost(%q, %q) = %q, want %q", tt.rawURL, tt.customHost, got, tt.want)
		}
	}
}

func TestRequestServerName(t *testing.T) {
	tests := []struct {
		rawURL     string
		customHost string
		want       string
	}{
		{"https://example.com/", "", "example.com"},
		{"https://example.com:8443/", "site.test:9000", "site.test"},
		{"https://example.com:8443/", "[::1]:8443", "::1"},
		{"https://[::1]:8443/", "", "::1"},
	}
	for _, tt := range tests {
		cfg := testConfig(t, tt.rawURL, tt.customHost)
		if got := requestServerName(cfg); got != tt.want {
			t.Errorf("requestServerName(%q, %q) = %q, want %q", tt.rawURL, tt.customHost, got, tt.want)
		}
	}
}

func TestBuildRequestOriginForm(t *testing.T) {
	cfg := testConfig(t, "https://example.com:8443/app?x=1#fragment", "site.test")
	cfg.CacheBust = true
	var buf, body bytes.Buffer
	buildRequest(&buf, cfg, "GET", requestHost(cfg), &body)

	raw := buf.String()
	if strings.Contains(raw, "#fragment") {
		t.Fatalf("request contains URL fragment: %q", raw)
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadRequest: %v\n%s", err, raw)
	}
	if req.Method != "GET" {
		t.Errorf("method = %q, want GET", req.Method)
	}
	if req.Host != "site.test:8443" {
		t.Errorf("Host = %q, want site.test:8443", req.Host)
	}
	if req.Proto != "HTTP/1.1" {
		t.Errorf("proto = %q, want HTTP/1.1", req.Proto)
	}
	if req.URL.Path != "/app" {
		t.Errorf("path = %q, want /app", req.URL.Path)
	}
	if req.URL.Query().Get("x") != "1" {
		t.Errorf("query x = %q, want 1", req.URL.Query().Get("x"))
	}
	if len(req.URL.Query()) < 2 {
		t.Errorf("expected a cache-busting query parameter, got %v", req.URL.Query())
	}
	if req.Header.Get("Connection") != "keep-alive" {
		t.Errorf("Connection = %q, want keep-alive", req.Header.Get("Connection"))
	}
}

func TestBuildRequestNoCacheBustByDefault(t *testing.T) {
	cfg := testConfig(t, "http://example.com/app?x=1", "")
	var buf bytes.Buffer
	buildRequest(&buf, cfg, "GET", requestHost(cfg), nil)

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got := req.URL.Query(); len(got) != 1 || got.Get("x") != "1" {
		t.Errorf("query = %v, want only x=1 (no cache-busting by default)", got)
	}
}

func TestBuildRequestAbsoluteFormThroughHTTPProxy(t *testing.T) {
	cfg := testConfig(t, "http://example.com:8080/app?x=1#fragment", "")
	cfg.ProxyType = "http"
	var buf bytes.Buffer
	buildRequest(&buf, cfg, "GET", requestHost(cfg), nil)

	raw := buf.String()
	if strings.Contains(raw, "#fragment") {
		t.Fatalf("request contains URL fragment: %q", raw)
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadRequest: %v\n%s", err, raw)
	}
	if !req.URL.IsAbs() {
		t.Errorf("request URI is not absolute-form: %q", req.RequestURI)
	}
	if req.URL.Scheme != "http" || req.URL.Host != "example.com:8080" {
		t.Errorf("URL = %s, want http://example.com:8080", req.URL)
	}
	if req.Host != "example.com:8080" {
		t.Errorf("Host = %q, want example.com:8080", req.Host)
	}
	if req.URL.Fragment != "" {
		t.Errorf("fragment = %q, want empty", req.URL.Fragment)
	}
}

func TestBuildRequestAbsoluteFormNoPath(t *testing.T) {
	cfg := testConfig(t, "http://example.com", "")
	cfg.ProxyType = "http"
	cfg.CacheBust = true
	var buf bytes.Buffer
	buildRequest(&buf, cfg, "GET", requestHost(cfg), nil)

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if !req.URL.IsAbs() || req.URL.Host != "example.com" {
		t.Errorf("URL = %s, want absolute http://example.com", req.URL)
	}
	if req.URL.Path != "/" {
		t.Errorf("path = %q, want /", req.URL.Path)
	}
	if len(req.URL.Query()) == 0 {
		t.Error("expected a cache-busting query parameter")
	}
}

func TestBuildRequestHTTPSProxyUsesOriginForm(t *testing.T) {
	cfg := testConfig(t, "https://example.com:8443/app", "")
	cfg.ProxyType = "http"
	var buf bytes.Buffer
	buildRequest(&buf, cfg, "GET", requestHost(cfg), nil)

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if req.URL.IsAbs() {
		t.Errorf("HTTPS request through CONNECT should use origin-form, got %q", req.RequestURI)
	}
	if req.Host != "example.com:8443" {
		t.Errorf("Host = %q, want example.com:8443", req.Host)
	}
}

func testChromeSession() *browserSession {
	for i := range uaProfiles {
		if uaProfiles[i].chrome {
			return &browserSession{
				profile:      uaProfiles[i],
				language:     languages[0],
				cookieHeader: "Cookie: _ga=GA1.2.111.222; _gid=GA1.2.333.444\r\n",
			}
		}
	}
	return nil
}

func TestBrowserSessionConsistency(t *testing.T) {
	sess := testChromeSession()
	if sess == nil {
		t.Fatal("no Chrome profile generated")
	}
	cfg := testConfig(t, "https://example.com/app", "")
	cfg.session = sess

	var reqs []*http.Request
	for i := 0; i < 2; i++ {
		var buf bytes.Buffer
		buildRequest(&buf, cfg, "GET", requestHost(cfg), nil)
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
		if err != nil {
			t.Fatalf("ReadRequest: %v", err)
		}
		reqs = append(reqs, req)
	}

	first, second := reqs[0], reqs[1]
	if first.UserAgent() != second.UserAgent() {
		t.Errorf("UA changed between requests: %q vs %q", first.UserAgent(), second.UserAgent())
	}
	if first.Header.Get("Accept-Language") != second.Header.Get("Accept-Language") {
		t.Error("Accept-Language changed between requests")
	}
	if first.Header.Get("Cookie") != second.Header.Get("Cookie") {
		t.Error("Cookie changed between requests")
	}
	if first.Header.Get("Cookie") == "" {
		t.Error("expected the session cookie to be sent")
	}
	if first.Header.Get("X-Forwarded-For") != "" {
		t.Error("browser-like requests must not send X-Forwarded-For by default")
	}
	if first.Header.Get("Cache-Control") != "" || first.Header.Get("Pragma") != "" {
		t.Error("browser-like requests must not send forced no-cache headers")
	}

	req := first
	major := sess.profile.chromeMajor
	if !strings.Contains(req.UserAgent(), "Chrome/"+major+".") {
		t.Errorf("UA %q does not match Chrome major %s", req.UserAgent(), major)
	}
	if ch := req.Header.Get("sec-ch-ua"); !strings.Contains(ch, `v="`+major+`"`) {
		t.Errorf("sec-ch-ua %q does not match Chrome major %s", ch, major)
	}
	wantMobile := "?0"
	if sess.profile.mobile {
		wantMobile = "?1"
	}
	if got := req.Header.Get("sec-ch-ua-mobile"); got != wantMobile {
		t.Errorf("sec-ch-ua-mobile = %q, want %q", got, wantMobile)
	}
	if got := req.Header.Get("sec-ch-ua-platform"); got != `"`+sess.profile.platform+`"` {
		t.Errorf("sec-ch-ua-platform = %q, want %q", got, sess.profile.platform)
	}

	site := req.Header.Get("Sec-Fetch-Site")
	referer := req.Referer()
	switch site {
	case "none":
		if referer != "" {
			t.Errorf("Sec-Fetch-Site none but Referer = %q", referer)
		}
	case "same-origin":
		if !strings.HasPrefix(referer, "https://example.com") {
			t.Errorf("same-origin Referer = %q", referer)
		}
	case "cross-site":
		if referer == "" {
			t.Error("cross-site request missing Referer")
		}
	default:
		t.Errorf("unexpected Sec-Fetch-Site %q", site)
	}
	if req.Header.Get("Sec-Fetch-Mode") != "navigate" ||
		req.Header.Get("Sec-Fetch-Dest") != "document" ||
		req.Header.Get("Sec-Fetch-User") != "?1" ||
		req.Header.Get("Upgrade-Insecure-Requests") != "1" {
		t.Errorf("incoherent navigation headers: %v", req.Header)
	}
}

func TestBuildRequestPOSTBrowserHeaders(t *testing.T) {
	cfg := testConfig(t, "http://example.com:8080/submit", "")
	cfg.session = testChromeSession()
	var buf, body bytes.Buffer
	buildRequest(&buf, cfg, "POST", requestHost(cfg), &body)

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := req.Header.Get("Origin"); got != "http://example.com:8080" {
		t.Errorf("Origin = %q", got)
	}
	if got := req.Referer(); got != "http://example.com:8080/submit" {
		t.Errorf("Referer = %q", got)
	}
	if req.Header.Get("Sec-Fetch-Site") != "same-origin" ||
		req.Header.Get("Sec-Fetch-Mode") != "navigate" ||
		req.Header.Get("Sec-Fetch-Dest") != "document" ||
		req.Header.Get("Sec-Fetch-User") != "?1" {
		t.Errorf("incoherent form POST headers: %v", req.Header)
	}
	if req.ContentLength != int64(body.Len()) || body.Len() == 0 {
		t.Errorf("bad form body length: Content-Length=%d body=%d", req.ContentLength, body.Len())
	}
}

func TestBuildRequestHEADFetchHeaders(t *testing.T) {
	cfg := testConfig(t, "https://example.com/page", "")
	cfg.session = testChromeSession()
	var buf bytes.Buffer
	buildRequest(&buf, cfg, "HEAD", requestHost(cfg), nil)

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got := req.Header.Get("Accept"); got != "*/*" {
		t.Errorf("Accept = %q, want */*", got)
	}
	if req.Header.Get("Sec-Fetch-Site") != "same-origin" ||
		req.Header.Get("Sec-Fetch-Mode") != "cors" ||
		req.Header.Get("Sec-Fetch-Dest") != "empty" {
		t.Errorf("incoherent fetch HEAD headers: %v", req.Header)
	}
	if req.Header.Get("Sec-Fetch-User") != "" || req.Header.Get("Upgrade-Insecure-Requests") != "" {
		t.Errorf("HEAD fetch should not have navigation headers: %v", req.Header)
	}
	if got := req.Referer(); got != "https://example.com/page" {
		t.Errorf("Referer = %q", got)
	}
	if req.Header.Get("Origin") != "" {
		t.Errorf("HEAD fetch should not have Origin")
	}
}

func TestBuildRequestXFFOptional(t *testing.T) {
	cfg := testConfig(t, "http://example.com/", "")
	var buf bytes.Buffer
	buildRequest(&buf, cfg, "GET", requestHost(cfg), nil)
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "" {
		t.Errorf("default X-Forwarded-For = %q, want empty", got)
	}

	cfg.XFF = true
	buf.Reset()
	buildRequest(&buf, cfg, "GET", requestHost(cfg), nil)
	req, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Forwarded-For"); got == "" {
		t.Error("--xff did not add X-Forwarded-For")
	}
}

func TestBuildRequestPOST(t *testing.T) {
	cfg := testConfig(t, "http://example.com:8080/submit", "")
	var buf, body bytes.Buffer
	buildRequest(&buf, cfg, "POST", requestHost(cfg), &body)

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.ContentLength != int64(body.Len()) {
		t.Errorf("Content-Length = %d, want %d", req.ContentLength, body.Len())
	}
	if body.Len() == 0 {
		t.Error("POST body is empty")
	}
	gotBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read POST body: %v", err)
	}
	if !bytes.Equal(gotBody, body.Bytes()) {
		t.Errorf("body mismatch: got %q, want %q", gotBody, body.Bytes())
	}
	if got := req.Header.Get("Origin"); got != "http://example.com:8080" {
		t.Errorf("Origin = %q, want http://example.com:8080", got)
	}
	if req.URL.Path != "/submit" {
		t.Errorf("path = %q, want /submit (POST must not be cache-busted)", req.URL.Path)
	}
}

func TestBuildSendBatch(t *testing.T) {
	cfg := testConfig(t, "http://example.com/api?x=1", "")
	var batch, body bytes.Buffer
	const want = 8
	n := buildSendBatch(&batch, &body, cfg, "example.com", want, sendBatchBytes)
	if n != want {
		t.Fatalf("batch requests = %d, want %d", n, want)
	}

	br := bufio.NewReader(bytes.NewReader(batch.Bytes()))
	for i := 0; i < n; i++ {
		req, err := http.ReadRequest(br)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if req.Host != "example.com" {
			t.Errorf("request %d Host = %q", i, req.Host)
		}
		if req.URL.Path != "/api" {
			t.Errorf("request %d path = %q", i, req.URL.Path)
		}
		if req.URL.Query().Get("x") != "1" {
			t.Errorf("request %d missing x=1", i)
		}
		if _, err := io.Copy(io.Discard, req.Body); err != nil {
			t.Fatalf("request %d body: %v", i, err)
		}
		_ = req.Body.Close()
	}
	if _, err := br.Peek(1); err != io.EOF {
		t.Fatalf("batch has trailing bytes or read error: %v", err)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		raw     string
		wantErr bool
	}{
		{"http://example.com/path?x=1", false},
		{"HTTPS://example.com/", false},
		{"ftp://example.com/", true},
		{"http://", true},
		{"http://user:pass@example.com/", true},
		{"http://example.com:0/", true},
		{"http://example.com:99999/", true},
		{"http://example.com:/", true},
		{"http://[::1]:/", true},
		{"not a url", true},
	}
	for _, tt := range tests {
		u, path, err := parseTarget(tt.raw)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseTarget(%q) expected error, got URL=%v path=%q", tt.raw, u, path)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTarget(%q): %v", tt.raw, err)
			continue
		}
		if u.Fragment != "" {
			t.Errorf("parseTarget(%q) kept fragment %q", tt.raw, u.Fragment)
		}
		if path == "" {
			t.Errorf("parseTarget(%q) returned empty path", tt.raw)
		}
	}
}

func TestValidateCustomHost(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{" site.test ", "site.test", false},
		{"example.com:8080", "example.com:8080", false},
		{"[::1]:8080", "[::1]:8080", false},
		{"::1", "[::1]", false},
		{"bad host", "", true},
		{"x\r\nY", "", true},
		{"http://x", "", true},
		{"example.com:99999", "", true},
		{"[::1", "", true},
		{"[example.com]", "", true},
		{"example.com:8080:90", "", true},
	}
	for _, tt := range tests {
		got, err := validateCustomHost(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("validateCustomHost(%q) expected error, got %q", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("validateCustomHost(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("validateCustomHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMetricsStatusClasses(t *testing.T) {
	var m Metrics
	m.recordResponse(200, 10*time.Millisecond)
	m.recordResponse(301, 20*time.Millisecond)
	m.recordResponse(404, 30*time.Millisecond)
	m.recordResponse(500, 40*time.Millisecond)
	m.recordResponse(700, 50*time.Millisecond)
	m.recordSentN(7)

	s := m.snapshot()
	if s.responses != 5 {
		t.Errorf("responses = %d, want 5", s.responses)
	}
	if s.sent != 7 {
		t.Errorf("sent = %d, want 7", s.sent)
	}
	if s.status2xx != 1 || s.status3xx != 1 || s.status4xx != 1 || s.status5xx != 1 || s.statusXXX != 1 {
		t.Errorf("unexpected status counts: %+v", s)
	}
	if got := s.avgLatencyMs(); got != 30 {
		t.Errorf("avg latency = %v ms, want 30", got)
	}
}

func TestServeConnectionCompletesResponses(t *testing.T) {
	var mu sync.Mutex
	var hosts []string
	var posts int

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		if r.Method == "POST" {
			posts++
		}
		mu.Unlock()

		if r.Method == "POST" {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello")
	}))
	defer ts.Close()

	u, path, err := parseTarget(ts.URL + "/test?x=1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target: u,
		Port:   determinePort(u),
		Path:   path,
	}
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var m Metrics
	completed, serveErr := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatalf("completed no requests (err=%v)", serveErr)
	}
	if serveErr == nil {
		t.Fatalf("expected context cancellation, got clean close")
	}

	s := m.snapshot()
	if s.responses != int64(completed) {
		t.Errorf("responses = %d, completed = %d", s.responses, completed)
	}
	if s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
	if s.errors != 0 || s.timeouts != 0 {
		t.Errorf("unexpected transport errors: %+v", s)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(hosts) == 0 {
		t.Fatal("handler saw no requests")
	}
	for _, h := range hosts {
		if h != u.Host {
			t.Fatalf("Host = %q, want %q", h, u.Host)
		}
	}
}

func TestServeConnectionCustomHostAnd5xx(t *testing.T) {
	var mu sync.Mutex
	var hosts []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "unavailable")
	}))
	defer ts.Close()

	u, path, err := parseTarget(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	custom, err := validateCustomHost("load.test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:     u,
		Port:       determinePort(u),
		Path:       path,
		CustomHost: custom,
	}
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no requests")
	}
	if s := m.snapshot(); s.status5xx != int64(completed) {
		t.Errorf("5xx = %d, completed = %d", s.status5xx, completed)
	}

	wantHost := net.JoinHostPort(custom, u.Port())
	mu.Lock()
	defer mu.Unlock()
	for _, h := range hosts {
		if h != wantHost {
			t.Fatalf("Host = %q, want %q", h, wantHost)
		}
	}
}

func TestServeConnectionCleanClose(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "bye")
	}))
	defer ts.Close()

	u, path, err := parseTarget(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{Target: u, Port: determinePort(u), Path: path}
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var m Metrics
	completed, serveErr := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if serveErr != nil {
		t.Fatalf("expected clean close, got %v", serveErr)
	}
	if completed != 1 {
		t.Errorf("completed = %d, want 1", completed)
	}
	if s := m.snapshot(); s.responses != 1 || s.status2xx != 1 {
		t.Errorf("unexpected metrics: %+v", s)
	}
}

func TestDirectTLSOnNonDefaultPort(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secure")
	}))
	defer ts.Close()

	u, path, err := parseTarget(ts.URL + "/secure")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{Target: u, Port: determinePort(u), Path: path}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	conn, err := dialConn(dialCtx, ts.Listener.Addr().String(), true, newTLSConfig(requestServerName(cfg)))
	dialCancel()
	if err != nil {
		t.Fatalf("dialConn TLS: %v", err)
	}

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no requests over direct TLS")
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
}

func TestSendOnlyConnection(t *testing.T) {
	var received atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Method == "POST" {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer ts.Close()

	u, path, err := parseTarget(ts.URL + "/send")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:   u,
		Port:     determinePort(u),
		Path:     path,
		SendOnly: true,
	}
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var m Metrics
	m.sendOnly = true
	sent, _ := sendOnlyConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if sent == 0 {
		t.Fatal("sent no requests")
	}
	if s := m.snapshot(); s.sent != int64(sent) {
		t.Errorf("sent metric = %d, wrote %d requests", s.sent, sent)
	}
	if s := m.snapshot(); s.responses != 0 || s.status2xx != 0 {
		t.Errorf("send-only mode recorded response stats: %+v", s)
	}
	if received.Load() == 0 {
		t.Error("server received no requests")
	}
}
