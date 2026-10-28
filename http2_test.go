package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func TestH2StartupFrames(t *testing.T) {
	tests := []struct {
		kind         fingerprintKind
		wantSettings []http2.Setting
		wantWU       uint32
		wantPriority int
	}{
		{
			kind: fpChrome,
			wantSettings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingEnablePush, Val: 0},
				{ID: http2.SettingInitialWindowSize, Val: 6291456},
				{ID: http2.SettingMaxHeaderListSize, Val: 262144},
			},
			wantWU:       15663105,
			wantPriority: 0,
		},
		{
			kind: fpFirefox,
			wantSettings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingInitialWindowSize, Val: 131072},
				{ID: http2.SettingMaxFrameSize, Val: 16384},
			},
			wantWU:       12517377,
			wantPriority: 6,
		},
		{
			kind: fpSafari,
			wantSettings: []http2.Setting{
				{ID: http2.SettingEnablePush, Val: 0},
				{ID: http2.SettingMaxConcurrentStreams, Val: 100},
				{ID: http2.SettingInitialWindowSize, Val: 2097152},
				{ID: http2.SettingEnableConnectProtocol, Val: 1},
				{ID: http2.SettingNoRFC7540Priorities, Val: 1},
			},
			wantWU:       10420225,
			wantPriority: 0,
		},
	}

	for _, tt := range tests {
		t.Run(fingerprintName(tt.kind), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			type result struct {
				err error
			}
			ch := make(chan result, 1)
			go func() {
				_, err := newH2Client(client, h2ProfileFor(tt.kind), false)
				ch <- result{err: err}
			}()

			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(server, preface); err != nil {
				t.Fatal(err)
			}
			if string(preface) != http2.ClientPreface {
				t.Fatalf("preface = %q", preface)
			}

			fr := http2.NewFramer(io.Discard, server)
			frame, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			sf, ok := frame.(*http2.SettingsFrame)
			if !ok {
				t.Fatalf("first frame = %T, want SETTINGS", frame)
			}
			if sf.NumSettings() != len(tt.wantSettings) {
				t.Fatalf("settings count = %d, want %d", sf.NumSettings(), len(tt.wantSettings))
			}
			for i, want := range tt.wantSettings {
				if got := sf.Setting(i); got != want {
					t.Errorf("setting %d = %+v, want %+v", i, got, want)
				}
			}

			frame, err = fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			wu, ok := frame.(*http2.WindowUpdateFrame)
			if !ok || wu.StreamID != 0 || wu.Increment != tt.wantWU {
				t.Fatalf("window update = %#v, want stream 0 increment %d", frame, tt.wantWU)
			}

			for i := 0; i < tt.wantPriority; i++ {
				frame, err = fr.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := frame.(*http2.PriorityFrame); !ok {
					t.Fatalf("frame %d after WINDOW_UPDATE = %T, want PRIORITY", i, frame)
				}
			}

			res := <-ch
			if res.err != nil {
				t.Fatal(res.err)
			}
			if tt.wantPriority == 0 {
				// No more startup frames should be pending. A read deadline
				// keeps the synchronous pipe from blocking forever.
				_ = server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				if _, err := fr.ReadFrame(); err == nil {
					t.Fatal("unexpected extra startup frame")
				}
				_ = server.SetReadDeadline(time.Time{})
			}
		})
	}
}

func TestH2PseudoHeaderOrder(t *testing.T) {
	u, path, err := parseTarget("https://example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:      u,
		Port:        determinePort(u),
		Path:        path,
		HTTP2:       true,
		Fingerprint: "chrome",
	}
	cfg.session = newBrowserSessionFor("chrome")

	fields, _ := buildH2Request(cfg, "GET", "example.com")
	if len(fields) < 4 {
		t.Fatalf("only %d header fields", len(fields))
	}
	want := []string{":method", ":authority", ":scheme", ":path"}
	for i, name := range want {
		if fields[i].Name != name {
			t.Errorf("field %d = %q, want %q", i, fields[i].Name, name)
		}
	}
	if fields[1].Value != "example.com" || fields[3].Value != "/app" {
		t.Errorf("authority/path = %q/%q", fields[1].Value, fields[3].Value)
	}

	// Firefox uses m,p,a,s.
	cfg.session = newBrowserSessionFor("firefox")
	fields, _ = buildH2Request(cfg, "GET", "example.com")
	want = []string{":method", ":path", ":authority", ":scheme"}
	for i, name := range want {
		if fields[i].Name != name {
			t.Errorf("firefox field %d = %q, want %q", i, fields[i].Name, name)
		}
	}
}

func fingerprintName(kind fingerprintKind) string {
	switch kind {
	case fpChrome:
		return "chrome"
	case fpFirefox:
		return "firefox"
	case fpSafari:
		return "safari"
	case fpIOS:
		return "ios"
	default:
		return "none"
	}
}

func TestH2Profiles(t *testing.T) {
	chrome := h2ProfileFor(fpChrome)
	if chrome.pseudoOrder != "masp" {
		t.Errorf("Chrome pseudo order = %q, want masp", chrome.pseudoOrder)
	}
	if chrome.windowUpdate != 15663105 {
		t.Errorf("Chrome window update = %d", chrome.windowUpdate)
	}
	if len(chrome.settings) != 4 ||
		chrome.settings[0].ID != http2.SettingHeaderTableSize || chrome.settings[0].Val != 65536 ||
		chrome.settings[1].ID != http2.SettingEnablePush || chrome.settings[1].Val != 0 ||
		chrome.settings[2].ID != http2.SettingInitialWindowSize || chrome.settings[2].Val != 6291456 ||
		chrome.settings[3].ID != http2.SettingMaxHeaderListSize || chrome.settings[3].Val != 262144 {
		t.Errorf("unexpected Chrome settings: %+v", chrome.settings)
	}

	firefox := h2ProfileFor(fpFirefox)
	if firefox.pseudoOrder != "mpas" {
		t.Errorf("Firefox pseudo order = %q, want mpas", firefox.pseudoOrder)
	}
	if firefox.windowUpdate != 12517377 {
		t.Errorf("Firefox window update = %d", firefox.windowUpdate)
	}
	if len(firefox.priorities) != 6 {
		t.Errorf("Firefox priorities = %d, want 6", len(firefox.priorities))
	}
	if len(firefox.settings) != 3 ||
		firefox.settings[0].ID != http2.SettingHeaderTableSize ||
		firefox.settings[1].ID != http2.SettingInitialWindowSize ||
		firefox.settings[2].ID != http2.SettingMaxFrameSize {
		t.Errorf("unexpected Firefox settings: %+v", firefox.settings)
	}

	safari := h2ProfileFor(fpSafari)
	if safari.pseudoOrder != "msap" {
		t.Errorf("Safari pseudo order = %q, want msap", safari.pseudoOrder)
	}
	if safari.windowUpdate != 10420225 {
		t.Errorf("Safari window update = %d", safari.windowUpdate)
	}
}

func TestFingerprintMapping(t *testing.T) {
	tests := []struct {
		ua    string
		kind  fingerprintKind
		hello utls.ClientHelloID
	}{
		{
			ua:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
			kind:  fpChrome,
			hello: utls.HelloChrome_133,
		},
		{
			ua:    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
			kind:  fpFirefox,
			hello: utls.HelloFirefox_120,
		},
		{
			ua:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
			kind:  fpSafari,
			hello: utls.HelloSafari_16_0,
		},
		{
			ua:    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/605.1.15",
			kind:  fpIOS,
			hello: utls.HelloIOS_14,
		},
	}

	for _, tt := range tests {
		p := makeUAProfile(tt.ua)
		fp := fingerprintForConfig(StressConfig{Fingerprint: "rotate", session: &browserSession{profile: p}})
		if fp.kind != tt.kind {
			t.Errorf("%q kind = %v, want %v", tt.ua, fp.kind, tt.kind)
		}
		if fp.hello != tt.hello {
			t.Errorf("%q ClientHello = %v, want %v", tt.ua, fp.hello, tt.hello)
		}
	}

	none := fingerprintForConfig(StressConfig{Fingerprint: "none"})
	if none.kind != fpNone {
		t.Errorf("fingerprint none kind = %v, want fpNone", none.kind)
	}
}

func newTestH2Server(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func TestHTTP2ALPNNegotiated(t *testing.T) {
	ts := newTestH2Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "h2")
	}))

	u, path, err := parseTarget(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:      u,
		Port:        determinePort(u),
		Path:        path,
		HTTP2:       true,
		Fingerprint: "chrome",
	}
	cfg.session = newBrowserSessionFor("chrome")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialConnSession(ctx, ts.Listener.Addr().String(), true, cfg, requestServerName(cfg))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if !isHTTP2Conn(conn) {
		t.Fatal("server did not negotiate h2")
	}
	if got := conn.(alpnConn).NegotiatedProtocol(); got != http2.NextProtoTLS {
		t.Errorf("ALPN = %q, want h2", got)
	}
}

func TestHTTP2ServeConnection(t *testing.T) {
	var hits atomic.Int64
	ts := newTestH2Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method == "POST" {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello over h2")
	}))

	u, path, err := parseTarget(ts.URL + "/h2?x=1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:      u,
		Port:        determinePort(u),
		Path:        path,
		HTTP2:       true,
		Fingerprint: "chrome",
		RotateEvery: 8,
	}
	cfg.session = newBrowserSessionFor("chrome")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialConnSession(ctx, ts.Listener.Addr().String(), true, cfg, requestServerName(cfg))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	var m Metrics
	completed, err := h2ServeConnection(ctx, cfg, conn, fingerprintForConfig(cfg), requestHost(cfg), &m)
	if err != nil {
		t.Fatalf("h2ServeConnection: %v", err)
	}
	if completed != 8 {
		t.Errorf("completed = %d, want 8", completed)
	}
	s := m.snapshot()
	if s.responses != 8 || s.status2xx != 8 {
		t.Errorf("metrics = %+v, want 8 2xx", s)
	}
	if hits.Load() != 8 {
		t.Errorf("server hits = %d, want 8", hits.Load())
	}
}

func TestHTTP2SendOnlyConnection(t *testing.T) {
	var hits atomic.Int64
	ts := newTestH2Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method == "POST" {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		_, _ = io.WriteString(w, "ok")
	}))

	u, path, err := parseTarget(ts.URL + "/send")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:      u,
		Port:        determinePort(u),
		Path:        path,
		SendOnly:    true,
		HTTP2:       true,
		Fingerprint: "chrome",
		RotateEvery: 12,
	}
	cfg.session = newBrowserSessionFor("chrome")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialConnSession(ctx, ts.Listener.Addr().String(), true, cfg, requestServerName(cfg))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	var m Metrics
	m.sendOnly = true
	sent, err := h2SendOnlyConnection(ctx, cfg, conn, fingerprintForConfig(cfg), requestHost(cfg), &m)
	if err != nil {
		t.Fatalf("h2SendOnlyConnection: %v", err)
	}
	if sent != 12 {
		t.Errorf("sent = %d, want 12", sent)
	}
	if s := m.snapshot(); s.sent != 12 || s.responses != 0 {
		t.Errorf("metrics = %+v, want sent=12 responses=0", s)
	}

	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Error("server received no HTTP/2 requests")
	}
}

func TestHTTP2DisabledUsesHTTP1(t *testing.T) {
	ts := newTestH2Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "h2-disabled")
	}))

	u, path, err := parseTarget(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:      u,
		Port:        determinePort(u),
		Path:        path,
		HTTP2:       false,
		Fingerprint: "chrome",
	}
	cfg.session = newBrowserSessionFor("chrome")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialConnSession(ctx, ts.Listener.Addr().String(), true, cfg, requestServerName(cfg))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if isHTTP2Conn(conn) {
		t.Fatal("HTTP/2 negotiated even though --http2=false")
	}

	var m Metrics
	completed, _ := serveConnection(ctx, cfg, conn, requestHost(cfg), &m)
	if completed == 0 {
		t.Fatal("completed no HTTP/1.1 requests")
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
}

func TestHTTP2AllProfiles(t *testing.T) {
	ts := newTestH2Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		_, _ = io.WriteString(w, "profile-ok")
	}))

	for _, mode := range []string{"chrome", "firefox", "safari", "ios"} {
		t.Run(mode, func(t *testing.T) {
			u, path, err := parseTarget(ts.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			cfg := StressConfig{
				Target:      u,
				Port:        determinePort(u),
				Path:        path,
				HTTP2:       true,
				Fingerprint: mode,
				RotateEvery: 3,
			}
			cfg.session = newBrowserSessionFor(mode)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialConnSession(ctx, ts.Listener.Addr().String(), true, cfg, requestServerName(cfg))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			if !isHTTP2Conn(conn) {
				t.Fatal("server did not negotiate h2")
			}

			var m Metrics
			completed, err := h2ServeConnection(ctx, cfg, conn, fingerprintForConfig(cfg), requestHost(cfg), &m)
			if err != nil {
				t.Fatalf("h2ServeConnection: %v", err)
			}
			if completed != 3 {
				t.Errorf("completed = %d, want 3", completed)
			}
			if s := m.snapshot(); s.status2xx != 3 {
				t.Errorf("2xx = %d, want 3", s.status2xx)
			}
		})
	}
}

func TestHTTP2ThroughHTTPProxy(t *testing.T) {
	var hits atomic.Int64
	target := newTestH2Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "proxied h2")
	}))
	proxySrv := newTestProxy(t)

	u, path, err := parseTarget(target.URL + "/proxied")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:      u,
		Port:        determinePort(u),
		Path:        path,
		ProxyType:   "http",
		HTTP2:       true,
		Fingerprint: "chrome",
		RotateEvery: 5,
	}
	cfg.session = newBrowserSessionFor("chrome")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialViaProxy(ctx, proxySrv.Listener.Addr().String(), cfg, newTLSConfig(requestServerName(cfg)))
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}
	defer conn.Close()

	if !isHTTP2Conn(conn) {
		t.Fatal("target did not negotiate h2 through the HTTP proxy")
	}

	var m Metrics
	completed, err := h2ServeConnection(ctx, cfg, conn, fingerprintForConfig(cfg), requestHost(cfg), &m)
	if err != nil {
		t.Fatalf("h2ServeConnection: %v", err)
	}
	if completed != 5 {
		t.Errorf("completed = %d, want 5", completed)
	}
	if s := m.snapshot(); s.status2xx != int64(completed) {
		t.Errorf("2xx = %d, completed = %d", s.status2xx, completed)
	}
	if hits.Load() != 5 {
		t.Errorf("target hits = %d, want 5", hits.Load())
	}
}

func TestHTTP2ThroughSOCKS5(t *testing.T) {
	var hits atomic.Int64
	target := newTestH2Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "socks h2")
	}))

	u, path, err := parseTarget(target.URL + "/socks")
	if err != nil {
		t.Fatal(err)
	}
	cfg := StressConfig{
		Target:      u,
		Port:        determinePort(u),
		Path:        path,
		ProxyType:   "sock5",
		HTTP2:       true,
		Fingerprint: "chrome",
		RotateEvery: 3,
	}
	cfg.session = newBrowserSessionFor("chrome")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialViaProxy(ctx, startTestSOCKS5(t), cfg, newTLSConfig(requestServerName(cfg)))
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}
	defer conn.Close()
	if !isHTTP2Conn(conn) {
		t.Fatal("target did not negotiate h2 through SOCKS5")
	}

	var m Metrics
	completed, err := h2ServeConnection(ctx, cfg, conn, fingerprintForConfig(cfg), requestHost(cfg), &m)
	if err != nil {
		t.Fatalf("h2ServeConnection: %v", err)
	}
	if completed != 3 {
		t.Errorf("completed = %d, want 3", completed)
	}
	if hits.Load() != 3 {
		t.Errorf("target hits = %d, want 3", hits.Load())
	}
}

func TestProxyRotatorRoundRobin(t *testing.T) {
	r := newProxyRotator([]string{"a:1", "b:2", "c:3"}, "round-robin")
	seen := make(map[string]bool)
	for i := 0; i < 3; i++ {
		seen[r.pick(0)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("round-robin used %d distinct proxies, want 3: %v", len(seen), seen)
	}
}

func TestProxyRotatorSticky(t *testing.T) {
	r := newProxyRotator([]string{"a:1", "b:2", "c:3"}, "sticky")
	if got := r.pick(1); got != "b:2" {
		t.Errorf("sticky pick = %q, want b:2", got)
	}
	if got := r.pick(1); got != "b:2" {
		t.Errorf("sticky pick = %q, want b:2", got)
	}
}

func TestProxyRotatorSkipsFailedProxy(t *testing.T) {
	r := newProxyRotator([]string{"a:1", "b:2", "c:3"}, "round-robin")
	r.markFailure("a:1")
	for i := 0; i < 4; i++ {
		if got := r.pick(0); got == "a:1" {
			t.Fatal("failed proxy was selected during cooldown")
		}
	}
	r.markSuccess("a:1")
}
