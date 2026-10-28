// Minimal browser-shaped HTTP/2 client.
//
// This is intentionally not net/http's HTTP/2 transport: that transport sends
// Go's own SETTINGS/WINDOW_UPDATE/priority values, which are a different
// fingerprint from Chrome, Firefox, or Safari. This client writes the
// browser-specific connection preface and a single HEADERS block per request
// with the matching pseudo-header order.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	h2MaxConcurrentStreams = 64
	h2InitialConnWindow    = 65535
	h2EncoderTableLimit    = 65536
	h2MaxHeaderListSize    = 1 << 20
)

var (
	errH2GoAway = errors.New("HTTP/2 GOAWAY received")
	errH2Closed = errors.New("HTTP/2 connection closed")
)

// h2Client owns one HTTP/2 connection. Writes are serialized because Framer
// is not safe for concurrent writers; the send-only reader also writes ACKs
// and WINDOW_UPDATE frames.
type h2Client struct {
	conn    net.Conn
	fr      *http2.Framer
	profile h2Profile

	writeMu sync.Mutex
	enc     *hpack.Encoder
	encBuf  bytes.Buffer

	nextStreamID uint32

	windowMu   sync.Mutex
	sendWindow int64
}

func newH2Client(conn net.Conn, profile h2Profile, readMetaHeaders bool) (*h2Client, error) {
	c := &h2Client{
		conn:         conn,
		profile:      profile,
		nextStreamID: 1,
		sendWindow:   h2InitialConnWindow,
	}
	c.enc = hpack.NewEncoder(&c.encBuf)
	c.enc.SetMaxDynamicTableSizeLimit(h2EncoderTableLimit)
	c.fr = http2.NewFramer(conn, conn)
	if readMetaHeaders {
		c.fr.ReadMetaHeaders = hpack.NewDecoder(h2EncoderTableLimit, nil)
		c.fr.MaxHeaderListSize = h2MaxHeaderListSize
	}

	_ = conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("HTTP/2 preface: %w", err)
	}
	if err := c.writeStartup(); err != nil {
		return nil, err
	}
	_ = conn.SetWriteDeadline(time.Time{})
	return c, nil
}

func (c *h2Client) writeStartup() error {
	return c.writeFrame(func() error {
		if err := c.fr.WriteSettings(c.profile.settings...); err != nil {
			return fmt.Errorf("HTTP/2 SETTINGS: %w", err)
		}
		if c.profile.windowUpdate > 0 {
			if err := c.fr.WriteWindowUpdate(0, c.profile.windowUpdate); err != nil {
				return fmt.Errorf("HTTP/2 WINDOW_UPDATE: %w", err)
			}
		}
		for _, p := range c.profile.priorities {
			if err := c.fr.WritePriority(p.streamID, http2.PriorityParam{
				StreamDep: p.dep,
				Exclusive: p.exclusive,
				Weight:    p.weight,
			}); err != nil {
				return fmt.Errorf("HTTP/2 PRIORITY: %w", err)
			}
		}
		return nil
	})
}

func (c *h2Client) nextStream() uint32 {
	id := c.nextStreamID
	c.nextStreamID += 2
	return id
}

// writeFrame applies a write timeout around one or more Framer writes.
func (c *h2Client) writeFrame(fn func() error) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	err := fn()
	_ = c.conn.SetWriteDeadline(time.Time{})
	return err
}

func (c *h2Client) writeHeaders(streamID uint32, fields []hpack.HeaderField, endStream bool) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.encBuf.Reset()
	for _, f := range fields {
		if err := c.enc.WriteField(f); err != nil {
			return err
		}
	}
	block := c.encBuf.Bytes()
	return c.writeFrame(func() error {
		return c.fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: block,
			EndStream:     endStream,
			EndHeaders:    true,
		})
	})
}

func (c *h2Client) writeData(streamID uint32, data []byte, endStream bool) error {
	if len(data) == 0 {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrame(func() error {
		return c.fr.WriteData(streamID, endStream, data)
	})
}

func (c *h2Client) writeSettingsAck() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrame(func() error { return c.fr.WriteSettingsAck() })
}

func (c *h2Client) writePingAck(data [8]byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrame(func() error { return c.fr.WritePing(true, data) })
}

func (c *h2Client) writeWindowUpdate(streamID, increment uint32) error {
	if increment == 0 {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrame(func() error { return c.fr.WriteWindowUpdate(streamID, increment) })
}

func (c *h2Client) writeRSTStream(streamID uint32, code http2.ErrCode) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrame(func() error { return c.fr.WriteRSTStream(streamID, code) })
}

func (c *h2Client) applyServerSettings(f *http2.SettingsFrame) {
	if v, ok := f.Value(http2.SettingHeaderTableSize); ok {
		c.writeMu.Lock()
		c.enc.SetMaxDynamicTableSize(v)
		c.writeMu.Unlock()
	}
}

func (c *h2Client) addSendWindow(n int64) {
	if n == 0 {
		return
	}
	c.windowMu.Lock()
	c.sendWindow += n
	c.windowMu.Unlock()
}

func (c *h2Client) tryReserveSendWindow(n int) bool {
	if n <= 0 {
		return true
	}
	c.windowMu.Lock()
	defer c.windowMu.Unlock()
	if c.sendWindow < int64(n) {
		return false
	}
	c.sendWindow -= int64(n)
	return true
}

func (c *h2Client) releaseSendWindow(n int) {
	if n <= 0 {
		return
	}
	c.windowMu.Lock()
	c.sendWindow += int64(n)
	c.windowMu.Unlock()
}

// h2Exchange dispatches a negotiated HTTP/2 connection to the matching mode.
func h2Exchange(ctx context.Context, cfg StressConfig, conn net.Conn, hostHdr string, metrics *Metrics) (int, error) {
	fp := fingerprintForConfig(cfg)
	if cfg.SendOnly {
		return h2SendOnlyConnection(ctx, cfg, conn, fp, hostHdr, metrics)
	}
	return h2ServeConnection(ctx, cfg, conn, fp, hostHdr, metrics)
}

// h2ServeConnection performs sequential response-aware HTTP/2 requests.
func h2ServeConnection(ctx context.Context, cfg StressConfig, conn net.Conn, fp sessionFingerprint, hostHdr string, metrics *Metrics) (completed int, err error) {
	stopWatch := watchConn(ctx, conn)
	defer stopWatch()
	// A GOAWAY after at least one completed request is a normal connection
	// shutdown, not a transport failure.
	defer func() {
		if errors.Is(err, errH2GoAway) && completed > 0 {
			err = nil
		}
	}()

	c, err := newH2Client(conn, fp.h2, true)
	if err != nil {
		return 0, err
	}

	for {
		if ctx.Err() != nil {
			return completed, ctx.Err()
		}

		method := httpMethods[rand.IntN(len(httpMethods))]
		fields, body := buildH2Request(cfg, method, hostHdr)
		if len(body) > 0 && !c.tryReserveSendWindow(len(body)) {
			// The connection-level send window is exhausted. Do not stall the
			// sequential loop waiting for WINDOW_UPDATE (the reader is this
			// goroutine); send a bodyless request instead.
			method = "GET"
			fields, body = buildH2Request(cfg, method, hostHdr)
		}
		streamID := c.nextStream()
		start := time.Now()

		if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
			return completed, err
		}
		if err := c.writeHeaders(streamID, fields, len(body) == 0); err != nil {
			if len(body) > 0 {
				c.releaseSendWindow(len(body))
			}
			return completed, fmt.Errorf("h2 write headers: %w", err)
		}
		if len(body) > 0 {
			if err := c.writeData(streamID, body, true); err != nil {
				c.releaseSendWindow(len(body))
				return completed, fmt.Errorf("h2 write body: %w", err)
			}
		}

		status, err := c.readResponse(streamID)
		if err != nil {
			return completed, err
		}
		metrics.recordResponse(status, time.Since(start))
		completed++
		_ = conn.SetDeadline(time.Time{})

		if cfg.RotateEvery > 0 && completed >= cfg.RotateEvery {
			return completed, nil
		}
		if cfg.JitterMs > 0 {
			jitter := time.Duration(rand.IntN(cfg.JitterMs)+1) * time.Millisecond
			if !sleepCtx(ctx, jitter) {
				return completed, ctx.Err()
			}
		}
	}
}

func (c *h2Client) readResponse(streamID uint32) (int, error) {
	status := 0
	for {
		frame, err := c.fr.ReadFrame()
		if err != nil {
			return 0, err
		}

		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			if f.Truncated {
				return 0, fmt.Errorf("h2 response headers truncated")
			}
			if v := f.PseudoValue("status"); v != "" {
				code, err := strconv.Atoi(v)
				if err != nil {
					return 0, fmt.Errorf("h2 invalid :status %q", v)
				}
				if code >= 100 && code < 200 {
					continue
				}
				status = code
			}
			if f.StreamEnded() {
				if status == 0 {
					return 0, fmt.Errorf("h2 response missing :status")
				}
				return status, nil
			}

		case *http2.DataFrame:
			n := int(f.Length) // includes padding, which also consumes flow control
			if n > 0 {
				// Replenish the connection window even for an unexpected
				// stream (for example a pushed response we are resetting).
				_ = c.writeWindowUpdate(0, uint32(n))
				if !f.StreamEnded() {
					_ = c.writeWindowUpdate(f.StreamID, uint32(n))
				}
			}
			if f.StreamID != streamID {
				continue
			}
			if f.StreamEnded() {
				if status == 0 {
					return 0, fmt.Errorf("h2 response missing :status")
				}
				return status, nil
			}

		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = c.writeSettingsAck()
				c.applyServerSettings(f)
			}

		case *http2.PingFrame:
			if !f.IsAck() {
				_ = c.writePingAck(f.Data)
			}

		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				c.addSendWindow(int64(f.Increment))
			}

		case *http2.GoAwayFrame:
			return 0, errH2GoAway

		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return 0, fmt.Errorf("h2 stream reset (code %d)", f.ErrCode)
			}

		case *http2.PushPromiseFrame:
			_ = c.writeRSTStream(f.PromiseID, http2.ErrCodeCancel)
		}
	}
}

// h2SendSession coordinates concurrent streams for send-only mode.
type h2SendSession struct {
	c     *h2Client
	slots chan struct{}

	mu     sync.Mutex
	active map[uint32]struct{}

	done       chan struct{}
	readerDone chan struct{}
	closeOnce  sync.Once

	errMu sync.Mutex
	err   error
}

func newH2SendSession(c *h2Client) *h2SendSession {
	return &h2SendSession{
		c:          c,
		slots:      make(chan struct{}, h2MaxConcurrentStreams),
		active:     make(map[uint32]struct{}, h2MaxConcurrentStreams),
		done:       make(chan struct{}),
		readerDone: make(chan struct{}),
	}
}

func (s *h2SendSession) stop() {
	s.closeOnce.Do(func() {
		close(s.done)
	})
	// Unblock a reader or writer that is currently in socket I/O.
	_ = s.c.conn.Close()
}

func (s *h2SendSession) fail(err error) {
	s.errMu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.errMu.Unlock()
	s.stop()
}

func (s *h2SendSession) lastErr() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		return errH2Closed
	}
	return s.err
}

func (s *h2SendSession) addStream(id uint32) {
	s.mu.Lock()
	s.active[id] = struct{}{}
	s.mu.Unlock()
}

func (s *h2SendSession) finishStream(id uint32) {
	s.mu.Lock()
	if _, ok := s.active[id]; ok {
		delete(s.active, id)
		select {
		case <-s.slots:
		default:
		}
	}
	s.mu.Unlock()
}

func (s *h2SendSession) reader() {
	defer close(s.readerDone)
	for {
		frame, err := s.c.fr.ReadFrame()
		if err != nil {
			s.fail(err)
			return
		}

		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if f.StreamEnded() {
				s.finishStream(f.StreamID)
			}
		case *http2.DataFrame:
			n := int(f.Length) // includes padding, which also consumes flow control
			if n > 0 {
				_ = s.c.writeWindowUpdate(0, uint32(n))
				if !f.StreamEnded() {
					_ = s.c.writeWindowUpdate(f.StreamID, uint32(n))
				}
			}
			if f.StreamEnded() {
				s.finishStream(f.StreamID)
			}
		case *http2.RSTStreamFrame:
			s.finishStream(f.StreamID)
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = s.c.writeSettingsAck()
				s.c.applyServerSettings(f)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = s.c.writePingAck(f.Data)
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				s.c.addSendWindow(int64(f.Increment))
			}
		case *http2.GoAwayFrame:
			s.fail(errH2GoAway)
			return
		case *http2.PushPromiseFrame:
			_ = s.c.writeRSTStream(f.PromiseID, http2.ErrCodeCancel)
		}
	}
}

// h2SendOnlyConnection opens up to h2MaxConcurrentStreams per connection and
// writes requests without waiting for their bodies. A reader drains response
// frames, replenishes flow-control windows, and frees stream slots.
func h2SendOnlyConnection(ctx context.Context, cfg StressConfig, conn net.Conn, fp sessionFingerprint, hostHdr string, metrics *Metrics) (sent int, err error) {
	stopWatch := watchConn(ctx, conn)
	defer stopWatch()
	// Treat a GOAWAY after some successful sends as a clean connection end.
	defer func() {
		if errors.Is(err, errH2GoAway) && sent > 0 {
			err = nil
		}
	}()

	c, err := newH2Client(conn, fp.h2, false)
	if err != nil {
		return 0, err
	}

	s := newH2SendSession(c)
	go s.reader()
	defer func() {
		s.stop()
		<-s.readerDone
	}()

	for {
		if ctx.Err() != nil {
			return sent, ctx.Err()
		}

		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			return sent, ctx.Err()
		case <-s.done:
			return sent, s.lastErr()
		}

		method := httpMethods[rand.IntN(len(httpMethods))]
		fields, body := buildH2Request(cfg, method, hostHdr)
		if len(body) > 0 && !c.tryReserveSendWindow(len(body)) {
			// Preserve send pressure when the connection-level send window
			// is exhausted: fall back to a bodyless method instead of
			// stalling on POST bodies.
			method = "GET"
			fields, body = buildH2Request(cfg, method, hostHdr)
		}

		streamID := c.nextStream()
		s.addStream(streamID)

		if len(body) == 0 {
			if err := c.writeHeaders(streamID, fields, true); err != nil {
				s.finishStream(streamID)
				return sent, fmt.Errorf("h2 write headers: %w", err)
			}
		} else {
			if err := c.writeHeaders(streamID, fields, false); err != nil {
				s.finishStream(streamID)
				c.releaseSendWindow(len(body))
				return sent, fmt.Errorf("h2 write headers: %w", err)
			}
			if err := c.writeData(streamID, body, true); err != nil {
				s.finishStream(streamID)
				c.releaseSendWindow(len(body))
				return sent, fmt.Errorf("h2 write body: %w", err)
			}
		}

		metrics.recordSentN(1)
		sent++

		if cfg.RotateEvery > 0 && sent >= cfg.RotateEvery {
			return sent, nil
		}
		if cfg.JitterMs > 0 {
			jitter := time.Duration(rand.IntN(cfg.JitterMs)+1) * time.Millisecond
			if !sleepCtx(ctx, jitter) {
				return sent, ctx.Err()
			}
		}
	}
}

// buildH2Request returns HPACK header fields in browser order plus an optional
// POST body.
func buildH2Request(cfg StressConfig, method, hostHdr string) ([]hpack.HeaderField, []byte) {
	sess := cfg.session
	if sess == nil {
		sess = defaultSession
	}
	p := sess.profile
	fpCfg := cfg
	fpCfg.session = sess
	fp := fingerprintForConfig(fpCfg)

	isNavigation := method == "GET" || method == "POST"
	site, refererMode, externalReferer := requestFetchContext(method)
	path := requestPath(cfg, method)

	var body []byte
	if method == "POST" {
		var bb bytes.Buffer
		createFormBody(&bb)
		body = bb.Bytes()
	}

	fields := make([]hpack.HeaderField, 0, 24)
	add := func(name, value string) {
		fields = append(fields, hpack.HeaderField{Name: name, Value: value})
	}

	// Browser-specific pseudo-header order is part of the h2 fingerprint.
	pseudoOrder := fp.h2.pseudoOrder
	if pseudoOrder == "" {
		pseudoOrder = "masp"
	}
	for i := 0; i < len(pseudoOrder); i++ {
		switch pseudoOrder[i] {
		case 'm':
			add(":method", method)
		case 'a':
			add(":authority", hostHdr)
		case 's':
			add(":scheme", cfg.Target.Scheme)
		case 'p':
			add(":path", path)
		}
	}

	if p.chrome {
		add("sec-ch-ua", fmt.Sprintf("\"Google Chrome\";v=\"%s\", \"Chromium\";v=\"%s\", \"Not_A Brand\";v=\"99\"", p.chromeMajor, p.chromeMajor))
		if p.mobile {
			add("sec-ch-ua-mobile", "?1")
		} else {
			add("sec-ch-ua-mobile", "?0")
		}
		add("sec-ch-ua-platform", "\""+p.platform+"\"")
	}

	if isNavigation {
		add("upgrade-insecure-requests", "1")
	}

	add("user-agent", p.ua)
	if method == "HEAD" {
		add("accept", "*/*")
	} else {
		add("accept", strings.TrimSuffix(strings.TrimPrefix(p.accept, "Accept: "), "\r\n"))
	}
	add("sec-fetch-site", site)
	if isNavigation {
		add("sec-fetch-mode", "navigate")
		add("sec-fetch-user", "?1")
		add("sec-fetch-dest", "document")
	} else {
		add("sec-fetch-mode", "cors")
		add("sec-fetch-dest", "empty")
	}

	if p.chrome && isNavigation && p.hasPriority {
		add("priority", "u=0, i")
	}

	add("accept-encoding", p.encoding)
	add("accept-language", sess.language)

	if cookie := sess.cookieValue(); cookie != "" {
		add("cookie", cookie)
	}

	switch refererMode {
	case 1:
		add("referer", pageURLString(cfg, hostHdr))
	case 2:
		add("referer", externalReferer)
	}

	if cfg.XFF {
		var xff bytes.Buffer
		writeRandomPublicIP(&xff)
		if rand.IntN(3) > 0 {
			xff.WriteString(", ")
			writeRandomCDNEdgeIP(&xff)
		}
		add("x-forwarded-for", xff.String())
	}

	if method == "POST" {
		add("origin", cfg.Target.Scheme+"://"+hostHdr)
		add("content-type", "application/x-www-form-urlencoded")
		add("content-length", strconv.Itoa(len(body)))
	}

	return fields, body
}
