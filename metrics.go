package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// Metrics is shared by direct and proxy modes. "responses" counts fully
// completed HTTP exchanges (headers + body), while "sent" counts successful
// request writes in send-only mode. "errors" counts transport failures only.
// HTTP 4xx/5xx responses are successful exchanges and are reported separately
// by status class.
type Metrics struct {
	sendOnly bool

	responses atomic.Int64
	sent      atomic.Int64
	errors    atomic.Int64
	timeouts  atomic.Int64

	status2xx atomic.Int64
	status3xx atomic.Int64
	status4xx atomic.Int64
	status5xx atomic.Int64
	statusXXX atomic.Int64

	latencyNanos atomic.Int64
}

type metricsSnapshot struct {
	responses int64
	sent      int64
	errors    int64
	timeouts  int64
	status2xx int64
	status3xx int64
	status4xx int64
	status5xx int64
	statusXXX int64
	latency   int64
}

func (m *Metrics) recordError(err error) {
	m.errors.Add(1)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		m.timeouts.Add(1)
	}
}

func (m *Metrics) recordSentN(n int) {
	if n > 0 {
		m.sent.Add(int64(n))
	}
}

func (m *Metrics) recordResponse(status int, latency time.Duration) {
	m.responses.Add(1)
	m.latencyNanos.Add(int64(latency))

	switch {
	case status >= 200 && status < 300:
		m.status2xx.Add(1)
	case status >= 300 && status < 400:
		m.status3xx.Add(1)
	case status >= 400 && status < 500:
		m.status4xx.Add(1)
	case status >= 500 && status < 600:
		m.status5xx.Add(1)
	default:
		m.statusXXX.Add(1)
	}
}

func (m *Metrics) snapshot() metricsSnapshot {
	return metricsSnapshot{
		responses: m.responses.Load(),
		sent:      m.sent.Load(),
		errors:    m.errors.Load(),
		timeouts:  m.timeouts.Load(),
		status2xx: m.status2xx.Load(),
		status3xx: m.status3xx.Load(),
		status4xx: m.status4xx.Load(),
		status5xx: m.status5xx.Load(),
		statusXXX: m.statusXXX.Load(),
		latency:   m.latencyNanos.Load(),
	}
}

func (s metricsSnapshot) avgLatencyMs() float64 {
	if s.responses == 0 {
		return 0
	}
	return float64(s.latency) / float64(s.responses) / float64(time.Millisecond)
}

func (m *Metrics) runStats(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	last := m.snapshot()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := m.snapshot()
			d := metricsSnapshot{
				responses: cur.responses - last.responses,
				sent:      cur.sent - last.sent,
				errors:    cur.errors - last.errors,
				timeouts:  cur.timeouts - last.timeouts,
				status2xx: cur.status2xx - last.status2xx,
				status3xx: cur.status3xx - last.status3xx,
				status4xx: cur.status4xx - last.status4xx,
				status5xx: cur.status5xx - last.status5xx,
				statusXXX: cur.statusXXX - last.statusXXX,
			}
			last = cur

			if m.sendOnly {
				rps := float64(d.sent) / interval.Seconds()
				slog.Info("stats",
					"mode", "send-only",
					"req/s", fmt.Sprintf("%.0f", rps),
					"sent", d.sent,
					"errors", d.errors,
					"timeouts", d.timeouts,
					"total_sent", cur.sent,
					"total_errors", cur.errors,
				)
				continue
			}

			rps := float64(d.responses) / interval.Seconds()
			slog.Info("stats",
				"req/s", fmt.Sprintf("%.0f", rps),
				"errors", d.errors,
				"timeouts", d.timeouts,
				"2xx", d.status2xx,
				"3xx", d.status3xx,
				"4xx", d.status4xx,
				"5xx", d.status5xx,
				"avg_ms", fmt.Sprintf("%.1f", cur.avgLatencyMs()),
				"total_reqs", cur.responses,
				"total_errors", cur.errors,
			)
		}
	}
}

func (m *Metrics) logSummary(start time.Time) {
	cur := m.snapshot()
	elapsed := time.Since(start)
	if elapsed <= 0 {
		elapsed = time.Nanosecond
	}

	if m.sendOnly {
		slog.Info("stress test completed",
			"mode", "send-only",
			"duration", elapsed.Round(time.Millisecond),
			"req/s", fmt.Sprintf("%.0f", float64(cur.sent)/elapsed.Seconds()),
			"requests_sent", cur.sent,
			"errors", cur.errors,
			"timeouts", cur.timeouts,
		)
		return
	}

	slog.Info("stress test completed",
		"duration", elapsed.Round(time.Millisecond),
		"req/s", fmt.Sprintf("%.0f", float64(cur.responses)/elapsed.Seconds()),
		"responses", cur.responses,
		"errors", cur.errors,
		"timeouts", cur.timeouts,
		"2xx", cur.status2xx,
		"3xx", cur.status3xx,
		"4xx", cur.status4xx,
		"5xx", cur.status5xx,
		"other", cur.statusXXX,
		"avg_ms", fmt.Sprintf("%.1f", cur.avgLatencyMs()),
	)
}
