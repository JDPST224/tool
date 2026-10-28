package main

import (
	"math/rand/v2"
	"sync"
	"time"
)

const proxyFailureCooldown = 15 * time.Second

// proxyRotator selects a proxy for each new connection. Failed proxies are
// skipped for a short cooldown so one dead entry does not keep attracting
// reconnects.
type proxyRotator struct {
	mu      sync.Mutex
	proxies []string
	mode    string
	next    uint64
	down    map[string]time.Time
}

func newProxyRotator(proxies []string, mode string) *proxyRotator {
	return &proxyRotator{
		proxies: proxies,
		mode:    mode,
		down:    make(map[string]time.Time),
	}
}

// pick returns the next usable proxy for the given worker.
func (r *proxyRotator) pick(workerID int) string {
	n := len(r.proxies)
	if n == 0 {
		return ""
	}
	if n == 1 {
		return r.proxies[0]
	}

	start := workerID % n
	switch r.mode {
	case "random":
		start = rand.IntN(n)
	case "sticky":
		// Keep the worker pinned to its original proxy unless it failed.
	default: // round-robin
		r.mu.Lock()
		start = int(r.next % uint64(n))
		r.next++
		r.mu.Unlock()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for i := 0; i < n; i++ {
		candidate := r.proxies[(start+i)%n]
		if until, ok := r.down[candidate]; !ok || !now.Before(until) {
			return candidate
		}
	}
	// Every proxy is cooling down; return the first candidate and let the
	// normal dial timeout/backoff handle it.
	return r.proxies[start]
}

func (r *proxyRotator) markFailure(proxy string) {
	r.mu.Lock()
	r.down[proxy] = time.Now().Add(proxyFailureCooldown)
	r.mu.Unlock()
}

func (r *proxyRotator) markSuccess(proxy string) {
	r.mu.Lock()
	delete(r.down, proxy)
	r.mu.Unlock()
}
