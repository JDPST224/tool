// Usage:
//
//	go run . [flags] <URL> <THREADS> <DURATION_SEC> [CUSTOM_HOST]              (direct mode)
//	go run . [flags] <URL> <THREADS> <DURATION_SEC> <PROXY_TYPE> [CUSTOM_HOST]  (proxy mode)
//
// Proxy types: http, https, sock4, sock5
// Proxies are loaded from proxies.txt (one host:port per line)
//
// By default requests are sent without waiting for or parsing responses. Use
// --send-only=false to enable response-aware mode with status/latency stats.
//
// Flags:
//
//	--jitter <ms>          Maximum per-request sleep in milliseconds (default: 0)
//	--send-only            Send-only mode (default: true); --send-only=false waits for responses
//	--cache-bust           Append a random query parameter (default: false; not browser-like)
//	--xff                  Add synthetic X-Forwarded-For headers (default: false; not browser-like)
//	--fingerprint <mode>   Browser TLS/HTTP2 profile: rotate, chrome, firefox, safari, ios, none
//	--http2                Negotiate HTTP/2 when the server supports it (default: true)
//	--proxy-rotation <m>   Proxy selection: round-robin, random, sticky (default: round-robin)
//	--rotate-every <n>     Reconnect (and rotate proxy/fingerprint) every N requests (default: 0 = off)
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type runOptions struct {
	JitterMs      int
	SendOnly      bool
	CacheBust     bool
	XFF           bool
	Fingerprint   string
	HTTP2         bool
	ProxyRotation string
	RotateEvery   int
}

var (
	jitterMs      = flag.Int("jitter", 0, "max per-request jitter in milliseconds (0 = disabled)")
	sendOnly      = flag.Bool("send-only", true, "send without waiting for responses (default true; use --send-only=false for response-aware mode)")
	cacheBust     = flag.Bool("cache-bust", false, "append a random query parameter to GET/HEAD requests")
	xff           = flag.Bool("xff", false, "add synthetic X-Forwarded-For headers")
	fingerprint   = flag.String("fingerprint", "rotate", "browser TLS/HTTP2 profile: rotate, chrome, firefox, safari, ios, none")
	http2Enabled  = flag.Bool("http2", true, "negotiate HTTP/2 when the server supports it")
	proxyRotation = flag.String("proxy-rotation", "round-robin", "proxy selection: round-robin, random, sticky")
	rotateEvery   = flag.Int("rotate-every", 0, "reconnect and rotate proxy/fingerprint every N requests (0 = disabled)")
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s [flags] <URL> <THREADS> <DURATION_SEC> [CUSTOM_HOST]              (direct)\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s [flags] <URL> <THREADS> <DURATION_SEC> <PROXY_TYPE> [CUSTOM_HOST]  (proxy)\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "PROXY_TYPE: http, https, sock4, sock5\n")
	fmt.Fprintf(os.Stderr, "FLAGS:\n")
	fmt.Fprintf(os.Stderr, "  --jitter <ms>         max per-request sleep in ms (default 0)\n")
	fmt.Fprintf(os.Stderr, "  --send-only           send without waiting for responses (default true)\n")
	fmt.Fprintf(os.Stderr, "                        use --send-only=false for response-aware stats\n")
	fmt.Fprintf(os.Stderr, "  --cache-bust          append a random query parameter (default false)\n")
	fmt.Fprintf(os.Stderr, "  --xff                 add synthetic X-Forwarded-For headers (default false)\n")
	fmt.Fprintf(os.Stderr, "  --fingerprint <mode>  rotate, chrome, firefox, safari, ios, none (default rotate)\n")
	fmt.Fprintf(os.Stderr, "  --http2               negotiate HTTP/2 when supported (default true)\n")
	fmt.Fprintf(os.Stderr, "  --proxy-rotation <m>  round-robin, random, sticky (default round-robin)\n")
	fmt.Fprintf(os.Stderr, "  --rotate-every <n>    reconnect and rotate every N requests (default 0 = off)\n")
	fmt.Fprintf(os.Stderr, "NOTE: put flags before the positional arguments.\n")
}

func main() {
	flag.Usage = printUsage
	flag.Parse()
	args := flag.Args()

	if len(args) < 3 || len(args) > 5 {
		printUsage()
		os.Exit(1)
	}

	threads, err := strconv.Atoi(args[1])
	if err != nil || threads <= 0 {
		fmt.Fprintf(os.Stderr, "Invalid THREADS (%q): must be a positive integer.\n", args[1])
		os.Exit(1)
	}
	durSec, err := strconv.Atoi(args[2])
	if err != nil || durSec <= 0 {
		fmt.Fprintf(os.Stderr, "Invalid DURATION_SEC (%q): must be a positive integer.\n", args[2])
		os.Exit(1)
	}
	if *jitterMs < 0 {
		fmt.Fprintf(os.Stderr, "Invalid --jitter (%d): must be zero or a positive integer.\n", *jitterMs)
		os.Exit(1)
	}
	if *rotateEvery < 0 {
		fmt.Fprintf(os.Stderr, "Invalid --rotate-every (%d): must be zero or a positive integer.\n", *rotateEvery)
		os.Exit(1)
	}

	fingerprintMode := strings.ToLower(strings.TrimSpace(*fingerprint))
	switch fingerprintMode {
	case "rotate", "chrome", "firefox", "safari", "ios", "none":
	default:
		fmt.Fprintf(os.Stderr, "Invalid --fingerprint %q: use rotate, chrome, firefox, safari, ios, or none.\n", *fingerprint)
		os.Exit(1)
	}

	rotationMode := strings.ToLower(strings.TrimSpace(*proxyRotation))
	switch rotationMode {
	case "round-robin", "random", "sticky":
	default:
		fmt.Fprintf(os.Stderr, "Invalid --proxy-rotation %q: use round-robin, random, or sticky.\n", *proxyRotation)
		os.Exit(1)
	}

	rawURL := args[0]
	duration := time.Duration(durSec) * time.Second
	opts := runOptions{
		JitterMs:      *jitterMs,
		SendOnly:      *sendOnly,
		CacheBust:     *cacheBust,
		XFF:           *xff,
		Fingerprint:   fingerprintMode,
		HTTP2:         *http2Enabled,
		ProxyRotation: rotationMode,
		RotateEvery:   *rotateEvery,
	}

	// Determine mode: if the 4th arg is a valid proxy type, use proxy mode.
	if len(args) >= 4 {
		proxyType := strings.ToLower(args[3])
		if isProxyType(proxyType) {
			customHost := ""
			if len(args) == 5 {
				customHost = args[4]
			}
			runProxy(rawURL, threads, duration, proxyType, customHost, opts)
			return
		}
	}

	if len(args) == 5 {
		fmt.Fprintf(os.Stderr, "Too many arguments for direct mode (use <PROXY_TYPE> as the 4th argument for proxy mode).\n")
		os.Exit(1)
	}

	// Direct mode (4th arg is optional custom host, or not provided).
	customHost := ""
	if len(args) == 4 {
		customHost = args[3]
	}
	runDirect(rawURL, threads, duration, customHost, opts)
}

func isProxyType(s string) bool {
	switch s {
	case "http", "https", "sock4", "sock5":
		return true
	default:
		return false
	}
}
