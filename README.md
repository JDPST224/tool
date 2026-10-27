# project_down — HTTP load / stress tester

A small Go load tester for HTTP/1.1 servers. It supports direct connections,
HTTP/HTTPS proxies, SOCKS4 and SOCKS5, custom `Host`/TLS `SNI`, optional
per-request jitter, and live throughput/error reporting. Requests use a coherent
browser-like session by default: stable UA/Client Hints/language/cookies per
connection, browser-style header order, and matching `Sec-Fetch`/`Referer`/
`Origin` headers. By default it sends requests without waiting for responses;
response-aware status/latency mode is available with `--send-only=false`.

Use it only against servers you own or have explicit permission to test.
Running this against third-party systems is abuse and may be illegal.

## Requirements

- Go 1.25+ to build from source (the included `tool.exe` is a Windows
  build and does not need Go installed).
- `golang.org/x/net/proxy` (installed automatically by `go mod download`).

## Build

```powershell
go build -o tool.exe .
```

On Linux/macOS:

```bash
go build -o tool .
```

Run the tests with:

```bash
go test ./...
```

Run the request-generation benchmarks with:

```bash
go test -run '^$' -bench . -benchmem
```

## Usage

```text
tool.exe [--jitter <ms>] <URL> <THREADS> <DURATION_SEC> [CUSTOM_HOST]              (direct)
tool.exe [--jitter <ms>] <URL> <THREADS> <DURATION_SEC> <PROXY_TYPE> [CUSTOM_HOST]  (proxy)
```

By default, requests are sent without waiting for or parsing responses. No mode
flag is required.

- `PROXY_TYPE`: `http`, `https`, `sock4`, or `sock5`
- `CUSTOM_HOST`: value used for the `Host` header and TLS SNI. It may include a
  port. If it has no port, a non-default target port is appended automatically.
  Because the CLI has no explicit mode flag, a custom-host value equal to a
  proxy type name (`http`, `https`, `sock4`, `sock5`) selects proxy mode; add an
  explicit port in that unusual case.
- `--jitter <ms>`: random sleep of 1..N ms between requests. Optional,
  default `0`. Put flags **before** the positional arguments.
- `--send-only`: send-only mode, **default `true`**. A background reader
  discards response bytes to prevent TCP receive-buffer backpressure from
  stalling the writer. Statistics count requests written, not completed
  responses.
- `--send-only=false`: response-aware mode. Waits for each complete response,
  drains its body, and reports status codes and latency.
- `--cache-bust`: append a random query parameter to GET/HEAD requests. Off by
  default because real browser requests use the URL exactly as given.
- `--xff`: add a synthetic `X-Forwarded-For` chain. Off by default because real
  browsers do not send that header; useful for CDN/proxy-chain testing.

Browser-like request profile:

- One browser identity per connection/worker: stable User-Agent, Client Hints,
  Accept-Language, and analytics-cookie set across requests and reconnects.
- Mostly GET navigations, with occasional form POSTs and fetch-style HEADs.
- Coherent `Sec-Fetch-Site` / `Referer` combinations: direct navigation has no
  Referer and `Sec-Fetch-Site: none`; external referers are cross-site;
  form POSTs and fetch HEADs are same-origin.
- Chrome requests use matching `sec-ch-ua`, mobile/platform hints, and
  `Priority` when appropriate.
- Header order follows a Chrome-like pattern.
- No synthetic `X-Forwarded-For` or forced `Cache-Control`/`Pragma` headers by
  default. Random query parameters are off unless `--cache-bust` is used.

All runs send browser-like requests with an HTTP/1.1 connection. This does not
execute JavaScript or fetch page subresources, so it mimics browser request
headers rather than a full browser session.

Examples:

```powershell
# Direct send-only (default): 50 connections for 30 seconds
.\tool.exe http://192.168.1.20:8080/ 50 30

# Direct HTTPS, send example.com as Host/SNI while connecting to the URL host
.\tool.exe https://203.0.113.10/ 50 30 example.com

# Proxy mode: 100 connections, 60 seconds, HTTP proxies from proxies.txt
.\tool.exe https://example.com/ 100 60 http

# Proxy mode with a custom Host/SNI value
.\tool.exe https://203.0.113.10/ 100 60 http example.com

# Proxy mode with a 10 ms maximum jitter
.\tool.exe --jitter 10 http://example.com/ 100 60 socks5

# Response-aware mode: wait for responses and report status codes/latency
.\tool.exe --send-only=false https://example.com/ 20 30

# Optional CDN/proxy-chain testing (non-browser-like)
.\tool.exe --cache-bust --xff https://example.com/ 50 30
```

### proxies.txt

`proxies.txt` is read when a proxy type is supplied. One proxy per line:

```text
# comments and blank lines are ignored
127.0.0.1:8080
10.0.0.5:3128
[::1]:1080
http://192.0.2.10:3128
```

The scheme prefix is optional and only informative: the `PROXY_TYPE` argument
decides the protocol. Proxy authentication is not supported. Invalid lines are
reported with their line number. See `proxies.example.txt`.

## What the output means

By default, each thread writes requests back-to-back and does not wait for,
parse, or classify responses. A background reader discards response bytes so
that unread data does not fill the TCP receive buffer and block the writer. This
gives maximum send pressure, but status codes and response latency are not
available in this mode.

Send-only mode batches up to 64 requests (or 64 KiB) per socket write, uses a
32 KiB discard-read buffer, and reuses per-connection buffers. `--jitter` keeps
one request per write so jitter spacing is preserved.

With `--send-only=false`, every thread keeps one HTTP/1.1 connection open and
waits for each complete response (headers **and** body) before sending the next
request. This makes the numbers reflect work the server actually completed
instead of bytes that only reached the client's socket buffer.

Default (send-only) statistics:

- `req/s`: successfully written requests per second during the last interval.
- `sent`: requests written during the last interval.
- `total_sent`: requests written during the whole run.
- `errors`: transport errors, including write timeouts and connections closed
  by the server.
- `timeouts`: subset of `errors` caused by a timeout.

Response-aware (`--send-only=false`) statistics:

- `req/s`: completed responses per second during the last interval.
- `responses`: completed HTTP exchanges.
- `errors`: transport errors (connect failures, resets, read/write errors).
- `timeouts`: subset of `errors` caused by a timeout.
- `2xx` / `3xx` / `4xx` / `5xx`: completed responses by status class. A `5xx`
  is not counted as a transport error; it is reported separately.
- `avg_ms`: average time from sending a request through receiving the full
  response body.
- `other`: unusual status codes (600+).

The final line (`stress test completed`) contains totals, overall throughput,
and either send-only request totals or response/status totals.

## Testing a home server before moving to a VPS

1. Run the tester from a **different machine** than the server. Testing over
   loopback measures the client and server on the same CPU, not network/stack
   capacity.
2. Start small: `10–25` threads for a `20–30` second run. Watch server CPU, RAM,
   disk, network, and application logs.
3. Increase threads gradually (for example 25 → 50 → 100) and repeat the same
   duration. Use `--send-only=false` first to verify status codes and latency,
   then use the default send-only mode for maximum outbound request pressure.
4. Keep the target endpoint and request mix consistent between the home and VPS
   runs. Requests are mostly GET navigations with occasional form POSTs and
   fetch HEADs, so use an endpoint where the occasional POST is harmless (or a
   test path that accepts them).
5. When you move to the VPS, run the same command from the same client network.
   Your home upload bandwidth (or Wi-Fi) can be the bottleneck, not the VPS.
6. A useful capacity result is the highest thread count where the server keeps
   returning successful responses with acceptable latency and no errors — not
   the highest momentary `req/s`.

## Notes and limitations

- HTTP/1.1 only. Redirects and `Set-Cookie` are not followed/processed; `3xx`
  responses are counted in response-aware mode.
- The browser-like profile mimics request headers and session consistency. It
  does not execute JavaScript, fetch page subresources, follow redirects, or
  reproduce Chrome's exact TLS/HTTP2 fingerprint. Cookies are synthetic and
  stable per worker, not a real cookie jar.
- Direct mode resolves IPv4 addresses only (the original behavior). Proxies are
  resolved by the operating system.
- In default send-only mode, multiple requests may be in flight on one
  connection. In response-aware mode each thread has at most one request in
  flight; increase `THREADS` for more concurrency.
- Default send-only mode uses a 15-second write timeout when the server stops
  accepting data. Response-aware mode uses a 15-second per-request timeout.
- Default send-only mode counts successfully written requests. It cannot tell
  whether the server returned `2xx`, `4xx`, or `5xx`, and it does not measure
  latency. Use `--send-only=false` to check server health.
- Servers may close heavily pipelined connections; the tool reconnects with
  backoff automatically.
- Send-only throughput is limited by client CPU, kernel/network bandwidth, and
  the target server. Start with a modest thread count and ramp up while watching
  both client and server resource usage.
- Send-only mode uses roughly 96 KiB of buffers per active connection (64 KiB
  batch + 32 KiB discard). Very high `THREADS` values also raise client memory
  use.
- TLS certificates are **not** verified, so self-signed home-lab certificates
  work. This is intentional and must not be used as a security check.
- `--xff` and `--cache-bust` intentionally make requests less browser-like. They
  are off by default and should only be used for proxy/CDN/cache testing.
- URL user:password credentials, proxy authentication, HTTP/2, HTTP/3, and
  IPv6 direct targets are not supported.

## Troubleshooting

- `Failed to load proxies.txt`: create `proxies.txt` in the current working
  directory (usually the folder you run the command from) and check the reported
  line number.
- `Initial DNS lookup failed`: the URL host must resolve to an IPv4 address from
  the machine running the tool.
- Many `timeouts` / `errors`: the server, network path, or proxy is saturated or
  unreachable. Check server logs and reduce threads.
- High `errors` in default send-only mode: some servers close pipelined or
  HTTP/1.0 connections after each response. The tool reconnects automatically;
  use `--send-only=false` to confirm the server's actual response status.
- `too many open files` (Linux/macOS): raise the shell's file-descriptor limit
  or use fewer threads.
- `--jitter`, `--cache-bust`, `--xff`, or `--send-only=false` seems ignored:
  place flags before the URL; Go's flag parser stops at the first positional
  argument.
