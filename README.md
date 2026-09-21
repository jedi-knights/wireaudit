# wireaudit

`wireaudit` probes a live HTTP/HTTPS API and reports whether it actually implements the HTTP protocol correctly — not what the code *looks* like it does, but what happens on the wire: status codes, header syntax, caching semantics, method semantics, content negotiation, and TLS.

Findings are grouped into three buckets, most severe first:

- **Must Fix** — a correctness failure: the target violates a MUST-level protocol requirement.
- **Should Fix** — a SHOULD-level deviation that drifts from the spec without breaking interoperability outright.
- **Consider** — an improvement opportunity with no normative violation.

## Installation

```bash
go install github.com/jedi-knights/wireaudit/cmd/wireaudit@latest
```

Or build from source:

```bash
git clone https://github.com/jedi-knights/wireaudit.git
cd wireaudit
go build -o wireaudit ./cmd/wireaudit
```

No runtime dependencies — the result is a single static binary.

## Usage

```bash
# Probe a single endpoint (defaults to "GET /" against --target)
wireaudit --target https://api.example.com

# Probe several endpoints
wireaudit --target https://api.example.com \
  --endpoint "GET /v1/users/42" \
  --endpoint "POST /v1/users"

# Probe endpoints from a file (one "METHOD path" per line; "#" comments allowed)
wireaudit --target https://api.example.com --endpoints-file endpoints.txt

# CI-friendly JSON output; non-zero exit code on any Must Fix finding
wireaudit --target https://api.example.com --format json
echo "exit code: $?"
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | No Must Fix finding |
| `1` | At least one Must Fix finding |
| `2` | The run itself could not complete (bad flags, unreachable target, TLS handshake failure) |

## Configuration

| Flag | Default | Description |
|---|---|---|
| `--target` | *(required)* | Base URL of the API to probe |
| `--endpoint` | — | Endpoint to probe, e.g. `"GET /v1/users/42"` (repeatable; default: probe `/`) |
| `--endpoints-file` | — | File with one `"METHOD path"` endpoint per line (mutually exclusive with `--endpoint`) |
| `--header` | — | Header to send on every request, e.g. `"Authorization: Bearer token"` (repeatable) |
| `--categories` | *(all)* | Comma-separated category allowlist: `header-syntax,response-headers,methods,caching,redirects,negotiation,tls` |
| `--exclude-rule` | — | Check ID to skip, e.g. `CACHE-003` (repeatable) |
| `--format` | `human` | Output format: `human` or `json` |
| `--timeout` | `10s` | Per-request timeout |
| `--insecure-skip-verify` | `false` | Disable TLS certificate verification — **never use against a production target** |
| `--allow-unsafe-writes` | `false` | Permit `CACHE-005` to send a real `PUT`/`PATCH`/`DELETE` against the target to verify precondition enforcement — **off by default; only enable against a target you can safely mutate** |
| `--concurrency` | `4` | Maximum endpoints probed in parallel |

## Rule catalog (v1)

| Check ID | Category | RFC / Spec | Verifies |
|---|---|---|---|
| `HDR-001` | header-syntax | RFC 9112 §6.3 | Multiple differing `Content-Length` values are rejected, not silently resolved |
| `HDR-002` | header-syntax | RFC 9112 §6.3 | `Content-Length` + `Transfer-Encoding: chunked` together is rejected (request-smuggling risk) |
| `HDR-003` | header-syntax | RFC 9112 §5.2 | Obsolete line-folded headers are rejected or correctly unfolded |
| `HDR-004` | header-syntax | RFC 9110 §5.5 | Injected CRLF in reflected input is not echoed into a response header |
| `RESP-001` | response-headers | RFC 9110 §6.6.1 | Responses carry a `Date` header |
| `RESP-002` | response-headers | RFC 9110 §8.3 | `Content-Type` is present and consistent with the body |
| `RESP-003` | response-headers | RFC 9112 §6.3 | `Content-Length` equals the actual body length |
| `METH-001` | methods | RFC 9110 §9.3.2 | HEAD returns no body and headers equivalent to GET |
| `METH-002` | methods | RFC 9110 §9.3.7 | OPTIONS returns `Allow` |
| `METH-003` | methods | RFC 9110 §15.5.6 | An unsupported method on an existing route returns 405 with `Allow` |
| `METH-004` | methods | RFC 9110 §9.3.1 | GET/HEAD succeed without a request body |
| `CACHE-001` | caching | RFC 9110 §8.8.2/3 | Cacheable GET carries `ETag` and/or `Last-Modified` |
| `CACHE-002` | caching | RFC 9110 §13.1.1/§13.1.3/§15.4.5 | A matching conditional GET returns 304 with an empty body |
| `CACHE-003` | caching | RFC 9111 §5.2 | `Cache-Control` is present and internally consistent |
| `CACHE-004` | caching | RFC 9110 §13.1.1/§13.1.3 | A non-matching conditional GET does **not** incorrectly return 304 |
| `CACHE-005` | caching | RFC 9110 §13.1.2/§13.1.4 | A stale `If-Match` on a write is rejected with 412 (only when `--allow-unsafe-writes` is set) |
| `REDIR-001` | redirects | RFC 9110 §10.2.2 | 3xx responses include `Location` |
| `REDIR-002` | redirects | RFC 9110 §15.4.4/8/9 | 307/308 preserve method and body; 303 implies GET |
| `NEG-001` | negotiation | RFC 9110 §12.5.1/§15.5.7 | An unsupported `Accept` produces 406 or a graceful default, never a 5xx |
| `NEG-002` | negotiation | RFC 9110 §12.5.5 | `Vary` is present when the response varies by request headers |
| `NEG-003` | negotiation | RFC 9110 §12.5.1, §8.3 | The returned `Content-Type` actually matches the negotiated `Accept` |
| `TLS-001` | tls | RFC 5280 | Certificate chain is valid, unexpired, and matches the hostname |
| `TLS-002` | tls | RFC 8996 | Negotiated TLS version is 1.2 or higher |
| `TLS-003` | tls | OWASP transport guidance | Plaintext HTTP redirects to HTTPS |
| `TLS-004` | tls | RFC 6797 | HTTPS responses carry `Strict-Transport-Security` |

Not yet covered (planned, added via the same extensible rule registry with no architecture change): HTTP/2 and HTTP/3 framing, WebSocket upgrade handshake, full cipher-suite auditing, CORS preflight semantics.

## Development

```bash
go build ./...
go vet ./...
go test ./...
golangci-lint run ./...
```
