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
| `--categories` | *(all)* | Comma-separated category allowlist: `header-syntax,response-headers,methods,caching,redirects,negotiation,authentication,errors,tls` |
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
| `AUTH-001` | authentication | RFC 9110 §15.5.2 | A `401` response carries a `WWW-Authenticate` challenge (passive: only judged when the endpoint itself answers `401`) |
| `ERR-001` | errors | RFC 9457 | The error body for an unknown resource (`GET /wireaudit-probe-nonexistent-resource`) is `application/problem+json` (**Consider**; skipped for empty bodies and catch-all `200` targets) |
| `TLS-001` | tls | RFC 5280 | Certificate chain is valid, unexpired, and matches the hostname |
| `TLS-002` | tls | RFC 8996 | Negotiated TLS version is 1.2 or higher |
| `TLS-003` | tls | OWASP transport guidance | Plaintext HTTP redirects to HTTPS |
| `TLS-004` | tls | RFC 6797 | HTTPS responses carry `Strict-Transport-Security` |

Not yet covered (planned, added via the same extensible rule registry with no architecture change): HTTP/2 and HTTP/3 framing, WebSocket upgrade handshake, full cipher-suite auditing, CORS preflight semantics.

## Coverage

What `wireaudit` v1 validates today versus what it does not. "Partial" means some sections of the RFC are checked; the Check IDs column links back to the [rule catalog](#rule-catalog-v1).

### By RFC

| RFC | Status | Check IDs | What is validated / what is not |
|---|---|---|---|
| RFC 9110 HTTP Semantics | Partial | `HDR-004`, `RESP-001/002`, `METH-001..004`, `CACHE-001/002/004/005`, `REDIR-001/002`, `NEG-001..003`, `AUTH-001` | Checked: `Date`, `Content-Type`, HEAD/OPTIONS/405 behavior, validators and conditional requests, redirects, `Accept`/`Vary`, `WWW-Authenticate` on `401`. **Not checked:** range requests (§14), `Expect: 100-continue`, `Upgrade`, `Content-Encoding`, `TRACE`/`CONNECT`, status-code selection for writes (e.g. `201` + `Location`) |
| RFC 9111 HTTP Caching | Partial | `CACHE-003` | Checked: `Cache-Control` present and not self-contradictory. **Not checked:** `Age`, `Expires`, freshness calculation, `s-maxage`, shared-cache rules |
| RFC 9112 HTTP/1.1 | Partial | `HDR-001..003`, `RESP-003` | Checked: duplicate/conflicting `Content-Length`, CL+TE smuggling, obs-fold, body length. **Not checked:** chunked-encoding edge cases, connection management, request-line parsing limits |
| RFC 5280 X.509 | Partial | `TLS-001` | Checked: chain validity, expiry, hostname match. **Not checked:** revocation (CRL/OCSP) |
| RFC 8996 Deprecating TLS 1.0/1.1 | Validated | `TLS-002` | Negotiated version is 1.2 or higher |
| RFC 6797 HSTS | Partial | `TLS-004` | Checked: header present with a `max-age`. **Not checked:** `includeSubDomains`, preload eligibility |
| RFC 9113 HTTP/2, RFC 9114 HTTP/3 (+ HPACK, QPACK, QUIC) | Not validated | — | No framing, stream, or compression checks. Planned |
| RFC 9846 / 8446 / 5246 TLS handshake details | Not validated | — | Only the negotiated version is checked; no cipher-suite or extension audit. Planned |
| RFC 6265 Cookies | Not validated | — | No `Secure`/`HttpOnly`/`SameSite` checks |
| RFC 9457 Problem Details | Partial | `ERR-001` | Checked: error body for an unknown resource is `application/problem+json`. **Not checked:** member names/types, `status` matching the HTTP status, 5xx and validation-error bodies |
| RFC 7617 / 6750 / 9729 Authentication | Partial | `AUTH-001` | Checked: `401` carries a `WWW-Authenticate` challenge (RFC 9110 §11.6.1 framework). **Not checked:** scheme-specific parameters (`realm`, Bearer `error`), `Authentication-Info`, `407` / `Proxy-Authenticate` |
| RFC 6455 / 8441 / 9220 WebSocket | Not validated | — | Upgrade handshake not probed. Planned |
| RFC 8288 Web Linking, RFC 9211 `Cache-Status`, RFC 9209 `Proxy-Status`, RFC 7838 `Alt-Svc`, RFC 5789 `PATCH`, RFC 6585 / 7725 / 8297 extra status codes, RFC 7239 `Forwarded`, RFC 9421 signatures, WebDAV | Not validated | — | Extension surface; no checks |

### By REST best practice ([restfulapi.net](https://restfulapi.net/))

Mapped from the site's guides on resource naming, HTTP methods, status codes, error handling, caching, content negotiation, idempotency, security, pagination, versioning, HATEOAS and long-running tasks.

| Best practice (source guide) | Status | Check IDs / note |
|---|---|---|
| Always use HTTPS; redirect plaintext (Security) | Validated | `TLS-001`, `TLS-002`, `TLS-003` |
| Send HSTS (Security) | Validated | `TLS-004` |
| Responses are cacheable or explicitly not (Caching) | Validated | `CACHE-003` |
| Cacheable responses carry `ETag` or `Last-Modified` (Caching) | Validated | `CACHE-001` |
| Validation via `If-None-Match` returns `304` (Caching) | Validated | `CACHE-002`, `CACHE-004` |
| GET and HEAD take no body; HEAD matches GET (HTTP Methods) | Validated | `METH-001`, `METH-004` |
| Unsupported method on a resource returns `405` with `Allow` (HTTP Methods) | Validated | `METH-003`, `METH-002` |
| Unacceptable `Accept` returns `406`, never 5xx (Content Negotiation) | Validated | `NEG-001` |
| `Vary` lists negotiation headers; returned `Content-Type` matches `Accept` (Content Negotiation) | Validated | `NEG-002`, `NEG-003` |
| Redirects carry `Location` (Status Codes) | Validated | `REDIR-001`, `REDIR-002` |
| Conditional writes are rejected with `412` when stale (Caching / Idempotence) | Validated (opt-in) | `CACHE-005`, needs `--allow-unsafe-writes` |
| HTTP dates are GMT (Caching) | Partial | `RESP-001` checks `Date` is present; format and zone are not verified |
| Charset declared in `Content-Type` (Content Negotiation) | Partial | `RESP-002` checks `Content-Type`; the `charset` parameter is not |
| Don't leak internals in errors (Error Handling) | Partial | `HDR-004` covers header injection only; stack traces, SQL and paths in bodies are not scanned |
| `201 Created` includes `Location` (Status Codes) | **Not validated** | Needs a write probe |
| `401` includes `WWW-Authenticate` (Status Codes) | Validated | `AUTH-001` (passive: only when the endpoint answers `401`) |
| `401` vs `403` usage (Status Codes) | **Not validated** | Needs API-specific knowledge |
| `400` vs `422`, `409`, `404` vs `410` usage (Status Codes) | **Not validated** | Needs API-specific knowledge |
| Errors use `application/problem+json` (Error Handling) | Partial | `ERR-001` (**Consider**), unknown-resource error only; required members `type`/`title`/`status`/`detail`/`instance` are not checked |
| `429` / `503` include `Retry-After` (Error Handling) | **Not validated** | Needs a rate-limit trigger |
| PUT and DELETE are idempotent; POST accepts `Idempotency-Key` (Idempotence) | **Not validated** | Repeated writes are deliberately not sent by default |
| `DELETE`/`PUT` on a collection returns `405` (HTTP Methods) | **Not validated** | |
| Nouns, plural collections, lowercase, hyphens, no trailing slash, no extensions, no verbs in URIs (Resource Naming) | **Not validated** | Static URI lint; could run on `--endpoint` paths without any probe |
| Credentials, tokens and API keys not in the URL (Security) | **Not validated** | Same: static lint of supplied endpoints |
| Pagination with `Link` headers, page-size cap, `400` on bad sort field (Pagination) | **Not validated** | |
| Versioning strategy; deprecation signals (Versioning) | **Not validated** | `Deprecation` (RFC 9745) / `Sunset` headers are not checked |
| Hypermedia links in responses (HATEOAS) | **Not validated** | |
| `202 Accepted` + `Location` + `Retry-After` for long-running work (Long-Running Tasks) | **Not validated** | |
| Stateless auth, least privilege, input validation, OAuth 2.0 (Security) | Out of scope | Server design, not observable from the wire |
| Resource modeling, REST vs GraphQL vs gRPC, client/server separation (REST Constraints) | Out of scope | Architecture guidance |

The site's own guidance is not fully consistent: Resource Naming says "no file extensions", while Content Negotiation lists `.json` / `.xml` URL suffixes as an alternative. `wireaudit` follows the header-based approach (RFC 9110 §12) and would not flag the absence of suffixes.

## References

Status is as listed by the [RFC Editor](https://www.rfc-editor.org/) (checked 2026-10-07). Every RFC links to its canonical page at `https://www.rfc-editor.org/rfc/rfcNNNN`.

### Core HTTP (current)

| RFC | Title | Role |
|---|---|---|
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | Methods, status codes, header fields, content negotiation, conditional requests, range requests, authentication. Primary source for most `wireaudit` checks |
| [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111) | HTTP Caching | `Cache-Control`, `Age`, `Expires`, freshness and validation |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) | HTTP/1.1 | Message syntax, framing (`Content-Length`, chunked), connection management |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) | HTTP/2 | Binary framing, multiplexing (planned coverage) |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 | HTTP over QUIC (planned coverage) |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) | QPACK: Field Compression for HTTP/3 | HTTP/3 header compression |
| [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) | HPACK: Header Compression for HTTP/2 | HTTP/2 header compression |
| [RFC 9931](https://www.rfc-editor.org/rfc/rfc9931) | Security Considerations for Optimistic Protocol Transitions in HTTP/1.1 | Updates RFC 9112 and RFC 9298 |

### HTTPS, TLS and transport security

| RFC | Title | Role |
|---|---|---|
| [RFC 9110 §4.3.3](https://www.rfc-editor.org/rfc/rfc9110#section-4.3.3) | HTTPS | Certificate verification for `https` URIs (obsoletes RFC 2818 "HTTP Over TLS") |
| [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846) | TLS 1.3 | Obsoletes RFC 8446 and RFC 5246 |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | TLS 1.3 (original) | Obsoleted by RFC 9846 |
| [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) | TLS 1.2 | Obsoleted by RFC 8446 / RFC 9846; still widely deployed |
| [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) | Deprecating TLS 1.0 and TLS 1.1 | Basis for `TLS-002` |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | X.509 PKI Certificate and CRL Profile | Basis for `TLS-001` |
| [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) | HTTP Strict Transport Security (HSTS) | Basis for `TLS-004` |
| [RFC 8740](https://www.rfc-editor.org/rfc/rfc8740) | Using TLS 1.3 with HTTP/2 | Obsoleted by RFC 9113 |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) / [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) / [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC transport, TLS for QUIC, loss detection | Transport underneath HTTP/3 |
| [RFC 7838](https://www.rfc-editor.org/rfc/rfc7838) | HTTP Alternative Services (`Alt-Svc`) | Advertising HTTP/2 / HTTP/3 endpoints |
| [RFC 8470](https://www.rfc-editor.org/rfc/rfc8470) | Using Early Data in HTTP | TLS 1.3 0-RTT replay safety (`425 Too Early`) |
| [RFC 7469](https://www.rfc-editor.org/rfc/rfc7469) | Public Key Pinning Extension for HTTP | Listed for completeness; pinning is not recommended |
| [RFC 9163](https://www.rfc-editor.org/rfc/rfc9163) | Expect-CT Extension for HTTP | Experimental; listed for completeness |

### Syntax building blocks

| RFC | Title |
|---|---|
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | URI: Generic Syntax |
| [RFC 3987](https://www.rfc-editor.org/rfc/rfc3987) | Internationalized Resource Identifiers (IRIs) |
| [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234) | ABNF for Syntax Specifications |
| [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) / [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651) | Structured Field Values for HTTP (RFC 9651 obsoletes RFC 8941) |
| [RFC 8187](https://www.rfc-editor.org/rfc/rfc8187) | Character Encoding and Language for Header Field Parameters |
| [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) | Well-Known URIs (obsoletes RFC 5785) |
| [RFC 6648](https://www.rfc-editor.org/rfc/rfc6648) | Deprecating the `X-` prefix |
| [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838) | Media Type Specifications and Registration Procedures |

### Header, status-code and method extensions

| RFC | Title |
|---|---|
| [RFC 5789](https://www.rfc-editor.org/rfc/rfc5789) | `PATCH` method |
| [RFC 6585](https://www.rfc-editor.org/rfc/rfc6585) | Additional status codes (`428`, `429`, `431`, `511`) |
| [RFC 7725](https://www.rfc-editor.org/rfc/rfc7725) | `451 Unavailable For Legal Reasons` |
| [RFC 8297](https://www.rfc-editor.org/rfc/rfc8297) | `103 Early Hints` |
| [RFC 5861](https://www.rfc-editor.org/rfc/rfc5861) | `stale-while-revalidate` / `stale-if-error` |
| [RFC 8246](https://www.rfc-editor.org/rfc/rfc8246) | `Cache-Control: immutable` |
| [RFC 9211](https://www.rfc-editor.org/rfc/rfc9211) | `Cache-Status` header |
| [RFC 9213](https://www.rfc-editor.org/rfc/rfc9213) | Targeted HTTP Cache Control (`CDN-Cache-Control`) |
| [RFC 9209](https://www.rfc-editor.org/rfc/rfc9209) | `Proxy-Status` header |
| [RFC 8586](https://www.rfc-editor.org/rfc/rfc8586) | Loop detection in CDNs (`CDN-Loop`) |
| [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239) | `Forwarded` header |
| [RFC 7240](https://www.rfc-editor.org/rfc/rfc7240) | `Prefer` header |
| [RFC 8674](https://www.rfc-editor.org/rfc/rfc8674) | `safe` preference |
| [RFC 8288](https://www.rfc-editor.org/rfc/rfc8288) | Web Linking (`Link`; obsoletes RFC 5988) |
| [RFC 9218](https://www.rfc-editor.org/rfc/rfc9218) | Extensible Prioritization Scheme |
| [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) | Digest Fields (`Content-Digest`, `Repr-Digest`; obsoletes RFC 3230) |
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) | HTTP Message Signatures |
| [RFC 9745](https://www.rfc-editor.org/rfc/rfc9745) | `Deprecation` response header |
| [RFC 8942](https://www.rfc-editor.org/rfc/rfc8942) | HTTP Client Hints |
| [RFC 7578](https://www.rfc-editor.org/rfc/rfc7578) | `multipart/form-data` |
| [RFC 8188](https://www.rfc-editor.org/rfc/rfc8188) | Encrypted Content-Encoding |
| [RFC 3229](https://www.rfc-editor.org/rfc/rfc3229) | Delta encoding in HTTP |

### Authentication, state and origin

| RFC | Title |
|---|---|
| [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617) | `Basic` authentication scheme |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | OAuth 2.0 Bearer Token Usage |
| [RFC 9729](https://www.rfc-editor.org/rfc/rfc9729) | Concealed HTTP Authentication Scheme |
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | OAuth 2.0 Protected Resource Metadata |
| [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265) | HTTP State Management (cookies) |
| [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454) | The Web Origin Concept |

### API design

| RFC | Title |
|---|---|
| [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) | Problem Details for HTTP APIs (obsoletes RFC 7807) |
| [RFC 9205](https://www.rfc-editor.org/rfc/rfc9205) | Building Protocols with HTTP (BCP 56) |
| [RFC 6902](https://www.rfc-editor.org/rfc/rfc6902) | JSON Patch |

### Tunnelling, proxying and upgrade

| RFC | Title |
|---|---|
| [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) | The WebSocket Protocol |
| [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441) | Bootstrapping WebSockets with HTTP/2 |
| [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) | Bootstrapping WebSockets with HTTP/3 |
| [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) | HTTP Datagrams and the Capsule Protocol |
| [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) | Proxying UDP in HTTP |
| [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) | Proxying IP in HTTP |
| [RFC 8336](https://www.rfc-editor.org/rfc/rfc8336) / [RFC 9412](https://www.rfc-editor.org/rfc/rfc9412) | `ORIGIN` frame for HTTP/2 and HTTP/3 |
| [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458) | Oblivious HTTP |
| [RFC 9440](https://www.rfc-editor.org/rfc/rfc9440) | Client-Cert HTTP header field |

### WebDAV

| RFC | Title |
|---|---|
| [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918) | HTTP Extensions for WebDAV |
| [RFC 3253](https://www.rfc-editor.org/rfc/rfc3253) | Versioning Extensions to WebDAV |
| [RFC 3744](https://www.rfc-editor.org/rfc/rfc3744) | WebDAV Access Control Protocol |
| [RFC 4331](https://www.rfc-editor.org/rfc/rfc4331) | Quota and Size Properties for DAV Collections |
| [RFC 5842](https://www.rfc-editor.org/rfc/rfc5842) | Binding Extensions to WebDAV |

### REST design guidance (non-normative)

| Source | Role |
|---|---|
| [restfulapi.net](https://restfulapi.net/) | REST tutorial and best-practice guides (naming, methods, status codes, errors, caching, negotiation, idempotence, security, pagination, versioning, HATEOAS). Not a standard; used as a checklist. See [Coverage](#by-rest-best-practice-restfulapinet) for what `wireaudit` checks |

### Superseded — do not cite for new checks

When a finding or rule cites one of these, map it to the current RFC instead.

| Obsolete RFC | Replaced by |
|---|---|
| [RFC 1945](https://www.rfc-editor.org/rfc/rfc1945) (HTTP/1.0) | Informational; behavior folded into RFC 9110 / RFC 9112 |
| [RFC 2068](https://www.rfc-editor.org/rfc/rfc2068), [RFC 2616](https://www.rfc-editor.org/rfc/rfc2616) (HTTP/1.1) | RFC 9110, RFC 9111, RFC 9112 |
| [RFC 2817](https://www.rfc-editor.org/rfc/rfc2817) (Upgrading to TLS within HTTP/1.1) | Updated by RFC 7230 / RFC 7231; use RFC 9110 §7.8 |
| [RFC 2818](https://www.rfc-editor.org/rfc/rfc2818) (HTTP Over TLS) | RFC 9110 §4.3.3 |
| [RFC 7230](https://www.rfc-editor.org/rfc/rfc7230) | RFC 9110, RFC 9112 |
| [RFC 7231](https://www.rfc-editor.org/rfc/rfc7231), [RFC 7232](https://www.rfc-editor.org/rfc/rfc7232), [RFC 7233](https://www.rfc-editor.org/rfc/rfc7233), [RFC 7235](https://www.rfc-editor.org/rfc/rfc7235) | RFC 9110 |
| [RFC 7234](https://www.rfc-editor.org/rfc/rfc7234) | RFC 9111 |
| [RFC 7540](https://www.rfc-editor.org/rfc/rfc7540) | RFC 9113 |
| [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) | RFC 9457 |
| [RFC 3230](https://www.rfc-editor.org/rfc/rfc3230) | RFC 9530 |
| [RFC 5988](https://www.rfc-editor.org/rfc/rfc5988) | RFC 8288 |

## Development

```bash
go build ./...
go vet ./...
go test ./...
golangci-lint run ./...
```
