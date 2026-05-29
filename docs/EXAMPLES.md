# Example scripts

Scripts live in [`examples/`](../examples/) in the **ruso-script** repository:
two runnable checks per protocol (HTTP, DNS, TCP, UDP). Every example has been
verified against a local Docker target.

Install or build [ruso-cli](https://github.com/Hopeless-Labs/ruso-cli), then
from a clone of **ruso-script**:

```bash
ruso validate --script examples/http_status_ok.ruso          # syntax + compile, no network
ruso scan --script examples/http_status_ok.ruso --target http://127.0.0.1:8080
```

Socket examples (`dns`/`tcp`/`udp`) take the host from `--target` via
`{{scan_host}}`; the port is the literal in the probe block. HTTP examples use
`--target` as the base URL.

## HTTP

### `http_status_ok.ruso`
**Purpose:** Endpoint availability + content check.
**Concepts:** `http` probe, `send`, `match` on `status` / `body` / `header`, `evidence`.
**Run:** `ruso scan --script examples/http_status_ok.ruso --target http://127.0.0.1:8080`

### `http_server_version_disclosure.ruso`
**Purpose:** Flag a `Server` header that leaks the product version (info disclosure).
**Concepts:** `HEAD` request, `match … header "Server" regex 'nginx/[0-9]+\.[0-9]+'`.
**Note:** Detects `nginx/1.31.1`; stays quiet when `server_tokens off` yields a bare `nginx`.

## DNS (wire mode over UDP)

### `dns_wire_a.ruso`
**Purpose:** Raw A query, confirm the server answers.
**Concepts:** `dns` with `host` / `port 53` / hex `payload bytes`; `match wire_a.response contains "ruso"` (the queried labels echo back in the response).

### `dns_wire_txt.ruso`
**Purpose:** Read a TXT record's plaintext value (TXT often carries tokens/secrets).
**Concepts:** Same shape as `dns_wire_a` with QTYPE TXT; `match … contains "ruso-dns-ok"` (TXT rdata is ASCII).

## TCP

### `tcp_redis_unauth.ruso`
**Purpose:** Detect unauthenticated Redis via RESP `PING` → `PONG`.
**Concepts:** `payload bytes "<hex>"` for the RESP `*1\r\n$4\r\nPING\r\n` frame (text payloads are sent verbatim, so control bytes must be hex), `read_idle`, `match … contains "PONG"` + `not_contains "NOAUTH"`, `evidence`.

### `tcp_http_banner.ruso`
**Purpose:** Banner-grab a text protocol over a raw TCP socket.
**Concepts:** `tcp` probe sending a hex-encoded `HEAD / HTTP/1.0` request, `match … contains "HTTP/1."` and `"Server:"`.

## UDP

### `udp_ntp.ruso`
**Purpose:** Confirm an NTP daemon replies (reflection/amplification exposure class).
**Concepts:** `udp` + `port 123` + a 48-byte client packet (`payload bytes "1b00…"`), `match ntp.response regex '^\x1c'` (server-mode reply byte).

### `udp_echo.ruso`
**Purpose:** Generic UDP request/response.
**Concepts:** Text `payload`, `match echo.response contains "RUSO-PING"`.

## Mapping examples to scanner patterns

| Pattern | Example |
|---------|---------|
| Web availability / content | `http_status_ok.ruso` |
| Header / version disclosure | `http_server_version_disclosure.ruso` |
| DNS recon (wire) | `dns_wire_a.ruso`, `dns_wire_txt.ruso` |
| Cleartext protocol test | `tcp_redis_unauth.ruso` |
| Service fingerprint / banner | `tcp_http_banner.ruso` |
| UDP service probe | `udp_ntp.ruso`, `udp_echo.ruso` |

## Writing your own

1. Copy the closest example.
2. Change metadata for your finding (`name`, `severity`, `cve [...]`, `cwe [...]`, `references [...]`, `cvss`, `cvss_score`, a single `mitigation`, …).
3. Adjust `host`/`port`/`payload` (use `payload bytes "<hex>"` for control/binary bytes) or the HTTP `path`.
4. Tighten matchers to reduce false positives.
5. Add `evidence` for the report body.

See [DSL reference](DSL_REFERENCE.md) for full syntax.
