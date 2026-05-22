# Example scripts

Scripts live in [`examples/`](../examples/) in the **ruso-script** repository.

Install or build [ruso-cli](https://github.com/Hopeless-Labs/ruso-cli), then from a clone of **ruso-script**:

```bash
ruso parse --script examples/<file>.ruso
ruso scan --script examples/http_health.ruso --target https://example.com
```

Or build the CLI from a sibling clone:

```bash
cd ../ruso-cli && cargo build --release
../ruso-cli/target/release/ruso parse --script ../ruso-script/examples/http_health.ruso
```

## `http_health.ruso`

**Purpose:** Minimal HTTP GET health check.

**Concepts:** `http` probe, `send`, `match` on `status` and `body`.

**Metadata:** `references` only (info/demo check).

**Run:**

```bash
ruso scan --script examples/http_health.ruso --target https://example.com
```

Requires a reachable HTTPS target; adjust matchers to match the real response.

---

## `dns_resolve.ruso`

**Purpose:** OS resolver mode (DNS probe with **only** `host`).

**Concepts:** `dns` without `port`/`payload`, `match lookup.answer`.

**Metadata:** `references` (resolver-mode demo).

**Run:** `--target` is unused for resolution; host is `one.one.one.one` in the script.

---

## `dns_wire_a.ruso`

**Purpose:** Wire-format DNS A query over UDP.

**Concepts:**

- `host` + `port 53` + hex `payload`  
- Binary DNS packet (query for `example.com`)  
- `match wire_a.response regex '.+'` (non-empty reply)

**Metadata:** `cwe`, `references` (wire-format demo).

**Run:** Needs UDP/53 reachability to `1.1.1.1` (or change `host`).

---

## `tcp_ssh_banner.ruso`

**Purpose:** TCP banner grab without sending data.

**Concepts:**

- `tcp` with `host` + `port 22`, no `payload`  
- SSH sends banner on connect  
- `match ssh_banner.response contains "SSH"`

**Metadata:** `cwe`, `cvss_score`, `references` (banner disclosure / fingerprinting).

**Run:** Example uses `scanme.nmap.org:22`; use only on systems you are allowed to scan.

---

## `tcp_redis_unauth.ruso`

**Purpose:** Detect unauthenticated Redis via RESP `PING`.

**Concepts:**

- Text `payload` with RESP encoding  
- `match redis_ping.response contains "PONG"`  
- `evidence regex 'PONG'`

**Metadata:** full advisory block — `cve`, `cwe`, `cvss`, `cvss_score`, `references`, `mitigation` (repeatable lines).

**Run:** Set `host` in script to your lab Redis (default `127.0.0.1:6379`).

---

## `udp_ntp.ruso`

**Purpose:** UDP probe shape (same fields as `tcp`/`dns` wire).

**Concepts:**

- `udp` + `port 123` + 48 zero bytes (NTP client request)  
- `pool.ntp.org` as example host

**Metadata:** `cve`, `cwe`, `cvss`, `cvss_score`, `references`, `mitigation` (NTP amplification class).

**Run:** May timeout on firewalled networks; validates UDP send/receive path.

---

## `tcp_session_loop.ruso`

**Purpose:** Stateful TCP + loop.

**Concepts:**

- `session true` — reuse connection  
- `read_idle 200ms` — aggregate multi-packet reads  
- `repeat 2 { send … match … }` — generic multi-step without new opcodes  

**Metadata:** `cwe`, `cvss_score`, `references`, `mitigation` (session reuse on unauthenticated Redis).

**Run:** Requires Redis on `127.0.0.1:6379` (same as redis example).

---

## Mapping examples to scanner patterns

| Pattern | Example |
|---------|---------|
| Web VA | `http_health.ruso` |
| Service fingerprint / banner | `tcp_ssh_banner.ruso` |
| Cleartext protocol test | `tcp_redis_unauth.ruso` |
| DNS recon | `dns_resolve.ruso` |
| Custom UDP / binary | `udp_ntp.ruso`, `dns_wire_a.ruso` |
| Multi-step socket | `tcp_session_loop.ruso` |

## Writing your own

1. Copy the closest example.  
2. Change metadata for your finding (`name`, `severity`, `cve`, `cwe`, `references`, `cvss`, `cvss_score`, `mitigation`, …).  
3. Adjust `host`/`port`/`payload` or HTTP `path`.  
4. Tighten matchers to reduce false positives.  
5. Add `evidence` for report body.

See [DSL reference](DSL_REFERENCE.md) for full syntax.
