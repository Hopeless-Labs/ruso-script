# Ruso DSL reference

Scripts use the `.ruso` extension. Syntax is line-oriented statements; blocks use `keyword name { … }` with `end` closing `if`, `match all`, `match any`, and `repeat`.

Keywords are **case-insensitive** (`HTTP`, `http`, `Send` are equivalent).

## File structure

Typical check layout:

```ruso
name "Check title"
description "What this check does"
impact "Risk if positive"
severity high
author "team"
cve "CVE-2024-1234"
cwe "CWE-79"
references "https://example.com/advisory"
cvss_score 9.8
cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
mitigation "Apply security patch"

# Probes (definitions only — no network yet)
http home { … }
tcp svc { … }

# Logic
send home
match home.status == 200

evidence home regex 'secret'
```

Comments start with `#`.

## Metadata

| Statement | Example |
|-----------|---------|
| `name` | `name "Open Redis"` |
| `description` | `description "…"` |
| `impact` | `impact "…"` |
| `severity` | `severity low \| medium \| high \| critical \| info` |
| `author` | `author "ruso-lab"` |
| `report` | `report "Report title override"` |
| `cve` | `cve "CVE-2024-1234"` (repeat to list multiple) |
| `cwe` | `cwe "CWE-79"` (repeat to list multiple) |
| `references` | `references "https://…"` (repeat to list multiple) |
| `cvss` | `cvss "CVSS:3.1/…"` full vector string (repeat to list multiple) |
| `cvss_score` | `cvss_score 9.8` numeric score literal (repeat to list multiple) |
| `mitigation` | `mitigation "…"` remediation text (repeat to list multiple) |

Repeat metadata lines on separate lines to build a list. Use `cvss` for vectors and `cvss_score` for scores (e.g. base + temporal). Values are stored on `CheckMetadata` and copied into findings and scan reports unchanged.

## Variables

```ruso
set token "abc123"
```

Values support `"{{ variable }}"` interpolation in strings where the grammar allows `interpolation`.

### Scan target variables (from CLI `--target`)

Before your script runs, the executor sets (when `--target` is a valid URL):

| Variable | Example value |
|----------|----------------|
| `scan_host` | `example.com` |
| `scan_port` | `443` |
| `scan_url` | `https://example.com` |

Use in socket probes: `host "{{scan_host}}"`. **HTTP** probes still use `base_url` from `--target`; they do not read `host` from the probe block.

## HTTP probe

```ruso
http <name> {
    method get | post | put | patch | delete
    path "/api/health"
    timeout 30s
    follow_redirect true
    verify_ssl true   # optional; overrides runtime default (skip verify). Use true for strict HTTPS checks
    proxy "http://127.0.0.1:8080"
    user_agent "ruso/1.0"
    header "X-Custom" "value"
    cookie "session" "id"
    query "q" "search"
    data { key "value" }
    json { key "value" }
    raw 'body.*pattern'
    body_bytes "504b0304"
    multipart { … }
}
```

HTTP requests use `ExecutorConfig.base_url` from the CLI `--target` (scheme + host + optional port). Probe `path` is appended to that base.

## Socket probes (dns / tcp / udp)

Same fields for all three keywords:

```ruso
tcp | udp | dns <name> {
    host "127.0.0.1"      # required
    port 6379             # optional (required at runtime for tcp/udp)
    payload "text"        # optional UTF-8 string
    payload "aabbccdd"    # optional hex (quoted hex digits)
    tls true              # TCP only: TLS before app data
    session true          # keep connection for repeated send
    read_max 65536        # max bytes per read phase (default 65536)
    read_idle 200ms       # multi-read until idle (0 = single read)
}
```

### DNS modes

| Configuration | Behavior | Match on |
|---------------|----------|----------|
| `host` only | OS DNS resolver | `.answer` |
| `host` + `port` and/or `payload` | UDP wire format (default port 53) | `.response` / `.banner` |

Do not use `.answer` on wire-mode probes or `.response` on resolver-only probes.

### Payload encoding

- **String** — sent as UTF-8 bytes (Redis RESP, SMTP text, …).
- **Hex literal** — `payload "010203ff"` decodes to raw bytes (DNS queries, NTP, …).

## Send

```ruso
send <probe_name>
send <probe_name> payload "next message"
send <probe_name> payload "deadbeef"
```

- First `send` on a `session true` probe opens the connection.
- Later `send` reuses the socket; with `session true`, response data is **appended** to the stored socket response (matchers see the full dialog).
- Without `session`, each `send` **replaces** the stored response for that probe name.
- `payload` on `send` overrides the probe definition for that step only.

## Matching

Single matcher:

```ruso
match <probe>.<field> <predicate>
assert <probe>.<field> <predicate>
```

Groups:

```ruso
match all
    home.status == 200
    home.body contains "ok"
end

match any
    home.status == 403
    home.status == 401
end
```

### HTTP fields

| Field | Example |
|-------|---------|
| `status` | `match home.status == 200` |
| `body` | `match home.body contains "admin"` |
| `header("Name")` | `match home.header("Server") contains "nginx"` |
| `response_time` | `match home.response_time < 500ms` |
| `response_size` | `match home.response_size > 100` |

### DNS resolver fields

| Field | Example |
|-------|---------|
| `answer` | `match lookup.answer contains "1.1.1.1"` |

### Socket fields (tcp / udp / wire dns)

| Field | Example |
|-------|---------|
| `response` | `match redis.response contains "PONG"` |
| `banner` | alias for `response` |

### Predicates

| Form | Example |
|------|---------|
| Compare | `==`, `!=`, `<`, `>`, `<=`, `>=` with number, string, or duration |
| Contains | `contains "text"` |
| Not contains | `not_contains "text"` |
| Regex | `regex 'pattern'` (Rust regex syntax) |

If any `match` / `match all` fails, the match chain latches false (later `match` / `match all` / `assert` / `evidence` short-circuit until `if` runs its own branch).

### `match` vs `assert`

| | `match` | `assert` |
|---|--------|----------|
| On failure | Sets match chain to false; run continues | **Aborts the run** with an error |
| When chain already false | Skipped (no-op) | Skipped (no-op) |
| Use for | Positive finding logic | Hard precondition (“must be 200 before we continue”) |

## Conditionals

```ruso
if home.status == 200
    match home.body contains "secret"
end
```

Compiled to `IfMatch` — skips body when chain already failed or condition false.

## Loops

```ruso
repeat 3
    send dialog
    match dialog.response contains "PONG"
    break
end
```

- `repeat N` — body runs N times (`LoopBack` decrements counter).
- `break` — jump to instruction after the loop.

There is no `while` or `for` with variables yet—only fixed-count `repeat`.

## Extract and save

```ruso
extract token from home.header("Set-Cookie") regex 'session=([^;]+)'
save home as cached
```

`extract` is HTTP-only (body or header). `save` copies an existing probe response to another name — it does **not** send again; `match cached.body` is a snapshot from when `save` ran.

## Evidence

Attach proof strings to the finding (only when the match chain is still true). Requires `name` or `report` metadata if the script uses `match` / `evidence` (compile-time check).

```ruso
evidence home.body
evidence home.response
evidence home regex 'PASSWORD='
evidence redis_ping regex 'PONG'
```

| Form | Meaning |
|------|---------|
| `evidence <probe>.body` | **HTTP only** — response body (max 500 chars) |
| `evidence <probe>.response` | Full response text: HTTP body, joined DNS answers, or socket data (max 500 chars) |
| `evidence <probe> regex '…'` | Regex on **that probe only**; capture group 1 or full match |

`<probe>` must already have been `send` in this run. Regex uses Rust syntax; mismatch fails the run.

Evidence is attached when the script finishes with a finding (`name` or `report` set, match chain true, and not stopped — see flow control).

## Retry and sleep

```ruso
retry_delay 2s
retry home 3
sleep 1s
```

## Flow control

| Statement | Effect |
|-----------|--------|
| `stop` | Stop script; **no finding** emitted (even if matchers passed) |
| `exit` | Stop script; emit finding if matchers passed and `name`/`report` set |
| `fail` | Abort with error |
| `continue` | Reserved — no effect today (do not rely on it) |

Scripts with `match` / `evidence` must include `name "…"` or `report "…"` or compilation fails.

## Duration literals

Suffix `ms` or `s`: `200ms`, `30s`, `1s`. Used in `timeout`, `read_idle`, `sleep`, `retry_delay`, and comparisons.

## Common footguns

1. **`--target` vs socket `host`** — HTTP uses `--target` as base URL; TCP/UDP/DNS wire use `host` in the script (prefer `host "{{scan_host}}"`).
2. **DNS resolver vs wire** — different match fields (`.answer` vs `.response`).
3. **`evidence home.body` on a TCP probe** — use `.response` or `evidence home regex`.
4. **`detected` in CLI** — requires a finding (`name`/`report` + matchers passed + not `stop`).
5. **Port cache (30s)** — `skipped` is per script run when a required port was already seen closed in this `ruso` process.
6. **`session true`** — socket responses accumulate across `send` in a loop.

## Grammar source

Authoritative syntax: `ruso-script/src/script/grammar.pest`.  
After grammar changes, regenerate is not required (Pest compiles at build time).
