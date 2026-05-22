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

# Probes (definitions only — no network yet)
http home { … }
tcp svc { … }

# Logic
send home
match home.status == 200

evidence regex 'secret'
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

Repeat `cve`, `cwe`, or `references` on separate lines to build a list. They are stored on `CheckMetadata` and copied into findings and scan reports unchanged.

## Variables

```ruso
set token "abc123"
```

Values support `"{{ variable }}"` interpolation in strings where the grammar allows `interpolation`.

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

| Configuration | Behavior |
|---------------|----------|
| `host` only | OS DNS resolver → match `.answer` |
| `host` + `port` / `payload` | UDP wire format → match `.response` (default port 53) |

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
- Later `send` reuses the socket; response data is **appended** to the stored socket response.
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

If any `match` / `match all` fails, the match chain latches false (later matchers short-circuit unless you structure logic with `if`).

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

## Evidence

```ruso
evidence home.body
evidence regex 'PASSWORD='
```

Collected when match chain is still true; attached to the finding on completion.

## Retry and sleep

```ruso
retry_delay 2s
retry home 3
sleep 1s
```

## Flow control

| Statement | Effect |
|-----------|--------|
| `stop` | Stop VM, success path |
| `exit` | Stop VM |
| `fail` | Abort with error |
| `continue` | Next instruction |

## Duration literals

Suffix `ms` or `s`: `200ms`, `30s`, `1s`. Used in `timeout`, `read_idle`, `sleep`, `retry_delay`, and comparisons.

## Grammar source

Authoritative syntax: `ruso-script/src/script/grammar.pest`.  
After grammar changes, regenerate is not required (Pest compiles at build time).
