# Compiler (`ruso-script`)

The compiler turns `.ruso` source into a `BytecodeProgram` consumed by `ruso-runtime`.

## Public API

```rust
use ruso_script::{parse, compile};

let program = parse(source)?;
let bytecode = compile(&program)?;
```

| Function | Output |
|----------|--------|
| `parse` | `Program { statements: Vec<Stmt> }` |
| `compile` | `BytecodeProgram` |

Parse errors: `ParseError` (Pest or `Invalid` message).  
Compile does not fail on well-formed AST today—errors are parse-time.

## Pipeline

```
source text
    → Pest (Rule::program)
    → build_statement per item
    → Program
    → build_program_spec (metadata + probes only)
    → Compiler::emit_program (executable stmts)
    → BytecodeProgram
```

### `build_program_spec`

File: `src/spec_build.rs`.

Walks statements; collects:

- Metadata into `CheckMetadata`  
- `Stmt::Http` / `Dns` / `Tcp` / `Udp` into `ProgramSpec.probes: HashMap<String, ProbeKind>`  

Executable statements are ignored here.

### `compile`

File: `src/compile.rs`.

`Compiler` maintains:

- `code: Vec<Instr>`  
- `strings` + `string_ids` dedup map  
- `payloads` + `payload_ids` dedup map (byte equality)  
- `matchers`, `extracts`, `evidence` append-only pools  

Probe definitions (`Http`, `Dns`, …) emit nothing—only `send` triggers network ops at runtime.

### Control-flow compilation

**`if`**

```rust
let if_pc = emit(IfMatch { matcher, else_pc: 0 });
emit_program(body);
patch else_pc = code.len();
```

## Parser layout

| Module | Responsibility |
|--------|----------------|
| `grammar.pest` | Syntax |
| `parser/mod.rs` | `build_statement` dispatch |
| `parser/metadata.rs` | name, description, impact, severity, author, report, cve, cwe, references, cvss, cvss_score, mitigation, tags, version, family |
| `parser/probes.rs` | `http` block items |
| `parser/socket.rs` | `dns` / `tcp` / `udp` shared builder |
| `parser/match_expr.rs` | qualified matchers, groups |
| `parser/statements.rs` | send, if, for, flow, … (`repeat` kept only to reject with a migration error) |
| `parser/body.rs` | HTTP body objects |

### Nesting-depth guard

`pest` is a recursive-descent parser, so each nested block (`if` / `for` /
`repeat` … `end`) or object (`{ … }`) costs one parser stack frame. A few
thousand levels — well under the backend's 256 KiB source cap — overflow
the stack and **abort the process** (a stack overflow can't be caught by
`catch_unwind` and isn't bounded by the executor's wall-clock budget).
`parse()` therefore runs `check_nesting_depth` before handing the source
to pest: a single linear, string-/comment-aware scan that rejects input
nesting deeper than `MAX_NESTING_DEPTH` (64) with a graceful
`ParseError::Invalid`. The counter tracks simultaneously-open constructs,
which equals pest's recursion depth, so it can't be evaded by interleaving
brace and keyword nesting.

### Adding a socket option

1. Add keyword to `grammar.pest` (`socket_item` arm).  
2. Parse in `parser/socket.rs` → field on `SocketProbe`.  
3. Copy in `spec_build::socket_spec`.  
4. Extend `SocketProbeSpec` in runtime + `write_socket_probe` / `read_socket_probe`.  
5. Implement behavior in `session.rs` / `executor.rs`.  
6. Document in `DSL_REFERENCE.md` and bump `VERSION` if wire format changes.

### Adding a statement

1. `grammar.pest` — new `statement` alternative.  
2. `ast.rs` — `Stmt` variant.  
3. `parser` — builder.  
4. `compile.rs` — `emit_stmt` + new `Instr` if needed.  
5. `executor.rs` + `binary.rs` + `opcode.rs` for new instructions.

## AST highlights

```rust
pub struct SocketProbe {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub payload: Option<Vec<u8>>,
    pub tls: bool,
    pub session: bool,
    pub read_max: u32,
    pub read_idle_ms: u32,
}

pub enum Stmt {
    Send { probe: String, payload: Option<Vec<u8>> },
    Break,
    // …
}
```

## Syntax tests

`src/script/syntax_tests.rs` — parse-only tests for grammar regressions. Run when changing parser:

```bash
cargo test -p ruso-script
```

## Examples

Bundled under `examples/*.ruso` in this repository — living documentation (see [EXAMPLES.md](EXAMPLES.md)).
