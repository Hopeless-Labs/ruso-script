# Ruso script documentation

Documentation for the **ruso-script** crate: Pest grammar, AST, and compiler to `ruso-runtime` bytecode.

## Reading order

1. **[Architecture overview](OVERVIEW.md)** — how script, runtime, and CLI fit together.
2. **[DSL reference](DSL_REFERENCE.md)** — everything you can write in `.ruso` files.
3. **[Compiler](COMPILER.md)** — `parse` → `ProgramSpec` + `compile` → `BytecodeProgram`.
4. **[Examples](EXAMPLES.md)** — bundled `examples/*.ruso` explained.

## Quick start

```rust
use ruso_script::{parse, compile};

let program = parse(source)?;
let bytecode = compile(&program);
// Hand off to ruso_runtime::Executor
```

```bash
# With ruso-cli installed (from ruso-cli repo)
ruso validate --script examples/http_status_ok.ruso
```

## Dependency

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso-runtime.git", branch = "main" }
```

Bytecode must target `ruso_runtime::VERSION` (currently **1**).

## Source map

| Path | Purpose |
|------|---------|
| `src/script/grammar.pest` | Syntax (source of truth) |
| `src/script/ast.rs` | AST types |
| `src/script/parser/` | Pest → AST |
| `src/spec_build.rs` | AST → `ProgramSpec` |
| `src/compile.rs` | AST → `Vec<Instr>` |
| `examples/*.ruso` | Example vulnerability checks |

## Runtime and CLI docs

| Topic | Where |
|-------|--------|
| Bytecode layout, opcodes | [ruso-runtime/docs](https://github.com/Hopeless-Labs/ruso-runtime/tree/main/docs) |
| VM execution, networking | [RUNTIME.md](https://github.com/Hopeless-Labs/ruso-runtime/blob/main/docs/RUNTIME.md) |
| Extending the VM | [EXTENDING.md](https://github.com/Hopeless-Labs/ruso-runtime/blob/main/docs/EXTENDING.md) |
| `ruso scan` / `compile` / … | [ruso-cli/docs/CLI.md](https://github.com/Hopeless-Labs/ruso-cli/blob/main/docs/CLI.md) |
