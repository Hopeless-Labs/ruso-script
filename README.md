# ruso-script

> **Development status:** This project is under active development. The DSL, compiler output, and grammar may change without notice. Not recommended for production use yet.

Parser and compiler for the Ruso DSL (`.ruso` → `BytecodeProgram`).

## Documentation

Full developer docs are in **[`docs/`](docs/README.md)**:

| Doc | Topic |
|-----|--------|
| [Architecture overview](docs/OVERVIEW.md) | How script, runtime, and CLI connect |
| [DSL reference](docs/DSL_REFERENCE.md) | Syntax for `.ruso` checks |
| [Compiler](docs/COMPILER.md) | Parse → AST → bytecode |
| [Examples](docs/EXAMPLES.md) | `examples/*.ruso` walkthrough |

Runtime bytecode and VM: [ruso-runtime/docs](https://github.com/Hopeless-Labs/ruso-runtime/tree/main/docs). CLI: [ruso-cli/docs](https://github.com/Hopeless-Labs/ruso-cli/tree/main/docs).

## Dependencies

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso-runtime.git", branch = "main" }
```

## Usage

```rust
use ruso_script::{parse, compile};

let program = parse(source)?;
let bytecode = compile(&program);
// Pass bytecode to ruso_runtime::Executor
```

## Layout

```text
src/
  compile.rs          # AST → Instr
  spec_build.rs       # AST → ProgramSpec
  script/
    grammar.pest      # syntax
    ast.rs
    parser/           # Pest builders
examples/*.ruso       # example checks
docs/                 # documentation
```

## Try examples

```bash
# Install ruso-cli from https://github.com/Hopeless-Labs/ruso-cli
ruso parse --script examples/http_health.ruso
ruso scan --script examples/http_health.ruso --target https://example.com
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
