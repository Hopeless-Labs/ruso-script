# ruso-script

Parser and compiler for the Ruso DSL (`.ruso` → `BytecodeProgram`).

## Documentation

- [DSL reference](../docs/DSL_REFERENCE.md)
- [Compiler pipeline](../docs/COMPILER.md)
- [Examples](../docs/EXAMPLES.md)

## Usage

```rust
use ruso_script::{parse, compile};

let program = parse(source)?;
let bytecode = compile(&program);
// Pass bytecode to ruso_runtime::Executor
```

## Layout

```
src/
  compile.rs          # AST → Instr
  spec_build.rs       # AST → ProgramSpec
  script/
    grammar.pest      # syntax
    ast.rs
    parser/           # Pest builders
    syntax_tests.rs
examples/*.ruso
```

## Examples

```bash
cargo build -p ruso-cli
ruso parse --script examples/http_health.ruso
```

## License

MIT OR Apache-2.0
