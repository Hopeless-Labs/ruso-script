# ruso-script

> [!NOTE]
> **Development status:** under active development. The RSL, compiler output, and
> grammar may change without notice. Not recommended for production use yet.

Parser and compiler for the **Ruso Scripting Language (RSL)**: `.rsl` source →
`BytecodeProgram`. Part of the [Ruso](https://github.com/Hopeless-Labs)
vulnerability-scanning ecosystem.

📖 **Full documentation:** <https://docs.ruso.hopeless-labs.com>
(language reference, examples, compiler internals).

## Usage

```rust
use ruso_script::{parse, compile};

let program = parse(source)?;
let bytecode = compile(&program);
// hand the bytecode to ruso_runtime::Executor
```

Dependency:

```toml
ruso-script = { git = "https://github.com/Hopeless-Labs/ruso-script.git", branch = "main" }
```

## In this repo

- `examples/*.rsl` — example checks
- `src/script/grammar.pest` — the grammar (source of truth for syntax)

Everything else — language reference, tutorials, architecture — lives in
**[The Ruso Book](https://docs.ruso.hopeless-labs.com)**.

## License

Apache License 2.0. See [LICENSE](LICENSE).
