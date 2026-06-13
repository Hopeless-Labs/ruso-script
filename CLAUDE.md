# ruso-script — guidance for Claude

Parser and compiler for the **Ruso Scripting Language (RSL)**: `.rsl` source →
`BytecodeProgram` (consumed by `ruso-runtime`).

Documentation lives in **The Ruso Book** (<https://docs.ruso.hopeless-labs.com>),
not in this repo — the local `docs/` was removed; the book is the single source.

## Quality gate (keep green before any commit)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets
cargo test
```

## Dev setup

Depends on `ruso-runtime`. Clone it as a sibling and the `paths` override in
`Cargo.toml` picks it up; otherwise Cargo uses the `git` dependency on `main`.

## Conventions

- Grammar lives in `src/script/grammar.pest` (Pest compiles it at build time —
  no codegen step). Bundled examples are `examples/*.rsl`.
- Keep `///` docs accurate — the book's `/api` rustdoc is generated from them.
- **Don't bump the version on every change** — accumulate notes under the
  current `0.1.0-beta.x` heading in `CHANGELOG.md`.
- Branding: the language is the Ruso Scripting Language (RSL); source is `.rsl`,
  bytecode is `.rbc`. The binary format MAGIC stays `RUSO`.
- Match the surrounding code's style and comment density.
