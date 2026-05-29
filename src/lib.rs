//! Parse Ruso DSL source into an AST and compile to `ruso-runtime` bytecode.
//!
//! # Developer documentation
//!
//! - [DSL reference](https://github.com/Hopeless-Labs/ruso-script/blob/main/docs/DSL_REFERENCE.md)
//! - [Compiler](https://github.com/Hopeless-Labs/ruso-script/blob/main/docs/COMPILER.md)
//! - [Examples](https://github.com/Hopeless-Labs/ruso-script/blob/main/docs/EXAMPLES.md)

// `ParseError::Pest` wraps `pest::error::Error`, which carries spans + rule
// chain for useful diagnostics and is naturally large. Boxing it would obscure
// the public error type at call sites; the size lint is noise here.
#![allow(clippy::result_large_err)]

mod compile;
pub mod script;
mod spec_build;

pub use compile::{CompileError, compile};
pub use ruso_runtime::{
    BytecodeProgram, EvidenceKind, ExtractSource, QualifiedMatch, Severity, encode_bytecode,
};
pub use script::ast::{self, Program, Stmt};
pub use script::{ParseError, parse};

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("failed to read {}: {source}", path.display())]
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {}: {source}", path.display())]
    Parse {
        path: std::path::PathBuf,
        source: ParseError,
    },
}

pub fn load_program(path: &Path) -> Result<Program, LoadError> {
    let source = std::fs::read_to_string(path).map_err(|err| LoadError::Io {
        path: path.to_path_buf(),
        source: err,
    })?;
    parse(&source).map_err(|err| LoadError::Parse {
        path: path.to_path_buf(),
        source: err,
    })
}

pub fn compile_program(program: &Program) -> Result<BytecodeProgram, CompileError> {
    compile(program)
}

pub fn compile_to_bytes(program: &Program) -> Result<Vec<u8>, CompileError> {
    Ok(encode_bytecode(&compile_program(program)?))
}

pub async fn run(
    program: &Program,
    config: ruso_runtime::ExecutorConfig,
) -> Result<ruso_runtime::ExecutionResult, ruso_runtime::RuntimeError> {
    let bytecode =
        compile_program(program).map_err(|e| ruso_runtime::RuntimeError::Other(e.to_string()))?;
    ruso_runtime::Executor::from_bytecode(config, bytecode)?
        .run()
        .await
}

pub async fn run_bytecode(
    bytecode: &BytecodeProgram,
    config: ruso_runtime::ExecutorConfig,
) -> Result<ruso_runtime::ExecutionResult, ruso_runtime::RuntimeError> {
    ruso_runtime::Executor::from_bytecode(config, bytecode.clone())?
        .run()
        .await
}

/// Run a pre-shared [`Arc<BytecodeProgram>`] against a single target.
///
/// Prefer this over [`run_bytecode`] when running the same compiled script
/// against many targets — the program is cloned via `Arc::clone` (a
/// reference-count bump) instead of being deep-copied for each run.
pub async fn run_program(
    bytecode: std::sync::Arc<BytecodeProgram>,
    config: ruso_runtime::ExecutorConfig,
) -> Result<ruso_runtime::ExecutionResult, ruso_runtime::RuntimeError> {
    ruso_runtime::Executor::from_program(config, bytecode)?
        .run()
        .await
}

pub async fn run_bytes(
    bytes: &[u8],
    config: ruso_runtime::ExecutorConfig,
) -> Result<ruso_runtime::ExecutionResult, ruso_runtime::RuntimeError> {
    ruso_runtime::Executor::from_bytes(config, bytes)?
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ruso_runtime::{bytes_to_hex, decode_bytecode, hex_to_bytes};

    use super::*;
    use crate::script::ast::Stmt;

    #[test]
    fn load_program_valid_example() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/http_status_ok.ruso");
        let program = load_program(&path).expect("example script should parse");
        assert!(!program.statements.is_empty());
    }

    #[test]
    fn bytecode_roundtrip_http_example() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/http_status_ok.ruso");
        let program = load_program(&path).unwrap();
        let original = compile_program(&program).unwrap();
        let bytes = encode_bytecode(&original);
        let restored = decode_bytecode(&bytes).unwrap();
        assert_eq!(original.code, restored.code);
        assert_eq!(original.strings, restored.strings);
        assert_eq!(original.matchers, restored.matchers);
    }

    #[test]
    fn hex_bytes_roundtrip() {
        let program = Program {
            statements: vec![Stmt::Name("Hex test".into()), Stmt::Severity(Severity::Low)],
        };
        let bytes = compile_to_bytes(&program).unwrap();
        let hex = bytes_to_hex(&bytes);
        let restored = hex_to_bytes(&hex).expect("hex decode");
        let decoded = decode_bytecode(&restored).expect("bytecode decode");
        assert_eq!(decoded.spec.metadata.name.as_deref(), Some("Hex test"));
    }
}
