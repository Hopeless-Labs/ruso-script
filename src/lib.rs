//! Parse Ruso Scripting Language (RSL) source into an AST and compile to
//! `ruso-runtime` bytecode.
//!
//! # Developer documentation
//!
//! - [Language reference](https://docs.ruso.hopeless-labs.com/rsl/reference.html)
//! - [Compiler](https://docs.ruso.hopeless-labs.com/internals/compiler.html)
//! - [Examples](https://docs.ruso.hopeless-labs.com/rsl/examples.html)

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

/// Error from [`load_program`]: reading the file failed, or its contents did
/// not parse.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The source file could not be read.
    #[error("failed to read {}: {source}", path.display())]
    Io {
        /// The path that failed to read.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The source file was read but did not parse as RSL.
    #[error("failed to parse {}: {source}", path.display())]
    Parse {
        /// The path that failed to parse.
        path: std::path::PathBuf,
        /// The underlying parse error.
        source: ParseError,
    },
}

/// Read and parse an `.rsl` file into a [`Program`] AST.
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

/// Compile a parsed [`Program`] into a [`BytecodeProgram`].
pub fn compile_program(program: &Program) -> Result<BytecodeProgram, CompileError> {
    compile(program)
}

/// Compile a [`Program`] and serialize it to a raw `.rbc` byte buffer.
pub fn compile_to_bytes(program: &Program) -> Result<Vec<u8>, CompileError> {
    Ok(encode_bytecode(&compile_program(program)?))
}

/// Compile a [`Program`] and run it against a single target in one step.
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

/// Run an already-compiled [`BytecodeProgram`] against a single target.
pub async fn run_bytecode(
    bytecode: &BytecodeProgram,
    config: ruso_runtime::ExecutorConfig,
) -> Result<ruso_runtime::ExecutionResult, ruso_runtime::RuntimeError> {
    ruso_runtime::Executor::from_bytecode(config, bytecode.clone())?
        .run()
        .await
}

/// Run a pre-shared `Arc<BytecodeProgram>` against a single target.
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

/// Decode a raw `.rbc` byte buffer and run it against a single target.
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
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/http_status_ok.rsl");
        let program = load_program(&path).expect("example script should parse");
        assert!(!program.statements.is_empty());
    }

    #[test]
    fn bytecode_roundtrip_http_example() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/http_status_ok.rsl");
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
