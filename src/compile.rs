//! Lower script AST to bytecode for `ruso-runtime`.

use std::collections::HashMap;

use ruso_runtime::opcode::Opcode as Instr;
use ruso_runtime::{BytecodeProgram, EvidenceKind, ExtractSource, QualifiedMatch};

use crate::script::ast::Stmt;
use crate::script::Program;
use crate::spec_build::build_program_spec;

pub fn compile(program: &Program) -> BytecodeProgram {
    let mut compiler = Compiler::new(build_program_spec(&program.statements));
    compiler.emit_program(&program.statements);
    compiler.finish()
}

struct Compiler {
    spec: ruso_runtime::ProgramSpec,
    code: Vec<Instr>,
    strings: Vec<String>,
    string_ids: HashMap<String, u32>,
    payloads: Vec<Vec<u8>>,
    payload_ids: HashMap<Vec<u8>, u32>,
    matchers: Vec<QualifiedMatch>,
    extracts: Vec<ExtractSource>,
    evidence: Vec<EvidenceKind>,
}

impl Compiler {
    fn new(spec: ruso_runtime::ProgramSpec) -> Self {
        Self {
            spec,
            code: Vec::new(),
            strings: Vec::new(),
            string_ids: HashMap::new(),
            payloads: Vec::new(),
            payload_ids: HashMap::new(),
            matchers: Vec::new(),
            extracts: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn finish(self) -> BytecodeProgram {
        BytecodeProgram {
            spec: self.spec,
            code: self.code,
            strings: self.strings,
            payloads: self.payloads,
            matchers: self.matchers,
            extracts: self.extracts,
            evidence: self.evidence,
        }
    }

    fn str_id(&mut self, value: impl Into<String>) -> u32 {
        let value = value.into();
        if let Some(&id) = self.string_ids.get(&value) {
            return id;
        }
        let id = self.strings.len() as u32;
        self.string_ids.insert(value.clone(), id);
        self.strings.push(value);
        id
    }

    fn payload_id(&mut self, bytes: Vec<u8>) -> u32 {
        if let Some(&id) = self.payload_ids.get(&bytes) {
            return id;
        }
        let id = self.payloads.len() as u32;
        self.payload_ids.insert(bytes.clone(), id);
        self.payloads.push(bytes);
        id
    }

    fn matcher_id(&mut self, matcher: QualifiedMatch) -> u32 {
        let id = self.matchers.len() as u32;
        self.matchers.push(matcher);
        id
    }

    fn extract_id(&mut self, source: ExtractSource) -> u32 {
        let id = self.extracts.len() as u32;
        self.extracts.push(source);
        id
    }

    fn evidence_id(&mut self, kind: EvidenceKind) -> u32 {
        let id = self.evidence.len() as u32;
        self.evidence.push(kind);
        id
    }

    fn emit(&mut self, instr: Instr) -> usize {
        let pc = self.code.len();
        self.code.push(instr);
        pc
    }

    fn emit_program(&mut self, statements: &[Stmt]) {
        for stmt in statements {
            self.emit_stmt(stmt);
        }
    }

    fn emit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Set { name, value } => {
                let name = self.str_id(name);
                let value = self.str_id(value);
                self.emit(Instr::Set { name, value });
            }
            Stmt::Send { probe, payload } => {
                let probe = self.str_id(probe);
                let payload = payload.as_ref().map(|bytes| self.payload_id(bytes.clone()));
                self.emit(Instr::Send { probe, payload });
            }
            Stmt::Match(matcher) => {
                let id = self.matcher_id(matcher.clone());
                self.emit(Instr::Match(id));
            }
            Stmt::MatchAll(matchers) => {
                let start = self.matchers.len() as u32;
                for matcher in matchers {
                    self.matchers.push(matcher.clone());
                }
                let len = (self.matchers.len() as u32 - start) as u16;
                self.emit(Instr::MatchAll { start, len });
            }
            Stmt::MatchAny(matchers) => {
                let start = self.matchers.len() as u32;
                for matcher in matchers {
                    self.matchers.push(matcher.clone());
                }
                let len = (self.matchers.len() as u32 - start) as u16;
                self.emit(Instr::MatchAny { start, len });
            }
            Stmt::Assert(matcher) => {
                let id = self.matcher_id(matcher.clone());
                self.emit(Instr::Assert(id));
            }
            Stmt::Extract { name, source } => {
                let name = self.str_id(name);
                let source = self.extract_id(source.clone());
                self.emit(Instr::Extract { name, source });
            }
            Stmt::If { condition, body } => {
                let matcher = self.matcher_id(condition.clone());
                let if_pc = self.emit(Instr::IfMatch {
                    matcher,
                    else_pc: 0,
                });
                self.emit_program(body);
                let else_pc = self.code.len() as u32;
                self.code[if_pc] = Instr::IfMatch { matcher, else_pc };
            }
            Stmt::Repeat { count, body } => {
                let repeat_pc = self.emit(Instr::Repeat {
                    count: *count,
                    end_pc: 0,
                });
                self.emit_program(body);
                self.emit(Instr::LoopBack);
                let end_pc = self.code.len() as u32;
                self.code[repeat_pc] = Instr::Repeat {
                    count: *count,
                    end_pc,
                };
            }
            Stmt::Break => {
                self.emit(Instr::Break);
            }
            Stmt::Save { request, alias } => {
                let from = self.str_id(request);
                let to = self.str_id(alias);
                self.emit(Instr::Save { from, to });
            }
            Stmt::Evidence(kind) => {
                let id = self.evidence_id(kind.clone());
                self.emit(Instr::Evidence(id));
            }
            Stmt::Retry { request, count } => {
                let probe = self.str_id(request);
                self.emit(Instr::Retry {
                    probe,
                    count: *count,
                });
            }
            Stmt::RetryDelay(value) => {
                let id = self.str_id(value);
                self.emit(Instr::RetryDelay(id));
            }
            Stmt::Sleep(value) => {
                let id = self.str_id(value);
                self.emit(Instr::Sleep(id));
            }
            Stmt::Stop => {
                self.emit(Instr::Stop);
            }
            Stmt::Fail => {
                self.emit(Instr::Fail);
            }
            Stmt::Continue => {
                self.emit(Instr::Continue);
            }
            Stmt::Exit => {
                self.emit(Instr::Exit);
            }
            Stmt::Name(_)
            | Stmt::Description(_)
            | Stmt::Impact(_)
            | Stmt::Severity(_)
            | Stmt::Author(_)
            | Stmt::Report(_)
            | Stmt::Cve(_)
            | Stmt::Cwe(_)
            | Stmt::Reference(_)
            | Stmt::Http { .. }
            | Stmt::Dns(_)
            | Stmt::Tcp(_)
            | Stmt::Udp(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use ruso_runtime::opcode::Opcode as Instr;

    use crate::script::ast::{
        CmpOp, CmpValue, FieldKind, MatchPredicate, QualifiedField, QualifiedMatch, Stmt,
    };
    use crate::script::Program;

    use super::compile;

    #[test]
    fn compile_skips_metadata_and_probe_definitions() {
        let program = Program {
            statements: vec![
                Stmt::Name("Check".into()),
                Stmt::Http {
                    name: "home".into(),
                    items: vec![],
                },
                Stmt::Send {
                    probe: "home".into(),
                    payload: None,
                },
                Stmt::Match(QualifiedMatch {
                    field: QualifiedField {
                        target: "home".into(),
                        kind: FieldKind::Status,
                    },
                    predicate: MatchPredicate::Compare {
                        op: CmpOp::Eq,
                        value: CmpValue::Number(200),
                    },
                }),
            ],
        };
        let bytecode = compile(&program);
        assert_eq!(bytecode.code.len(), 2);
        assert!(matches!(bytecode.code[0], Instr::Send { .. }));
        assert!(matches!(bytecode.code[1], Instr::Match(_)));
    }
}
