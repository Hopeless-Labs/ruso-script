mod body;
mod helpers;
mod match_expr;
mod metadata;
mod probes;
mod socket;
mod statements;

use pest::Parser;
use pest::iterators::Pair;
use thiserror::Error;

use crate::script::ast::{Program, Stmt};
use crate::script::grammar::{Rule, ScannerParser};

use self::match_expr::build_qualified_expr;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("parse error: {0}")]
    Pest(#[from] pest::error::Error<Rule>),
    #[error("unexpected rule: {0:?}")]
    UnexpectedRule(Rule),
    #[error("{0}")]
    Invalid(String),
}

/// Maximum structural nesting depth accepted before parsing.
///
/// `pest` is a recursive-descent (PEG) parser, so each nested block
/// (`if`/`for`/`repeat` … `end`) or object (`{ … }`) costs one parser
/// stack frame. A few thousand levels — comfortably under the backend's
/// 256 KiB source cap — overflow the stack and **abort the process**. A
/// stack overflow cannot be caught by `catch_unwind` and is not bounded
/// by the executor's wall-clock budget, so a single over-nested publish
/// could take the whole server down. We reject such input cheaply here,
/// before pest ever recurses. Real scanner scripts nest a handful of
/// levels deep; 64 is generous headroom.
const MAX_NESTING_DEPTH: usize = 64;

/// Conservative pre-parse guard: bound the simultaneous nesting depth.
///
/// At the point of pest's deepest recursion, every still-open construct is
/// either a brace pair (`{`…`}`) or a block keyword (`if`/`for`/`repeat`
/// closed by `end`). Counting openers minus closers therefore tracks the
/// parser's stack depth exactly, so this can't be evaded by interleaving
/// the two forms. String (`"…"`) and regex (`'…'`) literals and `#`
/// comments are skipped so braces/keywords inside them don't inflate the
/// count. The scan is a single linear pass over the bytes and only slices
/// the source at ASCII identifier boundaries, so it never panics.
fn check_nesting_depth(source: &str) -> Result<(), ParseError> {
    let too_deep = || {
        ParseError::Invalid(format!(
            "script nesting exceeds the maximum depth of {MAX_NESTING_DEPTH}"
        ))
    };
    let bytes = source.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    let mut depth: usize = 0;
    while i < n {
        match bytes[i] {
            b'#' => {
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < n {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b'\'' => {
                i += 1;
                while i < n && bytes[i] != b'\'' {
                    i += 1;
                }
                i += 1;
            }
            b'{' => {
                depth += 1;
                if depth > MAX_NESTING_DEPTH {
                    return Err(too_deep());
                }
                i += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &source[start..i];
                if word.eq_ignore_ascii_case("if")
                    || word.eq_ignore_ascii_case("for")
                    || word.eq_ignore_ascii_case("repeat")
                {
                    depth += 1;
                    if depth > MAX_NESTING_DEPTH {
                        return Err(too_deep());
                    }
                } else if word.eq_ignore_ascii_case("end") {
                    depth = depth.saturating_sub(1);
                }
            }
            _ => i += 1,
        }
    }
    Ok(())
}

pub fn parse(source: &str) -> Result<Program, ParseError> {
    // Reject pathologically nested input *before* pest recurses on it
    // (see `check_nesting_depth`). Without this, ~46 KiB of nested blocks
    // overflows the parser stack and aborts the process.
    check_nesting_depth(source)?;

    let mut pairs = ScannerParser::parse(Rule::program, source)?;
    let mut statements = Vec::new();

    let program = pairs
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::program))?;

    for item in program.into_inner() {
        match item.as_rule() {
            Rule::statement => statements.extend(build_statement(item)?),
            Rule::pad => {
                let stmt = item
                    .into_inner()
                    .find(|p| p.as_rule() == Rule::statement)
                    .ok_or(ParseError::UnexpectedRule(Rule::pad))?;
                statements.extend(build_statement(stmt)?);
            }
            _ => {}
        }
    }

    Ok(Program { statements })
}

pub(crate) fn build_statement(pair: Pair<Rule>) -> Result<Vec<Stmt>, ParseError> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::statement))?;

    Ok(match inner.as_rule() {
        Rule::metadata_block => metadata::build_metadata_block(inner)?,
        Rule::set_stmt => vec![statements::build_set(inner)?],
        Rule::http_block => vec![probes::build_http_block(inner)?],
        Rule::dns_block => {
            let probe = socket::build_socket_block(inner)?;
            vec![Stmt::Dns(probe)]
        }
        Rule::tcp_block => {
            let probe = socket::build_socket_block(inner)?;
            vec![Stmt::Tcp(probe)]
        }
        Rule::udp_block => {
            let probe = socket::build_socket_block(inner)?;
            vec![Stmt::Udp(probe)]
        }
        Rule::send_stmt => vec![statements::build_send(inner)?],
        Rule::match_stmt => {
            let expr = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::qualified_expr)
                .ok_or(ParseError::UnexpectedRule(Rule::match_stmt))?;
            vec![Stmt::Match(build_qualified_expr(expr)?)]
        }
        Rule::match_group => vec![match_expr::build_match_group(inner)?],
        Rule::assert_stmt => {
            let expr = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::qualified_expr)
                .ok_or(ParseError::UnexpectedRule(Rule::assert_stmt))?;
            vec![Stmt::Assert(build_qualified_expr(expr)?)]
        }
        Rule::extract_stmt => vec![statements::build_extract(inner)?],
        Rule::if_block => vec![statements::build_if(inner)?],
        Rule::repeat_block => vec![statements::build_repeat(inner)?],
        Rule::for_block => vec![statements::build_for(inner)?],
        Rule::save_stmt => vec![statements::build_save(inner)?],
        Rule::evidence_stmt => vec![statements::build_evidence(inner)?],
        Rule::flow_stmt => vec![statements::build_flow(inner)?],
        Rule::retry_stmt => vec![statements::build_retry(inner)?],
        Rule::sleep_stmt => {
            let duration = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::duration)
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            vec![Stmt::Sleep(duration)]
        }
        rule => return Err(ParseError::UnexpectedRule(rule)),
    })
}

#[cfg(test)]
mod nesting_tests {
    use super::*;

    #[test]
    fn deeply_nested_input_is_rejected_not_overflowed() {
        // Without the depth guard this same input overflows the pest parser
        // stack and aborts the process (depth 2000 ≈ 46 KiB does it). The
        // guard must turn it into a graceful error instead.
        let depth = 5000;
        let mut src = String::new();
        for _ in 0..depth {
            src.push_str("if a.status == 200\n");
        }
        src.push_str("sleep 1s\n");
        for _ in 0..depth {
            src.push_str("end\n");
        }
        match parse(&src) {
            Err(ParseError::Invalid(msg)) => assert!(msg.contains("nesting")),
            other => panic!("expected Invalid nesting error, got {other:?}"),
        }
    }

    #[test]
    fn deeply_nested_objects_are_rejected() {
        // Brace nesting via repeated `{` (object/block openers).
        let mut src = String::from("http p ");
        for _ in 0..200 {
            src.push('{');
        }
        let _ = parse(&src).expect_err("over-nested braces must be rejected");
        // Specifically the depth guard, not a downstream pest error.
        assert!(matches!(
            check_nesting_depth(&src),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn normal_nesting_passes_the_guard() {
        // A realistically nested script (a few levels) must not trip the
        // guard. `end` and `}` close their constructs; `endpoint`/`iframe`
        // must not be mistaken for `end`/`if`.
        let src = r#"
            set endpoint "/login"
            http probe {
                method get
                path "/"
                json { "iframe": "{{ endpoint }}" }
            }
            if probe.status == 200
                for marker in ["ok", "yes"]
                    match probe.body contains "{{ marker }}"
                end
            end
        "#;
        assert!(check_nesting_depth(src).is_ok());
    }

    #[test]
    fn braces_inside_strings_and_comments_do_not_count() {
        let src = r#"
            # if for repeat { { { these are in a comment
            set s "}}}}}}{{{{{{ if if if"
            set r '}}}}}}{{{{{{'
        "#;
        assert!(check_nesting_depth(src).is_ok());
    }

    #[test]
    fn repeat_is_rejected_with_a_migration_hint() {
        let src = r#"
            repeat 2
                sleep 1s
            end
        "#;
        let message = parse(src).expect_err("repeat must be rejected").to_string();
        assert!(message.contains("repeat"), "got: {message}");
        assert!(message.contains("no longer supported"), "got: {message}");
    }
}
