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

pub fn parse(source: &str) -> Result<Program, ParseError> {
    let mut pairs = ScannerParser::parse(Rule::program, source)?;
    let mut statements = Vec::new();

    let program = pairs
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::program))?;

    for item in program.into_inner() {
        match item.as_rule() {
            Rule::statement => statements.push(build_statement(item)?),
            Rule::pad => {
                let stmt = item
                    .into_inner()
                    .find(|p| p.as_rule() == Rule::statement)
                    .ok_or(ParseError::UnexpectedRule(Rule::pad))?;
                statements.push(build_statement(stmt)?);
            }
            _ => {}
        }
    }

    Ok(Program { statements })
}

pub(crate) fn build_statement(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::statement))?;

    match inner.as_rule() {
        Rule::metadata_stmt => metadata::build_metadata(inner),
        Rule::set_stmt => statements::build_set(inner),
        Rule::http_block => probes::build_http_block(inner),
        Rule::dns_block => {
            let probe = socket::build_socket_block(inner)?;
            Ok(Stmt::Dns(probe))
        }
        Rule::tcp_block => {
            let probe = socket::build_socket_block(inner)?;
            Ok(Stmt::Tcp(probe))
        }
        Rule::udp_block => {
            let probe = socket::build_socket_block(inner)?;
            Ok(Stmt::Udp(probe))
        }
        Rule::send_stmt => statements::build_send(inner),
        Rule::match_stmt => {
            let expr = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::qualified_expr)
                .ok_or(ParseError::UnexpectedRule(Rule::match_stmt))?;
            Ok(Stmt::Match(build_qualified_expr(expr)?))
        }
        Rule::match_group => match_expr::build_match_group(inner),
        Rule::assert_stmt => {
            let expr = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::qualified_expr)
                .ok_or(ParseError::UnexpectedRule(Rule::assert_stmt))?;
            Ok(Stmt::Assert(build_qualified_expr(expr)?))
        }
        Rule::extract_stmt => statements::build_extract(inner),
        Rule::if_block => statements::build_if(inner),
        Rule::repeat_block => statements::build_repeat(inner),
        Rule::save_stmt => statements::build_save(inner),
        Rule::evidence_stmt => statements::build_evidence(inner),
        Rule::flow_stmt => statements::build_flow(inner),
        Rule::retry_stmt => statements::build_retry(inner),
        Rule::sleep_stmt => {
            let duration = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::duration)
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            Ok(Stmt::Sleep(duration))
        }
        rule => Err(ParseError::UnexpectedRule(rule)),
    }
}
