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
