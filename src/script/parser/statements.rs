use pest::iterators::Pair;

use crate::script::ast::{EvidenceKind, ExtractSource, Stmt};
use crate::script::grammar::Rule;
use crate::script::parser::ParseError;
use crate::script::parser::helpers::unquote_regex;
use crate::script::parser::match_expr::build_qualified_expr;
use crate::script::parser::socket::parse_payload_value;

use super::helpers::string_or_interpolation;

pub(crate) fn build_set(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    inner.next();
    Ok(Stmt::Set {
        name: inner
            .next()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default(),
        value: inner.next().map(string_or_interpolation).unwrap_or_default(),
    })
}

pub(crate) fn build_send(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    let probe = inner
        .find(|p| p.as_rule() == Rule::ident)
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let payload = inner
        .find(|p| p.as_rule() == Rule::send_payload)
        .map(|item| {
            let mut parts = item.into_inner();
            let _kw = parts.next();
            parse_payload_value(parts.next())
        })
        .transpose()?;
    Ok(Stmt::Send { probe, payload })
}

pub(crate) fn build_if(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    let expr = inner
        .find(|p| p.as_rule() == Rule::qualified_expr)
        .ok_or(ParseError::UnexpectedRule(Rule::if_block))?;
    let condition = build_qualified_expr(expr)?;
    let mut body = Vec::new();
    for item in inner.filter(|p| p.as_rule() == Rule::statement) {
        body.push(super::build_statement(item)?);
    }
    Ok(Stmt::If { condition, body })
}

pub(crate) fn build_repeat(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    let count = inner
        .find(|p| p.as_rule() == Rule::number)
        .and_then(|p| p.as_str().parse().ok())
        .unwrap_or(0);
    let mut body = Vec::new();
    for item in inner.filter(|p| p.as_rule() == Rule::statement) {
        body.push(super::build_statement(item)?);
    }
    Ok(Stmt::Repeat { count, body })
}

pub(crate) fn build_save(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut idents = pair
        .into_inner()
        .filter(|p| p.as_rule() == Rule::ident)
        .map(|p| p.as_str().to_string());
    let request = idents.next().unwrap_or_default();
    let alias = idents.next().unwrap_or_default();
    Ok(Stmt::Save { request, alias })
}

pub(crate) fn build_extract(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    let name = inner
        .find(|p| p.as_rule() == Rule::ident)
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();

    let source_pair = inner
        .find(|p| p.as_rule() == Rule::extract_source)
        .ok_or(ParseError::UnexpectedRule(Rule::extract_stmt))?;

    let regex = inner
        .find(|p| p.as_rule() == Rule::regex_lit)
        .map(unquote_regex);

    let source = build_extract_source(source_pair, regex)?;

    Ok(Stmt::Extract { name, source })
}

fn build_extract_source(pair: Pair<Rule>, regex: Option<String>) -> Result<ExtractSource, ParseError> {
    let mut inner = pair.into_inner();
    let target = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::extract_source))?
        .as_str()
        .to_string();
    inner.next();
    let field = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::extract_source))?;

    match field.as_rule() {
        Rule::kw_body => Ok(ExtractSource::Body { target, regex }),
        Rule::kw_header => Ok(ExtractSource::Header {
            target,
            name: inner.next().map(super::helpers::unquote_string).unwrap_or_default(),
        }),
        rule => Err(ParseError::UnexpectedRule(rule)),
    }
}

pub(crate) fn build_evidence(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    inner.next();
    let next = inner.next().ok_or(ParseError::UnexpectedRule(Rule::evidence_stmt))?;
    Ok(match next.as_rule() {
        Rule::target_ref => {
            let target = next.as_str().to_string();
            inner.next();
            Stmt::Evidence(EvidenceKind::BodyRef(target))
        }
        Rule::kw_regex => Stmt::Evidence(EvidenceKind::Regex(
            inner
                .next()
                .map(unquote_regex)
                .unwrap_or_default(),
        )),
        rule => return Err(ParseError::UnexpectedRule(rule)),
    })
}

pub(crate) fn build_flow(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let rule = pair.into_inner().next().map(|p| p.as_rule());
    Ok(match rule {
        Some(Rule::kw_stop) => Stmt::Stop,
        Some(Rule::kw_fail) => Stmt::Fail,
        Some(Rule::kw_continue) => Stmt::Continue,
        Some(Rule::kw_break) => Stmt::Break,
        Some(Rule::kw_exit) => Stmt::Exit,
        _ => return Err(ParseError::UnexpectedRule(Rule::flow_stmt)),
    })
}

pub(crate) fn build_retry(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    let first = inner.next().ok_or(ParseError::UnexpectedRule(Rule::retry_stmt))?;
    match first.as_rule() {
        Rule::kw_retry_delay => {
            let value = inner
                .find(|p| p.as_rule() == Rule::duration)
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            Ok(Stmt::RetryDelay(value))
        }
        Rule::kw_retry => {
            let request = inner
                .find(|p| p.as_rule() == Rule::ident)
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            let count = inner
                .find(|p| p.as_rule() == Rule::number)
                .and_then(|p| p.as_str().parse().ok())
                .unwrap_or(0);
            Ok(Stmt::Retry { request, count })
        }
        rule => Err(ParseError::UnexpectedRule(rule)),
    }
}
