use pest::iterators::Pair;

use crate::script::ast::{FieldKind, MatchPredicate, QualifiedField, QualifiedMatch, Stmt};
use crate::script::grammar::Rule;
use crate::script::parser::ParseError;
use crate::script::parser::helpers::{
    parse_cmp_op, parse_cmp_value, unquote_regex, unquote_string,
};

pub(crate) fn build_match_group(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut is_all = false;
    let mut is_any = false;
    let mut matches = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::kw_all => is_all = true,
            Rule::kw_any => is_any = true,
            Rule::qualified_expr => matches.push(build_qualified_expr(item)?),
            _ => {}
        }
    }

    if is_all {
        Ok(Stmt::MatchAll(matches))
    } else if is_any {
        Ok(Stmt::MatchAny(matches))
    } else {
        Err(ParseError::UnexpectedRule(Rule::match_group))
    }
}

pub(crate) fn build_qualified_expr(pair: Pair<Rule>) -> Result<QualifiedMatch, ParseError> {
    let mut inner = pair.into_inner();
    let field_pair = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::qualified_expr))?;
    let field = build_qualified_field(field_pair)?;

    let next = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::qualified_expr))?;

    let predicate = match next.as_rule() {
        Rule::cmp_op => {
            let op = parse_cmp_op(next.as_str());
            let value = parse_cmp_value(inner.next());
            MatchPredicate::Compare { op, value }
        }
        Rule::neq_op => {
            let value = parse_cmp_value(inner.next());
            MatchPredicate::Compare {
                op: crate::script::ast::CmpOp::Ne,
                value,
            }
        }
        Rule::kw_contains => {
            MatchPredicate::Contains(inner.next().map(unquote_string).unwrap_or_default())
        }
        Rule::kw_not_contains => {
            MatchPredicate::NotContains(inner.next().map(unquote_string).unwrap_or_default())
        }
        Rule::kw_regex => {
            MatchPredicate::Regex(inner.next().map(unquote_regex).unwrap_or_default())
        }
        rule => return Err(ParseError::UnexpectedRule(rule)),
    };

    Ok(QualifiedMatch { field, predicate })
}

fn build_qualified_field(pair: Pair<Rule>) -> Result<QualifiedField, ParseError> {
    let mut inner = pair.into_inner();
    let target = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::qualified_field))?
        .as_str()
        .to_string();
    inner.next();
    let field_kw = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::qualified_field))?;

    let kind = match field_kw.as_rule() {
        Rule::kw_status => FieldKind::Status,
        Rule::kw_body => FieldKind::Body,
        Rule::kw_header => FieldKind::Header(inner.next().map(unquote_string).unwrap_or_default()),
        Rule::kw_response_time => FieldKind::ResponseTime,
        Rule::kw_response_size => FieldKind::ResponseSize,
        Rule::kw_answer => FieldKind::Answer,
        Rule::kw_banner => FieldKind::Banner,
        Rule::kw_response => FieldKind::Response,
        rule => return Err(ParseError::UnexpectedRule(rule)),
    };

    Ok(QualifiedField { target, kind })
}
