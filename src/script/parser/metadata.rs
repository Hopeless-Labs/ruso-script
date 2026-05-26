use pest::iterators::Pair;

use crate::script::ast::Stmt;
use crate::script::grammar::Rule;
use crate::script::parser::ParseError;
use crate::script::parser::helpers::{parse_list_items, parse_severity, unquote_string};

pub(crate) fn build_metadata_block(pair: Pair<Rule>) -> Result<Vec<Stmt>, ParseError> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::metadata_stmt)
        .try_fold(Vec::new(), |mut items, stmt| {
            items.extend(build_metadata(stmt)?);
            Ok(items)
        })
}

pub(crate) fn build_metadata(pair: Pair<Rule>) -> Result<Vec<Stmt>, ParseError> {
    let mut inner = pair.into_inner();
    let keyword = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::metadata_stmt))?;
    let value = inner.next();

    Ok(match keyword.as_rule() {
        Rule::kw_name => vec![Stmt::Name(value.map(unquote_string).unwrap_or_default())],
        Rule::kw_description => {
            vec![Stmt::Description(
                value.map(unquote_string).unwrap_or_default(),
            )]
        }
        Rule::kw_impact => vec![Stmt::Impact(value.map(unquote_string).unwrap_or_default())],
        Rule::kw_severity => vec![Stmt::Severity(parse_severity(
            value.map(|p| p.as_str()).unwrap_or("info"),
        ))],
        Rule::kw_author => vec![Stmt::Author(value.map(unquote_string).unwrap_or_default())],
        Rule::kw_report => vec![Stmt::Report(value.map(unquote_string).unwrap_or_default())],
        Rule::kw_cve => value
            .map(parse_list_items)
            .unwrap_or_default()
            .into_iter()
            .map(Stmt::Cve)
            .collect(),
        Rule::kw_cwe => value
            .map(parse_list_items)
            .unwrap_or_default()
            .into_iter()
            .map(Stmt::Cwe)
            .collect(),
        Rule::kw_references => value
            .map(parse_list_items)
            .unwrap_or_default()
            .into_iter()
            .map(Stmt::Reference)
            .collect(),
        Rule::kw_cvss => vec![Stmt::Cvss(value.map(unquote_string).unwrap_or_default())],
        Rule::kw_cvss_score => vec![Stmt::CvssScore(
            value.map(|p| p.as_str().to_string()).unwrap_or_default(),
        )],
        Rule::kw_mitigation => {
            vec![Stmt::Mitigation(
                value.map(unquote_string).unwrap_or_default(),
            )]
        }
        Rule::kw_tags => value
            .map(parse_list_items)
            .unwrap_or_default()
            .into_iter()
            .map(Stmt::Tag)
            .collect(),
        rule => return Err(ParseError::UnexpectedRule(rule)),
    })
}
