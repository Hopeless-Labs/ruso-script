use pest::iterators::Pair;

use crate::script::ast::Stmt;
use crate::script::grammar::Rule;
use crate::script::parser::ParseError;
use crate::script::parser::helpers::{parse_severity, unquote_string};

pub(crate) fn build_metadata(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    let keyword = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::metadata_stmt))?;
    let value = inner.next();

    Ok(match keyword.as_rule() {
        Rule::kw_name => Stmt::Name(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_description => Stmt::Description(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_impact => Stmt::Impact(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_severity => Stmt::Severity(parse_severity(
            value.map(|p| p.as_str()).unwrap_or("info"),
        )),
        Rule::kw_author => Stmt::Author(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_report => Stmt::Report(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_cve => Stmt::Cve(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_cwe => Stmt::Cwe(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_references => Stmt::Reference(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_cvss => Stmt::Cvss(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_cvss_score => Stmt::CvssScore(value.map(|p| p.as_str().to_string()).unwrap_or_default()),
        Rule::kw_mitigation => Stmt::Mitigation(value.map(unquote_string).unwrap_or_default()),
        rule => return Err(ParseError::UnexpectedRule(rule)),
    })
}
