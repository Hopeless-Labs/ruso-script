use pest::iterators::Pair;

use crate::script::ast::{HttpItem, Stmt};
use crate::script::grammar::Rule;
use crate::script::parser::ParseError;
use crate::script::parser::body::build_object_from_item;
use crate::script::parser::helpers::{
    find_http_method_pair, find_string, parse_bool, parse_http_method, string_or_interpolation,
    unquote_regex, unquote_string,
};

pub(crate) fn build_http_block(pair: Pair<Rule>) -> Result<Stmt, ParseError> {
    let mut inner = pair.into_inner();
    let name = inner
        .find(|p| p.as_rule() == Rule::ident)
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let mut items = Vec::new();

    for item in inner {
        match item.as_rule() {
            Rule::http_item => items.push(build_http_item(item)?),
            Rule::method_item
            | Rule::path_item
            | Rule::http_option
            | Rule::header_item
            | Rule::cookie_item
            | Rule::query_item
            | Rule::data_item
            | Rule::json_item
            | Rule::raw_item
            | Rule::body_bytes_item
            | Rule::multipart_item => items.push(build_http_item_inner(item)?),
            _ => {}
        }
    }

    Ok(Stmt::Http { name, items })
}

fn build_http_item(pair: Pair<Rule>) -> Result<HttpItem, ParseError> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::http_item))?;
    build_http_item_inner(inner)
}

fn build_http_item_inner(inner: Pair<Rule>) -> Result<HttpItem, ParseError> {
    match inner.as_rule() {
        Rule::method_item => {
            let method = find_http_method_pair(inner.into_inner())
                .ok_or(ParseError::UnexpectedRule(Rule::method_item))?;
            Ok(HttpItem::Method(parse_http_method(method.as_rule())))
        }
        Rule::path_item => Ok(HttpItem::Path(
            find_string(inner.into_inner()).unwrap_or_default(),
        )),
        Rule::http_option => build_http_option(inner),
        Rule::header_item => {
            let mut parts = inner.into_inner().filter(|p| p.as_rule() == Rule::string);
            Ok(HttpItem::Header {
                name: parts.next().map(unquote_string).unwrap_or_default(),
                value: parts.next().map(unquote_string).unwrap_or_default(),
            })
        }
        Rule::cookie_item => {
            let mut parts = inner.into_inner();
            parts.next();
            Ok(HttpItem::Cookie {
                name: parts.next().map(unquote_string).unwrap_or_default(),
                value: parts.next().map(string_or_interpolation).unwrap_or_default(),
            })
        }
        Rule::query_item => {
            let mut parts = inner.into_inner();
            parts.next();
            Ok(HttpItem::Query {
                name: parts.next().map(unquote_string).unwrap_or_default(),
                value: parts.next().map(string_or_interpolation).unwrap_or_default(),
            })
        }
        Rule::data_item => Ok(HttpItem::Data(build_object_from_item(inner)?)),
        Rule::json_item => Ok(HttpItem::Json(build_object_from_item(inner)?)),
        Rule::raw_item => Ok(HttpItem::Raw(
            inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::regex_lit)
                .map(unquote_regex)
                .unwrap_or_default(),
        )),
        Rule::body_bytes_item => Ok(HttpItem::BodyBytes(
            inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::hex_lit)
                .map(unquote_string)
                .unwrap_or_default(),
        )),
        Rule::multipart_item => Ok(HttpItem::Multipart(build_object_from_item(inner)?)),
        rule => Err(ParseError::UnexpectedRule(rule)),
    }
}

fn build_http_option(pair: Pair<Rule>) -> Result<HttpItem, ParseError> {
    let mut inner = pair.into_inner();
    let keyword = inner
        .next()
        .ok_or(ParseError::UnexpectedRule(Rule::http_option))?;
    let value = inner.next();

    Ok(match keyword.as_rule() {
        Rule::kw_timeout => HttpItem::Timeout(
            value.map(|p| p.as_str().to_string()).unwrap_or_default(),
        ),
        Rule::kw_follow_redirect => HttpItem::FollowRedirect(parse_bool(
            value.map(|p| p.as_str()).unwrap_or("false"),
        )),
        Rule::kw_verify_ssl => HttpItem::VerifySsl(parse_bool(
            value.map(|p| p.as_str()).unwrap_or("false"),
        )),
        Rule::kw_proxy => HttpItem::Proxy(value.map(unquote_string).unwrap_or_default()),
        Rule::kw_user_agent => HttpItem::UserAgent(value.map(unquote_string).unwrap_or_default()),
        rule => return Err(ParseError::UnexpectedRule(rule)),
    })
}

