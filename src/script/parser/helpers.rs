use pest::iterators::{Pair, Pairs};

use crate::script::ast::{
    BodyValue, CmpOp, CmpValue, HttpMethod, InlinePart, InlinePartBody, Severity,
};
use crate::script::grammar::Rule;

pub(crate) fn unquote_string(pair: Pair<Rule>) -> String {
    let text = pair.as_str();
    if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 {
        text[1..text.len() - 1].to_string()
    } else {
        text.to_string()
    }
}

pub(crate) fn unquote_regex(pair: Pair<Rule>) -> String {
    let text = pair.as_str();
    if text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2 {
        text[1..text.len() - 1].to_string()
    } else {
        text.to_string()
    }
}

pub(crate) fn string_or_interpolation(pair: Pair<Rule>) -> String {
    match pair.as_rule() {
        Rule::interpolation => {
            let var = pair.into_inner().next().map(|p| p.as_str()).unwrap_or("");
            format!("{{{{ {var} }}}}")
        }
        _ => unquote_string(pair),
    }
}

pub(crate) fn parse_list_items(pair: Pair<Rule>) -> Vec<String> {
    let target = if pair.as_rule() == Rule::list_lit {
        pair
    } else {
        match pair
            .into_inner()
            .find(|inner| inner.as_rule() == Rule::list_lit)
        {
            Some(list) => list,
            None => return Vec::new(),
        }
    };

    target
        .into_inner()
        .filter(|item| {
            matches!(
                item.as_rule(),
                Rule::list_item | Rule::string | Rule::interpolation
            )
        })
        .map(|item| match item.as_rule() {
            Rule::list_item => item
                .into_inner()
                .next()
                .map(string_or_interpolation)
                .unwrap_or_default(),
            _ => string_or_interpolation(item),
        })
        .collect()
}

pub(crate) fn parse_severity(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

pub(crate) fn parse_bool(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
}

pub(crate) fn find_string(pairs: Pairs<Rule>) -> Option<String> {
    for pair in pairs {
        match pair.as_rule() {
            Rule::string => return Some(unquote_string(pair)),
            _ => {
                if let Some(value) = find_string(pair.into_inner()) {
                    return Some(value);
                }
            }
        }
    }
    None
}

pub(crate) fn find_http_method_pair(pairs: Pairs<Rule>) -> Option<Pair<Rule>> {
    for pair in pairs {
        match pair.as_rule() {
            Rule::kw_get
            | Rule::kw_post
            | Rule::kw_put
            | Rule::kw_patch
            | Rule::kw_delete
            | Rule::kw_head
            | Rule::kw_options => {
                return Some(pair);
            }
            Rule::http_method => return find_http_method_pair(pair.into_inner()),
            _ => {}
        }
    }
    None
}

pub(crate) fn parse_http_method(rule: Rule) -> HttpMethod {
    match rule {
        Rule::kw_get => HttpMethod::Get,
        Rule::kw_post => HttpMethod::Post,
        Rule::kw_put => HttpMethod::Put,
        Rule::kw_patch => HttpMethod::Patch,
        Rule::kw_delete => HttpMethod::Delete,
        Rule::kw_head => HttpMethod::Head,
        Rule::kw_options => HttpMethod::Options,
        _ => HttpMethod::Get,
    }
}

pub(crate) fn parse_cmp_op(value: &str) -> CmpOp {
    match value {
        "==" => CmpOp::Eq,
        "!=" => CmpOp::Ne,
        "<" => CmpOp::Lt,
        ">" => CmpOp::Gt,
        "<=" => CmpOp::Le,
        ">=" => CmpOp::Ge,
        _ => CmpOp::Eq,
    }
}

pub(crate) fn parse_cmp_value(pair: Option<Pair<Rule>>) -> CmpValue {
    let Some(pair) = pair else {
        return CmpValue::Number(0);
    };

    match pair.as_rule() {
        Rule::cmp_rhs => parse_cmp_value(pair.into_inner().next()),
        Rule::number => CmpValue::Number(pair.as_str().parse().unwrap_or(0)),
        Rule::duration => CmpValue::Duration(pair.as_str().to_string()),
        Rule::string => CmpValue::String(unquote_string(pair)),
        _ => CmpValue::Number(0),
    }
}

pub(crate) fn collect_body_pairs(pairs: Pairs<Rule>) -> Vec<(String, BodyValue)> {
    pairs
        .filter(|p| p.as_rule() == Rule::body_pair)
        .map(|pair| {
            let mut inner = pair.into_inner();
            let key = inner.next().map(unquote_string).unwrap_or_default();
            let value = inner
                .next()
                .map(super::body::build_body_value)
                .unwrap_or(BodyValue::String(String::new()));
            (key, value)
        })
        .collect()
}

pub(crate) fn build_inline_part(pair: Pair<Rule>) -> BodyValue {
    let mut filename = None;
    let mut body = InlinePartBody::Text(String::new());

    let items = match pair.as_rule() {
        Rule::part_value => pair
            .into_inner()
            .find(|p| p.as_rule() == Rule::part_block)
            .map(|b| b.into_inner().collect::<Vec<_>>())
            .unwrap_or_default(),
        Rule::part_block => pair.into_inner().collect(),
        _ => Vec::new(),
    };

    for item in items.into_iter().filter(|p| p.as_rule() == Rule::part_item) {
        let mut inner = item.into_inner();
        let keyword = match inner.next() {
            Some(kw) => kw,
            None => continue,
        };
        let value = inner.next();
        match keyword.as_rule() {
            Rule::kw_filename => {
                filename = value.map(unquote_string);
            }
            Rule::kw_content => {
                body = InlinePartBody::Text(
                    value
                        .map(|p| match p.as_rule() {
                            Rule::regex_lit => unquote_regex(p),
                            _ => unquote_string(p),
                        })
                        .unwrap_or_default(),
                );
            }
            Rule::kw_bytes => {
                body = InlinePartBody::Bytes(
                    value
                        .and_then(|p| (p.as_rule() == Rule::hex_lit).then(|| unquote_string(p)))
                        .unwrap_or_default(),
                );
            }
            _ => {}
        }
    }

    BodyValue::Part(InlinePart { filename, body })
}
