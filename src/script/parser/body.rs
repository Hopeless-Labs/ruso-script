use pest::iterators::Pair;

use crate::script::ast::{BodyValue, ObjectBody};
use crate::script::grammar::Rule;
use crate::script::parser::ParseError;
use crate::script::parser::helpers::{collect_body_pairs, unquote_string};

use super::helpers::build_inline_part;

pub(crate) fn build_object_from_item(pair: Pair<Rule>) -> Result<ObjectBody, ParseError> {
    let object = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::object_body)
        .ok_or(ParseError::UnexpectedRule(Rule::object_body))?;
    Ok(ObjectBody {
        pairs: collect_body_pairs(object.into_inner()),
    })
}

pub(crate) fn build_body_value(pair: Pair<Rule>) -> BodyValue {
    match pair.as_rule() {
        Rule::body_value => pair
            .into_inner()
            .next()
            .map(build_body_value)
            .unwrap_or(BodyValue::String(String::new())),
        Rule::interpolation => BodyValue::Interpolation(
            pair.into_inner()
                .next()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default(),
        ),
        Rule::object_body => BodyValue::Object(ObjectBody {
            pairs: collect_body_pairs(pair.into_inner()),
        }),
        Rule::bytes_value => BodyValue::Bytes(
            pair.into_inner()
                .find(|p| p.as_rule() == Rule::hex_lit)
                .map(unquote_string)
                .unwrap_or_default(),
        ),
        Rule::part_value | Rule::part_block => build_inline_part(pair),
        _ => BodyValue::String(unquote_string(pair)),
    }
}
