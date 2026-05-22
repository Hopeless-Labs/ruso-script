use pest::iterators::Pair;

use ruso_runtime::{hex_to_bytes, parse_duration};

use crate::script::ast::SocketProbe;
use crate::script::grammar::Rule;
use crate::script::parser::ParseError;
use crate::script::parser::helpers::{parse_bool, unquote_string};

pub(crate) fn build_socket_block(pair: Pair<Rule>) -> Result<SocketProbe, ParseError> {
    let mut inner = pair.into_inner();
    let name = inner
        .find(|p| p.as_rule() == Rule::ident)
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let mut host = String::new();
    let mut port = None;
    let mut payload = None;
    let mut tls = false;
    let mut session = false;
    let mut read_max = 65_536u32;
    let mut read_idle_ms = 0u32;

    for item in inner.filter(|p| p.as_rule() == Rule::socket_item) {
        match item.as_rule() {
            Rule::payload_item => {
                let mut parts = item.into_inner();
                let _kw = parts.next();
                payload = Some(parse_payload_value(parts.next())?);
            }
            _ => {
                let mut parts = item.into_inner();
                let keyword = parts.next();
                match keyword.map(|p| p.as_rule()) {
                    Some(Rule::kw_host) => {
                        host = parts
                            .find(|p| p.as_rule() == Rule::string)
                            .map(unquote_string)
                            .unwrap_or_default();
                    }
                    Some(Rule::kw_port) => {
                        port = parts
                            .find(|p| p.as_rule() == Rule::number)
                            .and_then(|p| p.as_str().parse().ok());
                    }
                    Some(Rule::kw_tls) => {
                        tls = parts
                            .find(|p| p.as_rule() == Rule::bool_lit)
                            .map(|p| parse_bool(p.as_str()))
                            .unwrap_or(false);
                    }
                    Some(Rule::kw_session) => {
                        session = parts
                            .find(|p| p.as_rule() == Rule::bool_lit)
                            .map(|p| parse_bool(p.as_str()))
                            .unwrap_or(false);
                    }
                    Some(Rule::kw_read_max) => {
                        read_max = parts
                            .find(|p| p.as_rule() == Rule::number)
                            .and_then(|p| p.as_str().parse().ok())
                            .unwrap_or(read_max);
                    }
                    Some(Rule::kw_read_idle) => {
                        let duration = parts
                            .find(|p| p.as_rule() == Rule::duration)
                            .map(|p| p.as_str())
                            .unwrap_or("0s");
                        read_idle_ms = parse_duration(duration)
                            .map_err(|err| ParseError::Invalid(err.to_string()))?
                            .as_millis() as u32;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(SocketProbe {
        name,
        host,
        port,
        payload,
        tls,
        session,
        read_max,
        read_idle_ms,
    })
}

pub(crate) fn parse_payload_value(pair: Option<Pair<Rule>>) -> Result<Vec<u8>, ParseError> {
    let value = pair.ok_or(ParseError::UnexpectedRule(Rule::payload_item))?;
    Ok(match value.as_rule() {
        Rule::string => unquote_string(value).into_bytes(),
        Rule::hex_lit => hex_to_bytes(&unquote_string(value))
            .map_err(|err| ParseError::Invalid(format!("invalid payload hex: {err}")))?,
        rule => return Err(ParseError::UnexpectedRule(rule)),
    })
}
