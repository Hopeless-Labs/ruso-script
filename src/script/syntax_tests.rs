use crate::script::ast::*;
use crate::script::parse;

fn parse_one(source: &str) -> Stmt {
    let program = parse(source).unwrap_or_else(|err| panic!("parse failed: {err}\n---\n{source}"));
    assert_eq!(
        program.statements.len(),
        1,
        "expected 1 statement, got {}:\n{source}",
        program.statements.len()
    );
    program.statements.into_iter().next().unwrap()
}

fn parse_metadata_one(source: &str) -> Stmt {
    parse_one(&format!("metadata {{\n{source}\n}}"))
}

fn parse_program(source: &str) -> Program {
    parse(source).unwrap_or_else(|err| panic!("parse failed: {err}\n---\n{source}"))
}

fn field(target: &str, kind: FieldKind) -> QualifiedField {
    QualifiedField {
        target: target.into(),
        kind,
    }
}

fn compare(target: &str, kind: FieldKind, op: CmpOp, value: CmpValue) -> QualifiedMatch {
    QualifiedMatch {
        field: field(target, kind),
        predicate: MatchPredicate::Compare { op, value },
    }
}

fn contains(target: &str, kind: FieldKind, text: &str) -> QualifiedMatch {
    QualifiedMatch {
        field: field(target, kind),
        predicate: MatchPredicate::Contains(text.into()),
    }
}

// --- Metadata ---

#[test]
fn parse_name() {
    assert_eq!(
        parse_metadata_one("name \"Laravel Debug\""),
        Stmt::Name("Laravel Debug".into())
    );
}

#[test]
fn parse_description() {
    assert_eq!(
        parse_metadata_one("description \"Detect exposed debug page\""),
        Stmt::Description("Detect exposed debug page".into())
    );
}

#[test]
fn parse_impact() {
    assert_eq!(
        parse_metadata_one("impact \"Remote code execution\""),
        Stmt::Impact("Remote code execution".into())
    );
}

#[test]
fn parse_severity() {
    assert_eq!(
        parse_metadata_one("severity high"),
        Stmt::Severity(Severity::High)
    );
    assert_eq!(
        parse_metadata_one("severity critical"),
        Stmt::Severity(Severity::Critical)
    );
    assert_eq!(
        parse_metadata_one("severity low"),
        Stmt::Severity(Severity::Low)
    );
}

#[test]
fn parse_author() {
    assert_eq!(
        parse_metadata_one("author \"jaeger\""),
        Stmt::Author("jaeger".into())
    );
}

#[test]
fn parse_cve() {
    let program = parse_program("metadata {\ncve [\"CVE-2024-1234\", \"CVE-2024-9999\"]\n}");
    assert_eq!(
        program.statements,
        vec![
            Stmt::Cve("CVE-2024-1234".into()),
            Stmt::Cve("CVE-2024-9999".into())
        ]
    );
}

#[test]
fn parse_cwe() {
    let program = parse_program("metadata {\ncwe [\"CWE-79\"]\n}");
    assert_eq!(program.statements, vec![Stmt::Cwe("CWE-79".into())]);
}

#[test]
fn parse_references() {
    let program = parse_program(
        "metadata {\nreferences [\"https://example.com/a\", \"https://example.com/b\"]\n}",
    );
    assert_eq!(
        program.statements,
        vec![
            Stmt::Reference("https://example.com/a".into()),
            Stmt::Reference("https://example.com/b".into())
        ]
    );
}

#[test]
fn parse_tags() {
    let program = parse_program("metadata {\ntags [\"auth\", \"rce\", \"log4j\"]\n}");
    assert_eq!(
        program.statements,
        vec![
            Stmt::Tag("auth".into()),
            Stmt::Tag("rce".into()),
            Stmt::Tag("log4j".into())
        ]
    );
}

#[test]
fn parse_version() {
    let program = parse_program("metadata {\nversion \"1.2.3\"\n}");
    assert_eq!(program.statements, vec![Stmt::Version("1.2.3".into())]);
}

#[test]
fn parse_version_last_wins_in_spec() {
    use crate::spec_build::build_program_spec;
    let program = parse_program("metadata {\nversion \"0.1.0\"\nversion \"0.2.0\"\n}");
    let spec = build_program_spec(&program.statements);
    assert_eq!(spec.metadata.version.as_deref(), Some("0.2.0"));
}

#[test]
fn parse_cvss() {
    assert_eq!(
        parse_metadata_one("cvss \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\""),
        Stmt::Cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into())
    );
}

#[test]
fn parse_cvss_score() {
    assert_eq!(
        parse_metadata_one("cvss_score 9.8"),
        Stmt::CvssScore("9.8".into())
    );
    assert_eq!(
        parse_metadata_one("cvss_score 7.5"),
        Stmt::CvssScore("7.5".into())
    );
    assert_eq!(
        parse_metadata_one("cvss_score 10"),
        Stmt::CvssScore("10".into())
    );
}

#[test]
fn parse_mitigation() {
    assert_eq!(
        parse_metadata_one("mitigation \"Apply security patch\""),
        Stmt::Mitigation("Apply security patch".into())
    );
}

#[test]
fn parse_metadata_block() {
    let program = parse(
        "metadata {\n\
         name \"Open Redis\"\n\
         severity critical\n\
         cvss_score 9.8\n\
         }\n",
    )
    .unwrap();
    assert_eq!(program.statements.len(), 3);
    assert_eq!(program.statements[0], Stmt::Name("Open Redis".into()));
    assert_eq!(program.statements[1], Stmt::Severity(Severity::Critical));
    assert_eq!(program.statements[2], Stmt::CvssScore("9.8".into()));
}

// --- Variables ---

#[test]
fn parse_set() {
    assert_eq!(
        parse_one("set email \"admin@test.com\""),
        Stmt::Set {
            name: "email".into(),
            value: Value::String("admin@test.com".into()),
        }
    );
}

#[test]
fn parse_set_with_interpolation() {
    assert_eq!(
        parse_one("set token \"{{ csrf_token }}\""),
        Stmt::Set {
            name: "token".into(),
            value: Value::String("{{ csrf_token }}".into()),
        }
    );
}

#[test]
fn parse_set_list() {
    assert_eq!(
        parse_one("set hosts [\"a.example\", \"{{ scan_host }}\"]"),
        Stmt::Set {
            name: "hosts".into(),
            value: Value::List(vec!["a.example".into(), "{{ scan_host }}".into()]),
        }
    );
}

#[test]
fn parse_for_literal_list() {
    assert_eq!(
        parse_one(
            "for host in [\"a.example\", \"b.example\"]\n    set current \"{{ host }}\"\nend"
        ),
        Stmt::ForIn {
            item: "host".into(),
            list: ListSource::Literal(vec!["a.example".into(), "b.example".into()]),
            body: vec![Stmt::Set {
                name: "current".into(),
                value: Value::String("{{ host }}".into()),
            }],
        }
    );
}

#[test]
fn parse_for_variable_list() {
    assert_eq!(
        parse_one("for host in hosts\n    send probe\nend"),
        Stmt::ForIn {
            item: "host".into(),
            list: ListSource::Variable("hosts".into()),
            body: vec![Stmt::Send {
                probe: "probe".into(),
                payload: None,
            }],
        }
    );
}

// --- Request block items ---

#[test]
fn parse_request_method_get() {
    assert_eq!(
        parse_one("http home {\n    method GET\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Method(HttpMethod::Get)],
        }
    );
}

#[test]
fn parse_request_method_post() {
    assert_eq!(
        parse_one("http api {\n    method POST\n}"),
        Stmt::Http {
            name: "api".into(),
            items: vec![HttpItem::Method(HttpMethod::Post)],
        }
    );
}

#[test]
fn parse_request_method_put() {
    assert_eq!(
        parse_one("http r {\n    method PUT\n}"),
        Stmt::Http {
            name: "r".into(),
            items: vec![HttpItem::Method(HttpMethod::Put)],
        }
    );
}

#[test]
fn parse_request_method_patch() {
    assert_eq!(
        parse_one("http r {\n    method PATCH\n}"),
        Stmt::Http {
            name: "r".into(),
            items: vec![HttpItem::Method(HttpMethod::Patch)],
        }
    );
}

#[test]
fn parse_request_method_delete() {
    assert_eq!(
        parse_one("http r {\n    method DELETE\n}"),
        Stmt::Http {
            name: "r".into(),
            items: vec![HttpItem::Method(HttpMethod::Delete)],
        }
    );
}

#[test]
fn parse_request_method_head() {
    // M10 regression: HEAD/OPTIONS were missing from the parser even though
    // they're common in vuln scanners (HEAD for size probes, OPTIONS for
    // CORS misconfig checks).
    assert_eq!(
        parse_one("http r {\n    method HEAD\n}"),
        Stmt::Http {
            name: "r".into(),
            items: vec![HttpItem::Method(HttpMethod::Head)],
        }
    );
}

#[test]
fn parse_request_method_options() {
    assert_eq!(
        parse_one("http r {\n    method OPTIONS\n}"),
        Stmt::Http {
            name: "r".into(),
            items: vec![HttpItem::Method(HttpMethod::Options)],
        }
    );
}

#[test]
fn parse_request_timeout_minutes_and_hours() {
    // L3 regression: the duration parser only accepted ms/s. `5m` had to be
    // written as `300s` for things like long-running auth flows.
    assert_eq!(
        parse_one("http home {\n    timeout 5m\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Timeout("5m".into())],
        }
    );
    assert_eq!(
        parse_one("http home {\n    timeout 1h\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Timeout("1h".into())],
        }
    );
}

#[test]
fn parse_request_path() {
    assert_eq!(
        parse_one("http home {\n    path \"/\"\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Path("/".into())],
        }
    );
}

#[test]
fn parse_request_timeout() {
    assert_eq!(
        parse_one("http home {\n    timeout 5s\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Timeout("5s".into())],
        }
    );
}

#[test]
fn parse_request_follow_redirect() {
    assert_eq!(
        parse_one("http home {\n    follow_redirect true\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::FollowRedirect(true)],
        }
    );
}

#[test]
fn parse_request_verify_ssl() {
    assert_eq!(
        parse_one("http home {\n    verify_ssl false\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::VerifySsl(false)],
        }
    );
}

#[test]
fn parse_request_proxy() {
    assert_eq!(
        parse_one("http home {\n    proxy \"http://127.0.0.1:8080\"\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Proxy("http://127.0.0.1:8080".into())],
        }
    );
}

#[test]
fn parse_request_user_agent() {
    assert_eq!(
        parse_one("http home {\n    user_agent \"scanner/1.0\"\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::UserAgent("scanner/1.0".into())],
        }
    );
}

#[test]
fn parse_request_header() {
    assert_eq!(
        parse_one("http home {\n    header \"Authorization\" \"Bearer token\"\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Header {
                name: "Authorization".into(),
                value: "Bearer token".into(),
            }],
        }
    );
}

#[test]
fn parse_request_cookie() {
    assert_eq!(
        parse_one("http home {\n    cookie \"PHPSESSID\" \"xxx\"\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Cookie {
                name: "PHPSESSID".into(),
                value: "xxx".into(),
            }],
        }
    );
}

#[test]
fn parse_request_query() {
    assert_eq!(
        parse_one("http home {\n    query \"page\" \"1\"\n}"),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Query {
                name: "page".into(),
                value: "1".into(),
            }],
        }
    );
}

#[test]
fn parse_request_data() {
    assert_eq!(
        parse_one(
            "http home {\n    data {\n        \"email\": \"{{ email }}\"\n        \"password\": \"admin\"\n    }\n}"
        ),
        Stmt::Http {
            name: "home".into(),
            items: vec![HttpItem::Data(ObjectBody {
                pairs: vec![
                    ("email".into(), BodyValue::String("{{ email }}".into()),),
                    ("password".into(), BodyValue::String("admin".into())),
                ],
            })],
        }
    );
}

#[test]
fn parse_request_json() {
    assert_eq!(
        parse_one(
            "http api {\n    json {\n        \"username\": \"admin\"\n        \"password\": \"admin\"\n    }\n}"
        ),
        Stmt::Http {
            name: "api".into(),
            items: vec![HttpItem::Json(ObjectBody {
                pairs: vec![
                    ("username".into(), BodyValue::String("admin".into())),
                    ("password".into(), BodyValue::String("admin".into())),
                ],
            })],
        }
    );
}

#[test]
fn parse_request_raw() {
    assert_eq!(
        parse_one("http raw_req {\n    raw '{\"name\": \"test\"}'\n}"),
        Stmt::Http {
            name: "raw_req".into(),
            items: vec![HttpItem::Raw("{\"name\": \"test\"}".into())],
        }
    );
}

#[test]
fn parse_request_body_bytes() {
    assert_eq!(
        parse_one("http raw_up {\n    body_bytes \"504b0304\"\n}"),
        Stmt::Http {
            name: "raw_up".into(),
            items: vec![HttpItem::BodyBytes("504b0304".into())],
        }
    );
}

#[test]
fn parse_request_multipart() {
    use crate::script::ast::{InlinePart, InlinePartBody};
    assert_eq!(
        parse_one(
            "http up {\n    multipart {\n        \"file\": part {\n            filename \"shell.php\"\n            content '<?php echo 1;'\n        }\n        \"sig\": bytes \"89504e47\"\n        \"name\": \"test\"\n    }\n}"
        ),
        Stmt::Http {
            name: "up".into(),
            items: vec![HttpItem::Multipart(ObjectBody {
                pairs: vec![
                    (
                        "file".into(),
                        BodyValue::Part(InlinePart {
                            filename: Some("shell.php".into()),
                            body: InlinePartBody::Text("<?php echo 1;".into()),
                        }),
                    ),
                    ("sig".into(), BodyValue::Bytes("89504e47".into())),
                    ("name".into(), BodyValue::String("test".into())),
                ],
            })],
        }
    );
}

// --- DNS / TCP / Send ---

#[test]
fn parse_dns_block() {
    assert_eq!(
        parse_one("dns dns_check {\n    host \"example.com\"\n}"),
        Stmt::Dns(SocketProbe {
            name: "dns_check".into(),
            host: "example.com".into(),
            port: None,
            payload: None,
            tls: false,
            session: false,
            read_max: 65_536,
            read_idle_ms: 0,
        })
    );
}

#[test]
fn parse_tcp_block() {
    assert_eq!(
        parse_one("tcp ssh_check {\n    host \"127.0.0.1\"\n    port 22\n}"),
        Stmt::Tcp(SocketProbe {
            name: "ssh_check".into(),
            host: "127.0.0.1".into(),
            port: Some(22),
            payload: None,
            tls: false,
            session: false,
            read_max: 65_536,
            read_idle_ms: 0,
        })
    );
}

#[test]
fn parse_dns_wire_payload_hex() {
    // Hex payloads now require the explicit `bytes` keyword. The previous
    // implicit form (`payload "aabb0100"`) is ambiguous with text and was
    // removed when the grammar was tightened.
    assert_eq!(
        parse_one(
            "dns wire {\n    host \"1.1.1.1\"\n    port 53\n    payload bytes \"aabb0100\"\n}"
        ),
        Stmt::Dns(SocketProbe {
            name: "wire".into(),
            host: "1.1.1.1".into(),
            port: Some(53),
            payload: Some(vec![0xaa, 0xbb, 0x01, 0x00]),
            tls: false,
            session: false,
            read_max: 65_536,
            read_idle_ms: 0,
        })
    );
}

#[test]
fn parse_payload_string_is_literal_text() {
    // Without `bytes`, the payload is treated literally as UTF-8 bytes.
    // Pre-refactor, a string of hex digits would have been auto-detected as
    // bytes (foot-gun) — this test pins down the explicit-only behavior.
    let stmt = parse_one("tcp probe {\n    host \"h\"\n    port 1\n    payload \"deadbeef\"\n}");
    match stmt {
        Stmt::Tcp(probe) => {
            assert_eq!(probe.payload.as_deref(), Some(b"deadbeef" as &[u8]));
        }
        other => panic!("expected tcp probe, got {other:?}"),
    }
}

#[test]
fn parse_payload_bytes_decodes_hex() {
    let stmt =
        parse_one("tcp probe {\n    host \"h\"\n    port 1\n    payload bytes \"deadbeef\"\n}");
    match stmt {
        Stmt::Tcp(probe) => {
            let expected: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
            assert_eq!(probe.payload.as_deref(), Some(expected));
        }
        other => panic!("expected tcp probe, got {other:?}"),
    }
}

#[test]
fn parse_udp_block() {
    assert_eq!(
        parse_one("udp ntp {\n    host \"pool.ntp.org\"\n    port 123\n}"),
        Stmt::Udp(SocketProbe {
            name: "ntp".into(),
            host: "pool.ntp.org".into(),
            port: Some(123),
            payload: None,
            tls: false,
            session: false,
            read_max: 65_536,
            read_idle_ms: 0,
        })
    );
}

#[test]
fn parse_send() {
    assert_eq!(
        parse_one("send home"),
        Stmt::Send {
            probe: "home".into(),
            payload: None,
        }
    );
}

// --- Match ---

#[test]
fn parse_match_status_eq() {
    assert_eq!(
        parse_one("match home.status == 200"),
        Stmt::Match(compare(
            "home",
            FieldKind::Status,
            CmpOp::Eq,
            CmpValue::Number(200),
        ))
    );
}

#[test]
fn parse_match_status_ne() {
    assert_eq!(
        parse_one("match home.status != 404"),
        Stmt::Match(compare(
            "home",
            FieldKind::Status,
            CmpOp::Ne,
            CmpValue::Number(404),
        ))
    );
}

#[test]
fn parse_match_body_contains() {
    assert_eq!(
        parse_one("match home.body contains \"Laravel\""),
        Stmt::Match(contains("home", FieldKind::Body, "Laravel",))
    );
}

#[test]
fn parse_match_body_not_contains() {
    assert_eq!(
        parse_one("match home.body not_contains \"Access denied\""),
        Stmt::Match(QualifiedMatch {
            field: field("home", FieldKind::Body),
            predicate: MatchPredicate::NotContains("Access denied".into()),
        })
    );
}

#[test]
fn parse_match_body_regex() {
    assert_eq!(
        parse_one("match home.body regex 'root:.*:0:0'"),
        Stmt::Match(QualifiedMatch {
            field: field("home", FieldKind::Body),
            predicate: MatchPredicate::Regex("root:.*:0:0".into()),
        })
    );
}

#[test]
fn parse_match_header_contains() {
    assert_eq!(
        parse_one("match home.header \"server\" contains \"apache\""),
        Stmt::Match(contains(
            "home",
            FieldKind::Header("server".into()),
            "apache",
        ))
    );
}

#[test]
fn parse_match_response_time() {
    assert_eq!(
        parse_one("match home.response_time < 2s"),
        Stmt::Match(compare(
            "home",
            FieldKind::ResponseTime,
            CmpOp::Lt,
            CmpValue::Duration("2s".into()),
        ))
    );
}

#[test]
fn parse_match_response_size() {
    assert_eq!(
        parse_one("match home.response_size > 1000"),
        Stmt::Match(compare(
            "home",
            FieldKind::ResponseSize,
            CmpOp::Gt,
            CmpValue::Number(1000),
        ))
    );
}

#[test]
fn parse_match_dns_answer() {
    assert_eq!(
        parse_one("match dns_check.answer contains \"1.1.1.1\""),
        Stmt::Match(contains("dns_check", FieldKind::Answer, "1.1.1.1",))
    );
}

#[test]
fn parse_match_tcp_banner() {
    assert_eq!(
        parse_one("match ssh_check.banner contains \"OpenSSH\""),
        Stmt::Match(contains("ssh_check", FieldKind::Banner, "OpenSSH",))
    );
}

#[test]
fn parse_match_all() {
    assert_eq!(
        parse_one("match all\n    login.status == 302\n    login.body contains \"Dashboard\"\nend"),
        Stmt::MatchAll(vec![
            compare("login", FieldKind::Status, CmpOp::Eq, CmpValue::Number(302),),
            contains("login", FieldKind::Body, "Dashboard"),
        ])
    );
}

#[test]
fn parse_match_any() {
    assert_eq!(
        parse_one(
            "match any\n    home.body contains \"Laravel\"\n    home.body contains \"Symfony\"\nend"
        ),
        Stmt::MatchAny(vec![
            contains("home", FieldKind::Body, "Laravel"),
            contains("home", FieldKind::Body, "Symfony"),
        ])
    );
}

// --- Assert ---

#[test]
fn parse_assert() {
    assert_eq!(
        parse_one("assert login.status == 302"),
        Stmt::Assert(compare(
            "login",
            FieldKind::Status,
            CmpOp::Eq,
            CmpValue::Number(302),
        ))
    );
}

// --- Extract ---

#[test]
fn parse_extract_body_regex() {
    assert_eq!(
        parse_one("extract csrf_token\nfrom home.body\nregex 'csrf-token=\"(.*?)\"'"),
        Stmt::Extract {
            name: "csrf_token".into(),
            source: ExtractSource::Body {
                target: "home".into(),
                regex: Some("csrf-token=\"(.*?)\"".into()),
            },
        }
    );
}

#[test]
fn parse_extract_header() {
    assert_eq!(
        parse_one("extract version\nfrom home.header \"server\""),
        Stmt::Extract {
            name: "version".into(),
            source: ExtractSource::Header {
                target: "home".into(),
                name: "server".into(),
            },
        }
    );
}

// --- If ---

#[test]
fn parse_if_block() {
    assert_eq!(
        parse_one("if home.status == 200\n    match home.body contains \"Laravel\"\nend"),
        Stmt::If {
            condition: compare("home", FieldKind::Status, CmpOp::Eq, CmpValue::Number(200),),
            body: vec![Stmt::Match(contains("home", FieldKind::Body, "Laravel",))],
        }
    );
}

// --- Save ---

#[test]
fn parse_save() {
    assert_eq!(
        parse_one("save login as auth_response"),
        Stmt::Save {
            request: "login".into(),
            alias: "auth_response".into(),
        }
    );
}

// --- Evidence ---

#[test]
fn parse_evidence_body() {
    assert_eq!(
        parse_one("evidence login.body"),
        Stmt::Evidence(EvidenceKind::Body {
            target: "login".into(),
            pattern: None,
        })
    );
}

#[test]
fn parse_evidence_body_regex() {
    assert_eq!(
        parse_one("evidence login.body regex 'APP_DEBUG=true'"),
        Stmt::Evidence(EvidenceKind::Body {
            target: "login".into(),
            pattern: Some("APP_DEBUG=true".into()),
        })
    );
}

#[test]
fn parse_evidence_response() {
    assert_eq!(
        parse_one("evidence redis_ping.response"),
        Stmt::Evidence(EvidenceKind::Response {
            target: "redis_ping".into(),
            pattern: None,
        })
    );
}

#[test]
fn parse_evidence_header() {
    assert_eq!(
        parse_one("evidence home.header \"X-Powered-By\""),
        Stmt::Evidence(EvidenceKind::Header {
            target: "home".into(),
            name: "X-Powered-By".into(),
            pattern: None,
        })
    );
}

#[test]
fn parse_evidence_header_regex() {
    assert_eq!(
        parse_one("evidence home.header \"Server\" regex 'nginx/[\\d.]+'"),
        Stmt::Evidence(EvidenceKind::Header {
            target: "home".into(),
            name: "Server".into(),
            pattern: Some("nginx/[\\d.]+".into()),
        })
    );
}

#[test]
fn parse_evidence_implicit_regex_rejected() {
    // The old source-less `evidence p regex '…'` form no longer parses.
    assert!(parse("evidence login regex 'APP_DEBUG=true'").is_err());
}

// --- Control flow ---

#[test]
fn parse_stop() {
    assert_eq!(parse_one("stop"), Stmt::Stop);
}

#[test]
fn parse_fail() {
    assert_eq!(parse_one("fail"), Stmt::Fail);
}

#[test]
fn parse_continue() {
    assert_eq!(parse_one("continue"), Stmt::Continue);
}

#[test]
fn parse_exit() {
    assert_eq!(parse_one("exit"), Stmt::Exit);
}

// --- Retry / Sleep ---

#[test]
fn parse_retry() {
    assert_eq!(
        parse_one("retry login 3"),
        Stmt::Retry {
            request: "login".into(),
            count: 3,
        }
    );
}

#[test]
fn parse_retry_delay() {
    assert_eq!(parse_one("retry_delay 1s"), Stmt::RetryDelay("1s".into()));
}

#[test]
fn parse_sleep() {
    assert_eq!(parse_one("sleep 2s"), Stmt::Sleep("2s".into()));
}

// --- Lexical / program ---

#[test]
fn parse_ignores_comments_and_blank_lines() {
    let program = parse("# metadata block\n\nmetadata {\nname \"test\"\n}\n\n# end\n").unwrap();
    assert_eq!(program.statements.len(), 1);
    assert_eq!(program.statements[0], Stmt::Name("test".into()));
}

#[test]
fn parse_case_insensitive_keywords() {
    assert_eq!(parse_metadata_one("NAME \"x\"\n"), Stmt::Name("x".into()));
    assert_eq!(
        parse_one("Match HOME.STATUS == 200"),
        Stmt::Match(compare(
            "HOME",
            FieldKind::Status,
            CmpOp::Eq,
            CmpValue::Number(200),
        ))
    );
}
