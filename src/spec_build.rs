use ruso_runtime::{HttpRequestSpec, ProbeKind, ProgramSpec, SocketProbeSpec};

use crate::script::ast::{HttpItem, SocketProbe, Stmt};

pub fn build_program_spec(statements: &[Stmt]) -> ProgramSpec {
    let mut spec = ProgramSpec {
        probes: std::collections::HashMap::new(),
        metadata: Default::default(),
    };

    for stmt in statements {
        match stmt {
            Stmt::Name(value) => spec.metadata.name = Some(value.clone()),
            Stmt::Description(value) => spec.metadata.description = Some(value.clone()),
            Stmt::Impact(value) => spec.metadata.impact = Some(value.clone()),
            Stmt::Severity(value) => spec.metadata.severity = Some(value.clone()),
            Stmt::Author(value) => spec.metadata.author = Some(value.clone()),
            Stmt::Cve(value) => spec.metadata.cve.push(value.clone()),
            Stmt::Cwe(value) => spec.metadata.cwe.push(value.clone()),
            Stmt::Reference(value) => spec.metadata.references.push(value.clone()),
            Stmt::Cvss(value) => spec.metadata.cvss.push(value.clone()),
            Stmt::CvssScore(value) => spec.metadata.cvss_score.push(value.clone()),
            // Single field, last-wins on assignment. `compile()` rejects
            // scripts that declare `mitigation` more than once before we get
            // here, so in practice this only ever runs zero or one time.
            Stmt::Mitigation(value) => spec.metadata.mitigation = Some(value.clone()),
            Stmt::Tag(value) => spec.metadata.tags.push(value.clone()),
            // Last-wins for repeated version declarations. Compile-time
            // policy could reject duplicates, but the parser already
            // emits one Stmt::Version per declaration so we let the
            // final value land deterministically.
            Stmt::Version(value) => spec.metadata.version = Some(value.clone()),
            // Single-value, last-wins (same rationale as version).
            Stmt::Family(value) => spec.metadata.family = Some(value.clone()),
            Stmt::Http { name, items } => {
                spec.probes
                    .insert(name.clone(), ProbeKind::Http(http_spec(items)));
            }
            Stmt::Dns(probe) => {
                spec.probes
                    .insert(probe.name.clone(), ProbeKind::Dns(socket_spec(probe)));
            }
            Stmt::Tcp(probe) => {
                spec.probes
                    .insert(probe.name.clone(), ProbeKind::Tcp(socket_spec(probe)));
            }
            Stmt::Udp(probe) => {
                spec.probes
                    .insert(probe.name.clone(), ProbeKind::Udp(socket_spec(probe)));
            }
            _ => {}
        }
    }

    spec
}

fn socket_spec(probe: &SocketProbe) -> SocketProbeSpec {
    SocketProbeSpec {
        host: probe.host.clone(),
        port: probe.port,
        payload: probe.payload.clone(),
        tls: probe.tls,
        session: probe.session,
        read_max: probe.read_max,
        read_idle_ms: probe.read_idle_ms,
    }
}

fn http_spec(items: &[HttpItem]) -> HttpRequestSpec {
    let mut spec = HttpRequestSpec::default();
    for item in items {
        match item {
            HttpItem::Method(method) => spec.method = method.clone(),
            HttpItem::Path(path) => spec.path = path.clone(),
            HttpItem::Timeout(value) => spec.timeout = Some(value.clone()),
            HttpItem::FollowRedirect(value) => spec.follow_redirect = Some(*value),
            HttpItem::VerifySsl(value) => spec.verify_ssl = Some(*value),
            HttpItem::Proxy(value) => spec.proxy = Some(value.clone()),
            HttpItem::UserAgent(value) => spec.user_agent = Some(value.clone()),
            HttpItem::Header { name, value } => spec.headers.push((name.clone(), value.clone())),
            HttpItem::Cookie { name, value } => spec.cookies.push((name.clone(), value.clone())),
            HttpItem::Query { name, value } => spec.queries.push((name.clone(), value.clone())),
            HttpItem::Data(body) => spec.data_body = Some(body.clone()),
            HttpItem::Json(body) => spec.json_body = Some(body.clone()),
            HttpItem::Raw(body) => spec.raw_body = Some(body.clone()),
            HttpItem::BodyBytes(hex) => spec.body_bytes = Some(hex.clone()),
            HttpItem::Multipart(body) => spec.multipart_body = Some(body.clone()),
        }
    }
    spec
}

#[cfg(test)]
mod tests {
    use ruso_runtime::ProbeKind;

    use super::*;
    use crate::script::ast::{HttpItem, HttpMethod, Severity, Stmt};

    #[test]
    fn collects_metadata_and_http_probe() {
        let statements = vec![
            Stmt::Name("Test Check".into()),
            Stmt::Severity(Severity::High),
            Stmt::Http {
                name: "home".into(),
                items: vec![
                    HttpItem::Method(HttpMethod::Get),
                    HttpItem::Path("/".into()),
                ],
            },
        ];
        let spec = build_program_spec(&statements);
        assert_eq!(spec.metadata.name.as_deref(), Some("Test Check"));
        assert_eq!(spec.metadata.severity, Some(Severity::High));
        let probe = spec.probes.get("home").expect("home probe");
        assert!(matches!(probe, ProbeKind::Http(_)));
    }

    #[test]
    fn collects_cve_cwe_references_cvss_mitigation() {
        let statements = vec![
            Stmt::Name("Refs".into()),
            Stmt::Cve("CVE-2024-1".into()),
            Stmt::Cve("CVE-2024-2".into()),
            Stmt::Cwe("CWE-79".into()),
            Stmt::Reference("https://a.example".into()),
            Stmt::Reference("https://b.example".into()),
            Stmt::Cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
            Stmt::CvssScore("9.8".into()),
            Stmt::CvssScore("7.5".into()),
            Stmt::Mitigation("Patch the service and restrict network access".into()),
            Stmt::Tag("auth".into()),
            Stmt::Tag("rce".into()),
        ];
        let spec = build_program_spec(&statements);
        assert_eq!(spec.metadata.cve, vec!["CVE-2024-1", "CVE-2024-2"]);
        assert_eq!(spec.metadata.cwe, vec!["CWE-79"]);
        assert_eq!(
            spec.metadata.references,
            vec!["https://a.example", "https://b.example"]
        );
        assert_eq!(
            spec.metadata.cvss,
            vec!["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]
        );
        assert_eq!(spec.metadata.cvss_score, vec!["9.8", "7.5"]);
        assert_eq!(
            spec.metadata.mitigation.as_deref(),
            Some("Patch the service and restrict network access")
        );
        assert_eq!(spec.metadata.tags, vec!["auth", "rce"]);
    }
}
