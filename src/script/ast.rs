pub use ruso_runtime::contract::{
    BodyValue, CmpOp, CmpValue, EvidenceKind, ExtractSource, FieldKind, HttpMethod, InlinePart,
    InlinePartBody, MatchPredicate, ObjectBody, QualifiedField, QualifiedMatch, Severity,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub statements: Vec<Stmt>,
}

/// Generic socket probe fields shared by `dns`, `tcp`, and `udp`.
#[derive(Debug, Clone, PartialEq)]
pub struct SocketProbe {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    /// UTF-8 text or raw bytes (from `payload "..."` or `payload "aabbcc"` hex).
    pub payload: Option<Vec<u8>>,
    pub tls: bool,
    pub session: bool,
    pub read_max: u32,
    pub read_idle_ms: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ListSource {
    Literal(Vec<String>),
    Variable(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Name(String),
    Description(String),
    Impact(String),
    Severity(Severity),
    Author(String),
    Report(String),
    Cve(String),
    Cwe(String),
    Reference(String),
    Cvss(String),
    CvssScore(String),
    Mitigation(String),

    Set {
        name: String,
        value: Value,
    },

    ForIn {
        item: String,
        list: ListSource,
        body: Vec<Stmt>,
    },

    Http {
        name: String,
        items: Vec<HttpItem>,
    },
    Dns(SocketProbe),
    Tcp(SocketProbe),
    Udp(SocketProbe),
    Send {
        probe: String,
        payload: Option<Vec<u8>>,
    },
    Repeat {
        count: u32,
        body: Vec<Stmt>,
    },
    Break,

    Match(QualifiedMatch),
    MatchAll(Vec<QualifiedMatch>),
    MatchAny(Vec<QualifiedMatch>),
    Assert(QualifiedMatch),

    Extract {
        name: String,
        source: ExtractSource,
    },

    If {
        condition: QualifiedMatch,
        body: Vec<Stmt>,
    },

    Save {
        request: String,
        alias: String,
    },

    Evidence(EvidenceKind),

    Stop,
    Fail,
    Continue,
    Exit,

    Retry {
        request: String,
        count: u32,
    },
    RetryDelay(String),
    Sleep(String),
}

impl Stmt {
    pub fn is_metadata(&self) -> bool {
        matches!(
            self,
            Self::Name(_)
                | Self::Description(_)
                | Self::Impact(_)
                | Self::Severity(_)
                | Self::Author(_)
                | Self::Report(_)
                | Self::Cve(_)
                | Self::Cwe(_)
                | Self::Reference(_)
                | Self::Cvss(_)
                | Self::CvssScore(_)
                | Self::Mitigation(_)
        )
    }

    pub fn is_probe_definition(&self) -> bool {
        matches!(
            self,
            Self::Http { .. } | Self::Dns(_) | Self::Tcp(_) | Self::Udp(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpItem {
    Method(HttpMethod),
    Path(String),
    Timeout(String),
    FollowRedirect(bool),
    VerifySsl(bool),
    Proxy(String),
    UserAgent(String),
    Header {
        name: String,
        value: String,
    },
    Cookie {
        name: String,
        value: String,
    },
    Query {
        name: String,
        value: String,
    },
    Data(ObjectBody),
    Json(ObjectBody),
    Raw(String),
    BodyBytes(String),
    Multipart(ObjectBody),
}
