#[cfg(windows)]
use kenobi_windows::server::{AcceptContextError, AcceptContextErrorKind};

pub struct AcceptError {
    kind: AcceptErrorKind,
    #[cfg(unix)]
    inner: Option<kenobi_unix::server::StepError>,
    #[cfg(windows)]
    inner: kenobi_windows::server::AcceptContextError,
}
impl AcceptError {
    pub fn kind(&self) -> AcceptErrorKind {
        self.kind
    }
    #[cfg(unix)]
    pub fn error_token(&self) -> Option<&[u8]> {
        self.inner.as_ref().and_then(|i| i.error_token())
    }
    #[cfg(windows)]
    pub fn error_token(&self) -> Option<&[u8]> {
        self.inner.error_token()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AcceptErrorKind {
    BadChannelBindings,
    BadSignature,
    CredentialsExpired,
    DefectiveToken,
    DuplicateToken,
    Failure,
    InvalidCredentials,
    InvalidContext,
    NoCredentials,
    OldToken,
    Unknown,
}

#[cfg(unix)]
impl From<kenobi_unix::error::GssAccErrorKind> for AcceptErrorKind {
    fn from(value: kenobi_unix::error::GssAccErrorKind) -> Self {
        use kenobi_unix::error::GssAccErrorKind as Kind;
        match value {
            Kind::BadBindings => Self::BadChannelBindings,
            Kind::BadSignature => Self::BadSignature,
            Kind::CredentialsExpired => Self::CredentialsExpired,
            Kind::DefectiveCredentials => Self::InvalidCredentials,
            Kind::DefectiveToken => Self::DefectiveToken,
            Kind::Failure => Self::Unknown,
            Kind::NoContext => Self::InvalidContext,
            Kind::NoCredentials => Self::NoCredentials,
            Kind::DuplicateToken => Self::DuplicateToken,
            Kind::OldToken => Self::OldToken,
        }
    }
}

#[cfg(unix)]
impl From<kenobi_unix::Error> for AcceptError {
    fn from(value: kenobi_unix::Error) -> Self {
        use kenobi_unix::error::ErrorKind;
        let kind = match value.kind() {
            ErrorKind::Gss(gss) => match gss.kind_accept() {
                None => AcceptErrorKind::Unknown,
                Some(kind) => kind.into(),
            },
            _ => todo!(),
        };
        Self { kind, inner: None }
    }
}
#[cfg(unix)]
impl From<kenobi_unix::server::StepError> for AcceptError {
    fn from(value: kenobi_unix::server::StepError) -> Self {
        use kenobi_unix::error::ErrorKind;
        let kind = match value.kind() {
            ErrorKind::Gss(gss) => match gss.kind_accept() {
                None => AcceptErrorKind::Unknown,
                Some(kind) => kind.into(),
            },
            _ => todo!(),
        };
        Self {
            kind,
            inner: Some(value),
        }
    }
}

#[cfg(windows)]
impl From<AcceptContextError> for AcceptError {
    fn from(value: AcceptContextError) -> Self {
        use AcceptContextErrorKind as Kind;
        let kind = match value.kind() {
            Kind::Internal => AcceptErrorKind::Unknown,
            Kind::InvalidHandle => AcceptErrorKind::InvalidContext,
            Kind::InvalidToken => AcceptErrorKind::DefectiveToken,
            Kind::Denied => AcceptErrorKind::InvalidCredentials,
            // TODO this is a kerberos specific error in GSSAPI
            Kind::NoAuthority => AcceptErrorKind::Unknown,
            Kind::InvalidClientChannelBindings => AcceptErrorKind::BadChannelBindings,
        };
        Self { kind, inner: value }
    }
}
