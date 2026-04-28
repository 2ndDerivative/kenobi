#[cfg(windows)]
use kenobi_windows::server::AcceptContextError;

pub struct AcceptError {
    pub kind: AcceptErrorKind,
    #[cfg(unix)]
    inner: Option<kenobi_unix::server::StepError>,
}
impl AcceptError {
    #[cfg(unix)]
    pub fn error_token(&self) -> Option<&[u8]> {
        self.inner.as_ref().and_then(|i| i.error_token())
    }
    #[cfg(windows)]
    pub fn error_token(&self) -> Option<&[u8]> {
        None
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
        use AcceptContextError as Error;
        match value {
            Error::Internal => Self::Unknown,
            Error::InvalidHandle => Self::InvalidContext,
            Error::InvalidToken => Self::DefectiveToken,
            Error::Denied => Self::InvalidCredentials,
            // TODO this is a kerberos specific error in GSSAPI
            Error::NoAuthority => Self::Unknown,
            Error::InvalidClientChannelBindings => Self::BadChannelBindings,
        }
    }
}
