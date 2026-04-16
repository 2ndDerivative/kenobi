#[cfg(windows)]
use kenobi_windows::server::AcceptContextError;

#[derive(Clone, Copy, Debug)]
pub enum AcceptError {
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
impl From<kenobi_unix::Error> for AcceptError {
    fn from(value: kenobi_unix::Error) -> Self {
        use kenobi_unix::{Error, error::GssAccErrorKind as Kind};
        match value {
            Error::Gss(gss) => match gss.kind_accept() {
                None => Self::Unknown,
                Some(kind) => match kind {
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
                },
            },
            _ => todo!(),
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
