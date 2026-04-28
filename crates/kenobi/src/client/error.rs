#[cfg(windows)]
use kenobi_windows::client::InitializeContextError;

#[derive(Clone, Copy, Debug)]
pub enum InitializeError {
    BadChannelBindings,
    BadSignature,
    ContextExpired,
    CredentialsExpired,
    DefectiveToken,
    InvalidContext,
    InvalidCredentials,
    InvalidName,
    NoCredentials,
    Unknown,
}

#[cfg(unix)]
impl From<kenobi_unix::Error> for InitializeError {
    fn from(value: kenobi_unix::Error) -> Self {
        use kenobi_unix::{error::ErrorKind, error::GssInitErrorKind as Kind};
        match value.kind() {
            ErrorKind::Gss(gss) => match gss.kind_initialize() {
                None => Self::Unknown,
                Some(kind) => match kind {
                    Kind::BadBindings => Self::BadChannelBindings,
                    Kind::BadName | Kind::BadNameType => Self::InvalidName,
                    Kind::BadSignature => Self::BadSignature,
                    Kind::ContextExpired => Self::ContextExpired,
                    Kind::CredentialsExpired => Self::CredentialsExpired,
                    Kind::DefectiveCredentials => Self::InvalidCredentials,
                    Kind::DefectiveToken => Self::DefectiveToken,
                    Kind::Failure => Self::Unknown,
                    Kind::NoContext => Self::InvalidContext,
                    Kind::NoCredentials => Self::NoCredentials,
                },
            },
            _ => todo!(),
        }
    }
}

#[cfg(windows)]
impl From<InitializeContextError> for InitializeError {
    fn from(value: InitializeContextError) -> Self {
        use InitializeContextError as Error;
        match value {
            Error::Internal => Self::Unknown,
            Error::InvalidHandle => Self::InvalidContext,
            Error::InvalidToken => Self::DefectiveToken,
            Error::Denied => Self::InvalidCredentials,
            // TODO this is a kerberos specific error in GSSAPI
            Error::NoAuthority | Error::WrongPrincipal => Self::Unknown,
            Error::TargetUnknown => Self::InvalidName,
        }
    }
}
