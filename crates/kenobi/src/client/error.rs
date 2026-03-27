#[derive(Clone, Copy, Debug)]
pub enum InitializeError {
    BadChannelBindings,
    BadSignature,
    ContextExpired,
    CredentialsExpired,
    DefectiveToken,
    DefectiveCredentials,
    InvalidName,
    NoContext,
    NoCredentials,
    Unknown,
}

#[cfg(unix)]
impl From<kenobi_unix::Error> for InitializeError {
    fn from(value: kenobi_unix::Error) -> Self {
        use kenobi_unix::{Error, error::GssInitErrorKind as Kind};
        match value {
            Error::Gss(gss) => match gss.kind_initialize() {
                None => Self::Unknown,
                Some(kind) => match kind {
                    Kind::BadBindings => Self::BadChannelBindings,
                    Kind::BadName | Kind::BadNameType => Self::InvalidName,
                    Kind::BadSignature => Self::BadSignature,
                    Kind::ContextExpired => Self::ContextExpired,
                    Kind::CredentialsExpired => Self::CredentialsExpired,
                    Kind::DefectiveCredentials => Self::DefectiveCredentials,
                    Kind::DefectiveToken => Self::DefectiveToken,
                    Kind::Failure => Self::Unknown,
                    Kind::NoContext => Self::NoContext,
                    Kind::NoCredentials => Self::NoCredentials,
                },
            },
            _ => todo!(),
        }
    }
}
