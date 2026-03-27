#[derive(Clone, Copy, Debug)]
pub enum AcceptError {
    BadChannelBindings,
    BadSignature,
    CredentialsExpired,
    DefectiveToken,
    DefectiveCredentials,
    DuplicateToken,
    Failure,
    NoCredentials,
    NoContext,
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
                    Kind::DefectiveCredentials => Self::DefectiveCredentials,
                    Kind::DefectiveToken => Self::DefectiveToken,
                    Kind::Failure => Self::Unknown,
                    Kind::NoContext => Self::NoContext,
                    Kind::NoCredentials => Self::NoCredentials,
                    Kind::DuplicateToken => Self::DuplicateToken,
                    Kind::OldToken => Self::OldToken,
                },
            },
            _ => todo!(),
        }
    }
}
