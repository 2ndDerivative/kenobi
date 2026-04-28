use std::fmt::Display;

use crate::buffer::NonResizableVec;

#[derive(Debug)]
pub struct AcceptContextError {
    kind: AcceptContextErrorKind,
    token: Option<NonResizableVec>,
}
impl AcceptContextError {
    pub(crate) fn new(kind: AcceptContextErrorKind, token: Option<NonResizableVec>) -> Self {
        Self { kind, token }
    }
    pub fn kind(&self) -> AcceptContextErrorKind {
        self.kind
    }
    pub fn error_token(&self) -> Option<&[u8]> {
        Some(self.token.as_ref()?.as_slice()).filter(|x| !x.is_empty())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AcceptContextErrorKind {
    Internal,
    InvalidHandle,
    InvalidToken,
    Denied,
    NoAuthority,
    InvalidClientChannelBindings,
}
impl std::error::Error for AcceptContextErrorKind {}
impl Display for AcceptContextErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptContextErrorKind::Internal => write!(f, "Internal SSPI error"),
            AcceptContextErrorKind::InvalidHandle => write!(f, "Invalid handle passed to function"),
            AcceptContextErrorKind::InvalidToken => write!(f, "Invalid Token"),
            AcceptContextErrorKind::Denied => write!(f, "Access denied"),
            AcceptContextErrorKind::NoAuthority => write!(f, "No authenticating authority found"),
            AcceptContextErrorKind::InvalidClientChannelBindings => write!(f, "Invalid channel bindings"),
        }
    }
}
