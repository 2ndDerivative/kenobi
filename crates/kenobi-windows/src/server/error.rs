use std::fmt::Display;

#[derive(Debug)]
pub enum AcceptContextError {
    Internal,
    InvalidHandle,
    InvalidToken,
    Denied,
    NoAuthority,
}
impl std::error::Error for AcceptContextError {}
impl Display for AcceptContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptContextError::Internal => write!(f, "Internal SSPI error"),
            AcceptContextError::InvalidHandle => write!(f, "Invalid handle passed to function"),
            AcceptContextError::InvalidToken => write!(f, "Invalid Token"),
            AcceptContextError::Denied => write!(f, "Access denied"),
            AcceptContextError::NoAuthority => write!(f, "No authenticating authority found"),
        }
    }
}
