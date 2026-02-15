#[derive(Debug)]
pub enum InitializeContextError {
    Internal,
    InvalidHandle,
    InvalidToken,
    Denied,
    NoAuthority,
    TargetUnknown,
    ServerRefusedMutualAuth,
    ServerRefusedEncryption,
    ServerRefusedSigning,
    WrongPrincipal,
}
impl std::error::Error for InitializeContextError {}
impl std::fmt::Display for InitializeContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitializeContextError::Internal => write!(f, "Internal SSPI error"),
            InitializeContextError::InvalidHandle => write!(f, "Invalid handle passed to function"),
            InitializeContextError::InvalidToken => write!(f, "Invalid token"),
            InitializeContextError::Denied => write!(f, "Access denied"),
            InitializeContextError::NoAuthority => write!(f, "No authenticating authority found"),
            InitializeContextError::TargetUnknown => write!(f, "Target not recognized"),
            InitializeContextError::ServerRefusedMutualAuth => {
                write!(f, "The server refused to provide mutual authentication")
            }
            InitializeContextError::ServerRefusedEncryption => write!(f, "The server refused to provide encryption"),
            InitializeContextError::ServerRefusedSigning => write!(f, "The server refused to provide signing"),
            InitializeContextError::WrongPrincipal => write!(f, "Mutual authentication failed"),
        }
    }
}
