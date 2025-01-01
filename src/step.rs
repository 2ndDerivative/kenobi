use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use crate::{ContextBuilder, FinishedContext, PendingContext};
#[cfg(windows)]
use windows::Win32::Foundation::{
    SEC_E_INCOMPLETE_MESSAGE, SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED, SEC_E_NO_AUTHENTICATING_AUTHORITY,
};

pub trait Step {
    fn step(self, token: &[u8]) -> Result<StepSuccess, StepError>;
}
impl Step for ContextBuilder {
    fn step(self, token: &[u8]) -> Result<StepSuccess, StepError> {
        self.step_impl(token)
    }
}
impl Step for PendingContext {
    fn step(self, token: &[u8]) -> Result<StepSuccess, StepError> {
        self.step_impl(token)
    }
}

#[derive(Debug)]
pub enum StepSuccess {
    Finished(FinishedContext, Option<Box<[u8]>>),
    Continue(PendingContext, Box<[u8]>),
}

#[derive(Debug)]
/// More easily discernable Errors from the operating System that may happen in Negotiate stepping.
pub enum StepError {
    InvalidToken,
    LogonDenied,
    NoAuthenticatingAuthority,
    IncompleteMessage,
}
impl Error for StepError {}
#[cfg(windows)]
impl Display for StepError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "{SEC_E_INVALID_TOKEN}"),
            Self::LogonDenied => write!(f, "{SEC_E_LOGON_DENIED}"),
            Self::NoAuthenticatingAuthority => write!(f, "{SEC_E_NO_AUTHENTICATING_AUTHORITY}"),
            Self::IncompleteMessage => write!(f, "{SEC_E_INCOMPLETE_MESSAGE}"),
        }
    }
}
#[cfg(unix)]
impl Display for StepError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Unix is not yet supported")
    }
}
