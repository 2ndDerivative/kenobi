use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use crate::{ContextBuilder, FinishedContext, PendingContext};

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
impl Display for StepError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        crate::sys::format_error(self, f)
    }
}
