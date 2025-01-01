use std::ffi::OsString;

use crate::{SecurityInfo, StepResult};

pub struct SecurityInfoHandle;
pub struct ContextBuilder;
impl ContextBuilder {
    pub(crate) fn step_impl(self, _token: &[u8]) -> StepResult {
        unimplemented!()
    }
}
#[derive(Debug)]
pub struct PendingContext;
impl SecurityInfo for PendingContext {
    fn security_info(&self) -> SecurityInfoHandle {
        SecurityInfoHandle
    }
}
impl PendingContext {
    pub(crate) fn step_impl(self, _token: &[u8]) -> StepResult {
        unimplemented!()
    }
}
#[derive(Debug)]
pub struct FinishedContext;
impl FinishedContext {
    pub fn client_target(&self) -> Result<OsString, String> {
        unimplemented!()
    }
}
impl SecurityInfo for FinishedContext {
    fn security_info(&self) -> SecurityInfoHandle {
        SecurityInfoHandle
    }
}
