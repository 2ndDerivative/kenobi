use std::{ffi::OsString, marker::PhantomData};

use crate::{SecurityInfo, StepError, StepResult};

pub struct SecurityInfoHandle<'s>(PhantomData<&'s ()>);
pub struct ContextBuilder;
impl ContextBuilder {
    pub fn step_impl(self, _token: &[u8]) -> StepResult {
        unimplemented!()
    }
    pub fn new(_principal: Option<&str>) -> Result<Self, String> {
        unimplemented!()
    }
}
#[derive(Debug)]
pub struct PendingContext;
impl SecurityInfo for PendingContext {
    fn security_info(&self) -> crate::SecurityInfoHandle {
        crate::SecurityInfoHandle(SecurityInfoHandle(PhantomData))
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
    fn security_info(&self) -> crate::SecurityInfoHandle {
        crate::SecurityInfoHandle(SecurityInfoHandle(PhantomData))
    }
}

pub fn format_error(_err: &StepError, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    f.write_str("Unix is not yet supported")
}
