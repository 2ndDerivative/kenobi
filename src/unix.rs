use crate::StepResult;

pub struct SecurityInfoHandle;
#[derive(Debug)]
pub struct FinishedContext;
#[derive(Debug)]
pub struct PendingContext;
impl PendingContext {
    pub(crate) fn step_impl(self, _token: &[u8]) -> StepResult {
        unimplemented!()
    }
}
pub struct ContextBuilder;
impl ContextBuilder {
    pub(crate) fn step_impl(self, _token: &[u8]) -> StepResult {
        unimplemented!()
    }
}
