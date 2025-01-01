use std::{ffi::OsString, fmt::Formatter};

mod step;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
use windows as sys;
pub struct ContextBuilder(sys::ContextBuilder);
impl ContextBuilder {
    pub fn new(principal: Option<&str>) -> Result<Self, String> {
        let self_impl = sys::ContextBuilder::new(principal)?;
        Ok(Self(self_impl))
    }
}
pub struct FinishedContext(sys::FinishedContext);
impl FinishedContext {
    pub fn client_target(&self) -> Result<OsString, String> {
        self.0.client_target()
    }
}
impl std::fmt::Debug for FinishedContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinishedContext")
    }
}
pub struct PendingContext(sys::PendingContext);
impl std::fmt::Debug for PendingContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingContext")
    }
}
pub struct SecurityInfoHandle<'s>(sys::SecurityInfoHandle<'s>);

pub use step::{Step, StepError, StepSuccess};
pub type StepResult = Result<StepSuccess, StepError>;

pub trait SecurityInfo {
    fn security_info(&self) -> SecurityInfoHandle;
    #[cfg(windows)]
    fn client_name(&self) -> Result<OsString, String> {
        self.security_info().0.client_name()
    }
    #[cfg(windows)]
    fn client_native_name(&self) -> Result<OsString, String> {
        self.security_info().0.client_native_name()
    }
    #[cfg(windows)]
    fn server_native_name(&self) -> Result<OsString, String> {
        self.security_info().0.server_native_name()
    }
}
