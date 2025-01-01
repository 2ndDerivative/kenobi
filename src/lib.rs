#[cfg(windows)]
use std::ffi::OsString;

mod step;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
use windows as sys;

pub use sys::{ContextBuilder, FinishedContext, PendingContext, SecurityInfoHandle};

pub use step::{Step, StepError, StepSuccess};
pub type StepResult = Result<StepSuccess, StepError>;

pub trait SecurityInfo {
    fn security_info(&self) -> SecurityInfoHandle;
    #[cfg(windows)]
    fn client_name(&self) -> Result<OsString, String> {
        self.security_info().client_name()
    }
    #[cfg(windows)]
    fn client_native_name(&self) -> Result<OsString, String> {
        self.security_info().client_native_name()
    }
    #[cfg(windows)]
    fn server_native_name(&self) -> Result<OsString, String> {
        self.security_info().server_native_name()
    }
}
