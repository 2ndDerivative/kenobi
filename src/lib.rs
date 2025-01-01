#[cfg(windows)]
use std::ffi::OsString;

mod step;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{ContextBuilder, FinishedContext, PendingContext};
#[cfg(windows)]
pub use windows::{ContextBuilder, FinishedContext, PendingContext};

pub use step::{Step, StepError, StepSuccess};
pub type StepResult = Result<StepSuccess, StepError>;

#[cfg(unix)]
use unix::SecurityInfoHandle;
#[cfg(windows)]
use windows::SecurityInfoHandle;

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
