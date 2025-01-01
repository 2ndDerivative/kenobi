use std::ffi::OsString;

mod step;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{ContextBuilder, FinishedContext, PendingContext};

pub use step::{Step, StepError, StepSuccess};
pub type StepResult = Result<StepSuccess, StepError>;

#[cfg(windows)]
use windows::SecurityInfoHandle;

pub trait SecurityInfo {
    fn security_info(&self) -> SecurityInfoHandle;
    fn client_name(&self) -> Result<OsString, String> {
        #[cfg(windows)]
        self.security_info().client_name()
    }
    fn client_native_name(&self) -> Result<OsString, String> {
        #[cfg(windows)]
        self.security_info().client_native_name()
    }
    fn server_native_name(&self) -> Result<OsString, String> {
        #[cfg(windows)]
        self.security_info().server_native_name()
    }
}
