use std::{
    ffi::{c_void, OsStr, OsString},
    fmt::Formatter,
    os::windows::ffi::OsStrExt,
    sync::LazyLock,
};

use credentials::CredentialsHandle;
use step::ContextHandle;
use windows::{
    core::PCWSTR,
    Win32::Security::Authentication::Identity::{FreeContextBuffer, QuerySecurityPackageInfoW},
};

use crate::{SecurityInfo, StepError, StepResult};

mod attributes;
mod buffer;
mod credentials;
mod step;

static NEGOTIATE_ZERO_TERM_UTF16: LazyLock<Box<[u16]>> = LazyLock::new(|| {
    OsStr::new("Negotiate")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
});

pub struct SecurityInfoHandle<'s>(&'s ContextHandle);
impl SecurityInfoHandle<'_> {
    pub(crate) fn client_name(&self) -> Result<OsString, String> {
        attributes::client_name(self.0)
    }
    pub(crate) fn client_native_name(&self) -> Result<OsString, String> {
        attributes::client_native_name(self.0)
    }
    pub(crate) fn server_native_name(&self) -> Result<OsString, String> {
        attributes::server_native_name(self.0)
    }
}

pub struct ContextBuilder {
    credentials: CredentialsHandle,
    max_context_length: usize,
}

impl ContextBuilder {
    pub fn new(principal: Option<&str>) -> Result<Self, String> {
        let credentials = CredentialsHandle::new(principal)?;
        let max_context_length = unsafe {
            let info = QuerySecurityPackageInfoW(PCWSTR(NEGOTIATE_ZERO_TERM_UTF16.as_ptr().cast()))
                .map_err(|e| e.message())?;
            let context_length = (*info).cbMaxToken as usize;
            FreeContextBuffer(info as *mut c_void).map_err(|e| e.message())?;
            context_length
        };
        Ok(ContextBuilder {
            credentials,
            max_context_length,
        })
    }
    pub(crate) fn step_impl(self, token: &[u8]) -> StepResult {
        ContextHandle::step(
            self.credentials,
            None,
            0,
            token,
            vec![0; self.max_context_length].into_boxed_slice(),
        )
    }
}

pub struct PendingContext {
    credentials: CredentialsHandle,
    context: ContextHandle,
    buffer: Box<[u8]>,
    attr_flags: u32,
}
impl std::fmt::Debug for PendingContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingContext")
    }
}
impl SecurityInfo for PendingContext {
    fn security_info(&self) -> SecurityInfoHandle {
        SecurityInfoHandle(&self.context)
    }
}
impl PendingContext {
    pub(crate) fn step_impl(self, token: &[u8]) -> StepResult {
        let Self {
            credentials,
            context,
            buffer,
            attr_flags,
        } = self;
        ContextHandle::step(credentials, Some(context), attr_flags, token, buffer)
    }
}

pub struct FinishedContext {
    context: ContextHandle,
}
impl std::fmt::Debug for FinishedContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinishedContext")
    }
}
impl FinishedContext {
    pub fn client_target(&self) -> Result<OsString, String> {
        attributes::client_target(&self.context)
    }
}

impl SecurityInfo for FinishedContext {
    fn security_info(&self) -> SecurityInfoHandle {
        SecurityInfoHandle(&self.context)
    }
}

pub(crate) fn format_error(error: &StepError, f: &mut Formatter<'_>) -> std::fmt::Result {
    use windows::Win32::Foundation::{
        SEC_E_INCOMPLETE_MESSAGE, SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED, SEC_E_NO_AUTHENTICATING_AUTHORITY,
    };
    match error {
        StepError::InvalidToken => write!(f, "{SEC_E_INVALID_TOKEN}"),
        StepError::LogonDenied => write!(f, "{SEC_E_LOGON_DENIED}"),
        StepError::NoAuthenticatingAuthority => write!(f, "{SEC_E_NO_AUTHENTICATING_AUTHORITY}"),
        StepError::IncompleteMessage => write!(f, "{SEC_E_INCOMPLETE_MESSAGE}"),
    }
}
