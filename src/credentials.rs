use windows::{
    core::PCWSTR,
    Win32::Security::{
        Authentication::Identity::{AcquireCredentialsHandleW, FreeCredentialsHandle, SECPKG_CRED_INBOUND},
        Credentials::SecHandle,
    },
};

use crate::{to_boxed_zero_term, NEGOTIATE_ZERO_TERM_UTF16};

#[derive(Debug, Default)]
pub struct Credentials(SecHandle);
impl Credentials {
    pub fn new(principal: Option<&str>) -> Result<Self, String> {
        let mut cred = SecHandle::default();
        let boxed_os = principal.map(to_boxed_zero_term);
        let principal = boxed_os.map(|bo| bo.as_ptr()).unwrap_or(std::ptr::null());
        unsafe {
            AcquireCredentialsHandleW(
                // Must be valid UTF16 zero-terminated string or null pointer (if own user is needed)
                PCWSTR(principal),
                PCWSTR(NEGOTIATE_ZERO_TERM_UTF16.as_ptr().cast()),
                SECPKG_CRED_INBOUND,
                None,
                None,
                None,
                None,
                &mut cred,
                Some(&mut 0),
            )
            .map_err(|e| e.message())?;
        };
        Ok(Self(cred))
    }
    pub fn handle(&self) -> &SecHandle {
        &self.0
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeCredentialsHandle(&self.0);
        }
    }
}
