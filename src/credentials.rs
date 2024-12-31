use std::{ffi::OsStr, ops::Deref, os::windows::ffi::OsStrExt};

use windows::{
    core::PCWSTR,
    Win32::Security::{
        Authentication::Identity::{AcquireCredentialsHandleW, FreeCredentialsHandle, SECPKG_CRED_INBOUND},
        Credentials::SecHandle,
    },
};

use crate::NEGOTIATE_ZERO_TERM_UTF16;

#[derive(Debug, Default)]
pub struct CredentialsHandle(SecHandle);
impl CredentialsHandle {
    pub fn new(principal: Option<&str>) -> Result<Self, String> {
        let mut cred = SecHandle::default();
        let boxed_os: Option<Box<[u16]>> =
            principal.map(|p| OsStr::new(p).encode_wide().chain(std::iter::once(0)).collect());
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
}
impl Deref for CredentialsHandle {
    type Target = SecHandle;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for CredentialsHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeCredentialsHandle(&self.0);
        }
    }
}
