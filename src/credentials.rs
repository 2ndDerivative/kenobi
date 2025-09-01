use std::{ffi::OsStr, mem::MaybeUninit, os::windows::ffi::OsStrExt};

use windows::{
    core::{w, PCWSTR},
    Win32::Security::{
        Authentication::Identity::{AcquireCredentialsHandleW, FreeCredentialsHandle, SECPKG_CRED_INBOUND},
        Credentials::SecHandle,
    },
};

#[derive(Clone, Debug)]
pub struct CredentialsHandle {
    handle: SecHandle,
    expiry: i64,
}
impl Drop for CredentialsHandle {
    fn drop(&mut self) {
        let _ = unsafe { FreeCredentialsHandle(&self.handle) };
    }
}
impl CredentialsHandle {
    pub fn acquire(spn: &OsStr) -> Result<CredentialsHandle, windows_result::Error> {
        let principal_buf: Vec<u16> = spn.encode_wide().chain(std::iter::once(0)).collect();
        let principal = PCWSTR(principal_buf.as_ptr());
        let mut cred_handle = MaybeUninit::uninit();
        let mut expiry = MaybeUninit::uninit();
        unsafe {
            AcquireCredentialsHandleW(
                principal,
                w!("Negotiate"),
                SECPKG_CRED_INBOUND,
                None,
                None,
                None,
                None,
                cred_handle.as_mut_ptr(),
                Some(expiry.as_mut_ptr()),
            )
        }?;
        println!("Acquired credentials!");
        let handle = unsafe { cred_handle.assume_init() };
        let expiry = unsafe { expiry.assume_init() };
        Ok(CredentialsHandle { handle, expiry })
    }
    pub fn sec_handle(&self) -> SecHandle {
        self.handle
    }
}
