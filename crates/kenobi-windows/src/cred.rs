use std::marker::PhantomData;

use crate::NEGOTIATE;
pub use kenobi_core::cred::usage::{Both, Inbound, Outbound};
use windows::{
    Win32::Security::{
        Authentication::Identity::{
            AcquireCredentialsHandleW, FreeCredentialsHandle, SECPKG_CRED, SECPKG_CRED_BOTH, SECPKG_CRED_INBOUND,
            SECPKG_CRED_OUTBOUND,
        },
        Credentials::SecHandle,
    },
    core::PCWSTR,
};

#[derive(Debug)]
pub struct Error(windows_result::Error);
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

pub struct Credentials<Usage> {
    handle: SecHandle,
    _usage: PhantomData<Usage>,
}
impl<Usage: CredentialsUsage> Credentials<Usage> {
    pub fn acquire_default(principal: Option<&str>) -> Result<Credentials<Usage>, Error> {
        let mut handle = SecHandle::default();
        let mut _valid_seconds = 0;
        let princ_wide = principal.map(crate::to_wide);
        let princ_ref = princ_wide.as_ref().map(|b| b.as_ptr());
        let res = unsafe {
            AcquireCredentialsHandleW(
                PCWSTR(princ_ref.unwrap_or_default()),
                NEGOTIATE,
                Usage::to_usage(),
                None,
                None,
                None,
                None,
                &mut handle,
                Some(&mut _valid_seconds),
            )
        };
        match res {
            Ok(()) => Ok(Self {
                handle,
                _usage: PhantomData,
            }),
            Err(e) => Err(Error(e)),
        }
    }
}
impl Credentials<Inbound> {
    pub fn inbound(principal: Option<&str>) -> Result<Self, Error> {
        Credentials::acquire_default(principal)
    }
}
impl Credentials<Outbound> {
    pub fn outbound(principal: Option<&str>) -> Result<Self, Error> {
        Credentials::acquire_default(principal)
    }
}
impl Credentials<Both> {
    pub fn both(principal: Option<&str>) -> Result<Self, Error> {
        Credentials::acquire_default(principal)
    }
}
impl<Usage> Credentials<Usage> {
    pub(crate) fn raw_handle(&self) -> &SecHandle {
        &self.handle
    }
}
impl<Usage> AsRef<Credentials<Usage>> for Credentials<Usage> {
    fn as_ref(&self) -> &Credentials<Usage> {
        self
    }
}
impl<Usage> Drop for Credentials<Usage> {
    fn drop(&mut self) {
        let _ = unsafe { FreeCredentialsHandle(&self.handle) };
    }
}

pub trait CredentialsUsage {
    fn to_usage() -> SECPKG_CRED;
}
impl CredentialsUsage for Inbound {
    fn to_usage() -> SECPKG_CRED {
        SECPKG_CRED_INBOUND
    }
}
impl CredentialsUsage for Outbound {
    fn to_usage() -> SECPKG_CRED {
        SECPKG_CRED_OUTBOUND
    }
}
impl CredentialsUsage for Both {
    fn to_usage() -> SECPKG_CRED {
        SECPKG_CRED(SECPKG_CRED_BOTH)
    }
}
