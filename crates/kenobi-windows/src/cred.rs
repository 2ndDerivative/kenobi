use std::marker::PhantomData;

use crate::{NEGOTIATE, cred::handle::CredentialsHandle};
pub use kenobi_core::cred::usage::{Both, Inbound, Outbound};
use windows::{
    Win32::Security::{
        Authentication::Identity::{
            AcquireCredentialsHandleW, SECPKG_CRED, SECPKG_CRED_BOTH, SECPKG_CRED_INBOUND, SECPKG_CRED_OUTBOUND,
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

mod handle {
    use std::ffi::c_void;

    use windows::{
        Win32::Security::{
            Authentication::Identity::{
                FreeContextBuffer, FreeCredentialsHandle, QueryCredentialsAttributesW, SECPKG_CRED_ATTR_NAMES,
                SecPkgCredentials_NamesW,
            },
            Credentials::SecHandle,
        },
        core::PCWSTR,
    };

    pub struct CredentialsHandle(SecHandle);
    impl CredentialsHandle {
        /// # Safety
        /// SecHandle must refer (and be the only one referring to) a valid freeable credentials handle
        pub unsafe fn pick_up(sec: SecHandle) -> Self {
            Self(sec)
        }
        pub fn as_raw_handle(&self) -> &SecHandle {
            &self.0
        }
        pub fn get_identity(&self) -> windows_result::Result<String> {
            let mut names = SecPkgCredentials_NamesW::default();
            unsafe {
                QueryCredentialsAttributesW(
                    self.as_raw_handle(),
                    SECPKG_CRED_ATTR_NAMES,
                    std::ptr::from_mut(&mut names) as *mut c_void,
                )?
            };
            let name = PCWSTR(names.sUserName);
            let rust_st = unsafe { name.to_string() }.unwrap();
            unsafe { FreeContextBuffer(names.sUserName as *mut c_void)? };
            Ok(rust_st)
        }
    }
    impl Drop for CredentialsHandle {
        fn drop(&mut self) {
            let _ = unsafe { FreeCredentialsHandle(&self.0) };
        }
    }
    impl PartialEq for CredentialsHandle {
        fn eq(&self, other: &Self) -> bool {
            matches!((self.get_identity(), other.get_identity()), (Ok(v), Ok(u)) if v == u)
        }
    }
}

pub struct Credentials<Usage> {
    handle: handle::CredentialsHandle,
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
            Ok(()) => {
                let handle = unsafe { CredentialsHandle::pick_up(handle) };
                dbg!(handle.get_identity().unwrap());
                Ok(Self {
                    handle,
                    _usage: PhantomData,
                })
            }
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
    pub(crate) fn as_raw_handle(&self) -> &SecHandle {
        self.handle.as_raw_handle()
    }
}
impl<Usage> AsRef<Credentials<Usage>> for Credentials<Usage> {
    fn as_ref(&self) -> &Credentials<Usage> {
        self
    }
}
impl<U> PartialEq for Credentials<U> {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
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
impl From<Credentials<Both>> for Credentials<Inbound> {
    fn from(value: Credentials<Both>) -> Self {
        Credentials {
            handle: value.handle,
            _usage: PhantomData,
        }
    }
}
impl From<Credentials<Both>> for Credentials<Outbound> {
    fn from(value: Credentials<Both>) -> Self {
        Credentials {
            handle: value.handle,
            _usage: PhantomData,
        }
    }
}
