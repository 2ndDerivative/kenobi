use std::{
    marker::PhantomData,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const WINDOWS_TICKS_PER_SEC: u64 = 10_000_000;
const UNIX_EPOCH_IN_WINDOWS_TICKS: u64 = 11644473600 * WINDOWS_TICKS_PER_SEC;

fn windows_timestamp_to_system_time(windows_ticks: i64) -> SystemTime {
    let ticks_since_1601 = windows_ticks as u64;
    let ticks_since_1970 = ticks_since_1601.saturating_sub(UNIX_EPOCH_IN_WINDOWS_TICKS);

    let secs = ticks_since_1970 / WINDOWS_TICKS_PER_SEC;
    let nanos = ((ticks_since_1970 % WINDOWS_TICKS_PER_SEC) * 100) as u32;
    UNIX_EPOCH + Duration::new(secs, nanos)
}

use crate::{KERBEROS, NEGOTIATE, cred::handle::CredentialsHandle};
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
    valid_until: Instant,
    _usage: PhantomData<Usage>,
}
impl<Usage: CredentialsUsage> Credentials<Usage> {
    pub fn acquire_default(principal: Option<&str>) -> Result<Credentials<Usage>, Error> {
        Credentials::acquire_pure_kerberos(principal)
    }
    pub fn acquire_negotiate(principal: Option<&str>) -> Result<Credentials<Usage>, Error> {
        Credentials::acquire(principal, NEGOTIATE)
    }
    pub fn acquire_pure_kerberos(principal: Option<&str>) -> Result<Credentials<Usage>, Error> {
        Credentials::acquire(principal, KERBEROS)
    }
    fn acquire(principal: Option<&str>, mech: PCWSTR) -> Result<Credentials<Usage>, Error> {
        let mut handle = SecHandle::default();
        let mut expiry_ticks = 0;
        let princ_wide = principal.map(crate::to_wide);
        let princ_ref = princ_wide.as_ref().map(|b| b.as_ptr());
        let res = unsafe {
            AcquireCredentialsHandleW(
                PCWSTR(princ_ref.unwrap_or_default()),
                mech,
                Usage::to_usage(),
                None,
                None,
                None,
                None,
                &mut handle,
                Some(&mut expiry_ticks),
            )
        };
        let expiry = windows_timestamp_to_system_time(expiry_ticks);
        let valid_until = Instant::now() + expiry.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO);
        match res {
            Ok(()) => {
                let handle = unsafe { CredentialsHandle::pick_up(handle) };
                Ok(Self {
                    handle,
                    valid_until,
                    _usage: PhantomData,
                })
            }
            Err(e) => Err(Error(e)),
        }
    }
    pub fn valid_until(&self) -> Instant {
        self.valid_until
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
    fn from(
        Credentials {
            handle, valid_until, ..
        }: Credentials<Both>,
    ) -> Self {
        Credentials {
            valid_until,
            handle,
            _usage: PhantomData,
        }
    }
}
impl From<Credentials<Both>> for Credentials<Outbound> {
    fn from(
        Credentials {
            handle, valid_until, ..
        }: Credentials<Both>,
    ) -> Self {
        Credentials {
            valid_until,
            handle,
            _usage: PhantomData,
        }
    }
}
