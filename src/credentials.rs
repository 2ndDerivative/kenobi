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

use crate::NEGOTIATE;

pub struct Credentials(SecHandle, i64);
impl Credentials {
    pub fn acquire_default(usage: CredentialsUsage, principal: Option<&str>) -> Credentials {
        let mut cred_handle = SecHandle::default();
        let mut expiry = 0;
        let princ_wide = principal.map(crate::to_wide);
        let princ_ref = princ_wide.as_ref().map(|b| b.as_ptr());
        unsafe {
            AcquireCredentialsHandleW(
                PCWSTR(princ_ref.unwrap_or_default()),
                NEGOTIATE,
                usage.to_windows(),
                None,
                None,
                None,
                None,
                &mut cred_handle,
                Some(&mut expiry),
            )
            .unwrap();
        }
        Self(cred_handle, expiry)
    }
    pub(crate) fn raw_handle(&self) -> &SecHandle {
        &self.0
    }
}
impl AsRef<Credentials> for Credentials {
    fn as_ref(&self) -> &Credentials {
        self
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        let _ = unsafe { FreeCredentialsHandle(&self.0) };
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CredentialsUsage {
    Inbound,
    Outbound,
    Both,
}
impl CredentialsUsage {
    pub(crate) const fn to_windows(self) -> SECPKG_CRED {
        match self {
            CredentialsUsage::Both => SECPKG_CRED(SECPKG_CRED_BOTH),
            CredentialsUsage::Inbound => SECPKG_CRED_INBOUND,
            CredentialsUsage::Outbound => SECPKG_CRED_OUTBOUND,
        }
    }
}
impl From<CredentialsUsage> for SECPKG_CRED {
    fn from(value: CredentialsUsage) -> Self {
        value.to_windows()
    }
}
