use std::marker::PhantomData;

use kenobi_core::cred::usage::OutboundUsable;
#[cfg(unix)]
use kenobi_unix::credentials::Credentials as UnixCred;
#[cfg(windows)]
use kenobi_windows::cred::Credentials as WinCred;

pub mod client;
mod sign_encrypt;

#[derive(Debug)]
pub struct CredentialsError {
    #[cfg(windows)]
    win: kenobi_windows::cred::Error,
    #[cfg(unix)]
    unix: kenobi_unix::Error,
}
impl std::error::Error for CredentialsError {}
impl std::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(windows)]
        return self.win.fmt(f);
        #[cfg(unix)]
        self.unix.fmt(f)
    }
}

/// A GSSAPI credentials handle
pub struct Credentials<Usage> {
    #[cfg(windows)]
    inner: WinCred<Usage>,
    #[cfg(unix)]
    inner: UnixCred,
    _marker: PhantomData<Usage>,
}
impl<Usage: CredentialsUsage + OutboundUsable> Credentials<Usage> {
    #[cfg(windows)]
    fn into_platform(self) -> WinCred<Usage> {
        self.inner
    }
    #[cfg(unix)]
    fn into_platform(self) -> UnixCred {
        self.inner
    }
    /// Grab the default credentials handle for a given principal (or the default user principal)
    ///
    /// On windows, this will use the current security context, and on Unix, this will use the default Keytab/ticket store
    pub fn acquire_default(principal: Option<&str>) -> Result<Self, CredentialsError> {
        #[cfg(windows)]
        let inner = WinCred::acquire_default(principal).map_err(|win| CredentialsError { win })?;
        #[cfg(unix)]
        let inner = UnixCred::acquire_default(usage.to_unix(), principal).map_err(|unix| CredentialsError { unix })?;
        Ok(Self {
            inner,
            _marker: PhantomData,
        })
    }
}

#[cfg(windows)]
pub trait CredentialsUsage: kenobi_windows::cred::CredentialsUsage {}
