use std::marker::PhantomData;

use kenobi_core::cred::usage::{Outbound, OutboundUsable};
#[cfg(unix)]
use kenobi_unix::cred::Credentials as UnixCred;
#[cfg(unix)]
pub use kenobi_unix::cred::CredentialsUsage;
#[cfg(windows)]
use kenobi_windows::cred::Credentials as WinCred;
#[cfg(windows)]
pub use kenobi_windows::cred::CredentialsUsage;
pub mod client;
pub mod sign_encrypt;

pub mod cred {
    pub use kenobi_core::cred::usage::{Both, Inbound, InboundUsable, Outbound, OutboundUsable};
}
pub mod channel_bindings {
    pub use kenobi_core::channel_bindings::Channel;
}
pub mod typestate {
    pub use kenobi_core::typestate::{Encryption, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing};
}

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
    inner: UnixCred<Usage>,
    _marker: PhantomData<Usage>,
}
impl<Usage: CredentialsUsage + OutboundUsable> Credentials<Usage> {
    #[cfg(windows)]
    fn into_platform(self) -> WinCred<Usage> {
        self.inner
    }
    #[cfg(unix)]
    fn into_platform(self) -> UnixCred<Usage> {
        self.inner
    }
    /// Grab the default credentials handle for a given principal (or the default user principal)
    ///
    /// On windows, this will use the current security context, and on Unix, this will use the default Keytab/ticket store
    pub fn new(principal: Option<&str>) -> Result<Self, CredentialsError> {
        #[cfg(windows)]
        let inner = WinCred::acquire_default(principal).map_err(|win| CredentialsError { win })?;
        #[cfg(unix)]
        let inner = UnixCred::new(principal, None).map_err(|unix| CredentialsError { unix })?;
        Ok(Self {
            inner,
            _marker: PhantomData,
        })
    }
}
impl Credentials<Outbound> {
    pub fn outbound(principal: Option<&str>) -> Result<Self, CredentialsError> {
        Self::new(principal)
    }
}
