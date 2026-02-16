#[cfg(unix)]
use kenobi_unix::credentials::Credentials as UnixCred;
#[cfg(windows)]
use kenobi_windows::credentials::Credentials as WinCred;

pub mod client;

#[derive(Debug)]
pub struct CredentialsError {
    #[cfg(windows)]
    win: kenobi_windows::credentials::Error,
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
pub struct Credentials {
    #[cfg(windows)]
    inner: WinCred,
    #[cfg(unix)]
    inner: UnixCred,
}
impl Credentials {
    #[cfg(windows)]
    fn into_platform(self) -> WinCred {
        self.inner
    }
    #[cfg(unix)]
    fn into_platform(self) -> UnixCred {
        self.inner
    }
    /// Grab the default credentials handle for a given principal (or the default user principal)
    ///
    /// On windows, this will use the current security context, and on Unix, this will use the default Keytab/ticket store
    pub fn acquire_default(usage: CredentialsUsage, principal: Option<&str>) -> Result<Self, CredentialsError> {
        #[cfg(windows)]
        let inner = WinCred::acquire_default(usage.to_windows(), principal).map_err(|win| CredentialsError { win })?;
        #[cfg(unix)]
        let inner = UnixCred::acquire_default(usage.to_unix(), principal).map_err(|unix| CredentialsError { unix })?;
        Ok(Self { inner })
    }
}

#[derive(Clone, Copy, Debug)]
/// The usage marker for a credentials handle
/// Currently, there is no way to use an Inbound token for a server context, but I am keeping this in case there will be a server feature for this crate
pub enum CredentialsUsage {
    Inbound,
    Outbound,
    Both,
}
impl CredentialsUsage {
    #[cfg(windows)]
    fn to_windows(self) -> kenobi_windows::credentials::CredentialsUsage {
        use kenobi_windows::credentials::CredentialsUsage::*;
        match self {
            Self::Inbound => Inbound,
            Self::Outbound => Outbound,
            Self::Both => Both,
        }
    }
    #[cfg(unix)]
    fn to_unix(self) -> kenobi_unix::CredentialsUsage {
        use kenobi_unix::CredentialsUsage::*;
        match self {
            Self::Inbound => Inbound,
            Self::Outbound => Outbound,
            Self::Both => Both,
        }
    }
}
