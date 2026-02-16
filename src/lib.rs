#[cfg(unix)]
use kenobi_unix::credentials::Credentials as UnixCred;
#[cfg(windows)]
use kenobi_windows::credentials::Credentials as WinCred;

pub mod client;

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
    pub fn acquire_default(usage: CredentialsUsage, principal: Option<&str>) -> Self {
        #[cfg(windows)]
        let inner = WinCred::acquire_default(usage.to_windows(), principal);
        #[cfg(unix)]
        let inner = UnixCred::acquire_default(usage.to_unix(), principal).unwrap();
        Self { inner }
    }
}

#[derive(Clone, Copy, Debug)]
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
