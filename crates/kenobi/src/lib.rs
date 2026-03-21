pub mod client;
pub mod server;
pub mod sign_encrypt;

pub mod cred {
    use std::sync::Arc;
    use std::{marker::PhantomData, time::Instant};

    pub use kenobi_core::{
        cred::usage::{Both, Inbound, InboundUsable, Outbound, OutboundUsable},
        mech::Mechanism,
    };
    #[cfg(unix)]
    use kenobi_unix::cred::Credentials as UnixCred;
    #[cfg(unix)]
    pub use kenobi_unix::cred::CredentialsUsage;
    #[cfg(windows)]
    use kenobi_windows::cred::Credentials as WinCred;
    #[cfg(windows)]
    pub use kenobi_windows::cred::CredentialsUsage;

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
    #[derive(Debug)]
    pub struct Credentials<Usage> {
        #[cfg(windows)]
        pub(crate) inner: Arc<WinCred<Usage>>,
        #[cfg(unix)]
        pub(crate) inner: Arc<UnixCred<Usage>>,
        _marker: PhantomData<Usage>,
    }
    // Necessary because Usage isn't part of the cloneability
    impl<U> Clone for Credentials<U> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
                _marker: PhantomData,
            }
        }
    }
    impl<Usage: CredentialsUsage> Credentials<Usage> {
        /// Grab the default credentials handle for a given principal (or the default user principal)
        ///
        /// On windows, this will use the current security context, and on Unix, this will use the default Keytab/ticket store
        fn new(principal: Option<&str>, mechanism: Mechanism) -> Result<Self, CredentialsError> {
            #[cfg(windows)]
            let inner = WinCred::acquire(principal, mechanism).map_err(|win| CredentialsError { win })?;
            #[cfg(unix)]
            let inner = UnixCred::new(principal, None, mechanism).map_err(|unix| CredentialsError { unix })?;
            Ok(Self {
                inner: Arc::new(inner),
                _marker: PhantomData,
            })
        }
        pub fn mechanism(&self) -> Mechanism {
            self.inner.mechanism()
        }
        pub fn valid_until(&self) -> Instant {
            self.inner.valid_until()
        }
    }
    impl Credentials<Outbound> {
        pub fn outbound(principal: Option<&str>, mechanism: Mechanism) -> Result<Self, CredentialsError> {
            Self::new(principal, mechanism)
        }
    }
}
pub mod channel_bindings {
    pub use kenobi_core::channel_bindings::Channel;
}
pub mod typestate {
    pub use kenobi_core::typestate::{
        Delegation, Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning, NoDelegation, NoEncryption, NoSigning,
        Signing,
    };
}
pub use kenobi_core::mech;
