use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable};

use crate::{client::StepOut, cred::Credentials};

/// A Builder to setup a signing and encryption policy for a client context.
/// finish setting up with `ClientBuilder::initialize`
#[derive(Debug)]
pub struct ClientBuilder<Usage> {
    #[cfg(windows)]
    inner: kenobi_windows::client::ClientBuilder<Usage>,
    #[cfg(unix)]
    inner: kenobi_unix::client::ClientBuilder<Usage>,
}
impl<Usage> ClientBuilder<Usage> {
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let inner = self.inner.bind_to_channel(channel)?;
        Ok(Self { inner })
    }
}

#[cfg(windows)]
impl<Usage: OutboundUsable> ClientBuilder<Usage> {
    #[must_use]
    pub fn new_from_credentials(cred: Credentials<Usage>, target_principal: Option<&str>) -> Self {
        let inner = kenobi_windows::client::ClientBuilder::new_from_credentials(cred.inner, target_principal);
        ClientBuilder { inner }
    }
}

#[cfg(unix)]
impl<Usage: OutboundUsable> ClientBuilder<Usage> {
    #[must_use]
    pub fn new_from_credentials(cred: Credentials<Usage>, target_principal: Option<&str>) -> ClientBuilder<Usage> {
        let inner = kenobi_unix::client::ClientBuilder::new(cred.inner, target_principal).unwrap();
        ClientBuilder { inner }
    }
}

impl<Usage> ClientBuilder<Usage> {
    #[must_use]
    pub fn request_mutual_auth(self) -> Self {
        let inner = { self.inner.request_mutual_auth() };
        ClientBuilder { inner }
    }
    #[must_use]
    pub fn request_signing(self) -> Self {
        let inner = { self.inner.request_signing() };
        ClientBuilder { inner }
    }
    #[must_use]
    pub fn request_encryption(self) -> Self {
        let inner = { self.inner.request_encryption() };
        ClientBuilder { inner }
    }
    #[must_use]
    pub fn request_delegation(self) -> Self {
        let inner = { self.inner.allow_delegation() };
        ClientBuilder { inner }
    }
}

#[cfg(windows)]
impl<Usage: OutboundUsable> ClientBuilder<Usage> {
    #[must_use]
    pub fn initialize(self) -> StepOut<Usage> {
        StepOut::from_windows(self.inner.initialize().unwrap())
    }
}

#[cfg(unix)]
impl<Usage: OutboundUsable> ClientBuilder<Usage> {
    #[must_use]
    pub fn initialize(self) -> StepOut<Usage> {
        StepOut::from_unix(self.inner.initialize().unwrap())
    }
}
