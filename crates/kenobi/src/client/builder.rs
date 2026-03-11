use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable};

use crate::{client::StepOut, cred::Credentials};

/// A Builder to setup a signing and encryption policy for a client context.
/// finish setting up with `ClientBuilder::initialize`
pub struct ClientBuilder<'cred, Usage> {
    #[cfg(windows)]
    inner: kenobi_windows::client::ClientBuilder<'cred, Usage>,
    #[cfg(unix)]
    inner: kenobi_unix::client::ClientBuilder<'cred, Usage>,
}
impl<'cred, Usage> ClientBuilder<'cred, Usage> {
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let inner = self.inner.bind_to_channel(channel)?;
        Ok(Self { inner })
    }
}

#[cfg(windows)]
impl<Usage> ClientBuilder<'_, Usage> {
    #[must_use]
    pub fn new_from_credentials<'cred>(
        cred: &'cred Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> ClientBuilder<'cred, Usage> {
        let inner = kenobi_windows::client::ClientBuilder::new_from_credentials(&cred.inner, target_principal);
        ClientBuilder { inner }
    }
}

#[cfg(unix)]
impl<Usage: OutboundUsable> ClientBuilder<'_, Usage> {
    #[must_use]
    pub fn new_from_credentials<'cred>(
        cred: &'cred Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> ClientBuilder<'cred, Usage> {
        let inner = kenobi_unix::client::ClientBuilder::new(&cred.inner, target_principal).unwrap();
        ClientBuilder { inner }
    }
}

impl<'cred, Usage> ClientBuilder<'cred, Usage> {
    #[must_use]
    pub fn request_signing(self) -> Self {
        let inner = { self.inner.request_signing() };
        ClientBuilder { inner }
    }
}

impl<'cred, Usage> ClientBuilder<'cred, Usage> {
    #[must_use]
    pub fn request_encryption(self) -> Self {
        let inner = { self.inner.request_encryption() };
        ClientBuilder { inner }
    }
}

impl<'cred, Usage> ClientBuilder<'cred, Usage> {
    #[must_use]
    pub fn request_delegation(self) -> Self {
        let inner = { self.inner.allow_delegation() };
        ClientBuilder { inner }
    }
}

#[cfg(windows)]
impl<'cred, Usage: OutboundUsable> ClientBuilder<'cred, Usage> {
    #[must_use]
    pub fn initialize(self) -> StepOut<'cred, Usage> {
        StepOut::from_windows(self.inner.initialize().unwrap())
    }
}

#[cfg(unix)]
impl<'cred, Usage: OutboundUsable> ClientBuilder<'cred, Usage> {
    #[must_use]
    pub fn initialize(self) -> StepOut<'cred, Usage> {
        StepOut::from_unix(self.inner.initialize().unwrap())
    }
}
