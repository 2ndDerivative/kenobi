use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable, typestate::DeniedSigning};
#[cfg(windows)]
use kenobi_windows::client::NoDelegation;

use crate::{
    client::{
        EncryptionState, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, SigningState, StepOut,
        UnfinishedEncryptionState, UnfinishedSigningState,
    },
    cred::Credentials,
};

#[cfg(unix)]
use kenobi_unix::client::NoDelegation;

/// A Builder to setup a signing and encryption policy for a client context.
/// finish setting up with `ClientBuilder::initialize`
pub struct ClientBuilder<Usage, S: SigningState, E: EncryptionState> {
    #[cfg(windows)]
    inner: kenobi_windows::client::ClientBuilder<Usage, S, E, NoDelegation>,
    #[cfg(unix)]
    inner: kenobi_unix::client::ClientBuilder<Usage, S, E, NoDelegation>,
}
impl<Usage, S: SigningState, E: EncryptionState> ClientBuilder<Usage, S, E> {
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let inner = self.inner.bind_to_channel(channel)?;
        Ok(Self { inner })
    }
}

#[cfg(windows)]
impl<Usage> ClientBuilder<Usage, NoSigning, NoEncryption> {
    #[must_use]
    pub fn new_from_credentials(
        cred: Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> ClientBuilder<Usage, NoSigning, NoEncryption> {
        let inner = kenobi_windows::client::ClientBuilder::new_from_credentials(cred.inner, target_principal);
        ClientBuilder { inner }
    }
}

#[cfg(unix)]
impl<Usage: OutboundUsable> ClientBuilder<Usage, NoSigning, NoEncryption> {
    #[must_use]
    pub fn new_from_credentials(
        cred: Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> ClientBuilder<Usage, NoSigning, NoEncryption> {
        let inner = kenobi_unix::client::ClientBuilder::new(cred.inner, target_principal).unwrap();
        ClientBuilder { inner }
    }
}

impl<Usage, E: EncryptionState> ClientBuilder<Usage, NoSigning, E> {
    #[must_use]
    pub fn request_signing(self) -> ClientBuilder<Usage, MaybeSigning, E> {
        let ClientBuilder { inner } = self;
        let inner = { inner.request_signing() };
        ClientBuilder { inner }
    }
    #[must_use]
    pub fn deny_signing(self) -> ClientBuilder<Usage, DeniedSigning, E> {
        let ClientBuilder { inner } = self;
        let inner = inner.deny_signing();
        ClientBuilder { inner }
    }
}

impl<Usage, S: SigningState> ClientBuilder<Usage, S, NoEncryption> {
    #[must_use]
    pub fn request_encryption(self) -> ClientBuilder<Usage, S, MaybeEncryption> {
        let ClientBuilder { inner } = self;
        let inner = { inner.request_encryption() };
        ClientBuilder { inner }
    }
}

#[cfg(windows)]
impl<Usage: OutboundUsable, S: UnfinishedSigningState, E: UnfinishedEncryptionState> ClientBuilder<Usage, S, E> {
    #[must_use]
    pub fn initialize(self) -> StepOut<Usage, S, E> {
        StepOut::from_windows(self.inner.initialize().unwrap())
    }
}

#[cfg(unix)]
impl<Usage: OutboundUsable, S: UnfinishedSigningState, E: UnfinishedEncryptionState> ClientBuilder<Usage, S, E> {
    #[must_use]
    pub fn initialize(self) -> StepOut<Usage, S, E> {
        StepOut::from_unix(self.inner.initialize().unwrap())
    }
}
