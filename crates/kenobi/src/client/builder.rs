use kenobi_core::{
    channel_bindings::Channel,
    cred::usage::OutboundUsable,
    typestate::{DeniedSigning, MaybeDelegation},
};

#[cfg(windows)]
use crate::client::typestate::UnfinishedDelegationState;
use crate::{
    client::{
        EncryptionState, MaybeEncryption, MaybeSigning, NoDelegation, NoEncryption, NoSigning, SigningState, StepOut,
        UnfinishedEncryptionState, UnfinishedSigningState, typestate::DelegationState,
    },
    cred::Credentials,
};

#[cfg(unix)]
use kenobi_unix::client::NoDelegation;

/// A Builder to setup a signing and encryption policy for a client context.
/// finish setting up with `ClientBuilder::initialize`
pub struct ClientBuilder<'cred, Usage, S: SigningState, E: EncryptionState, D: DelegationState> {
    #[cfg(windows)]
    inner: kenobi_windows::client::ClientBuilder<'cred, Usage, S, E, D>,
    #[cfg(unix)]
    inner: kenobi_unix::client::ClientBuilder<'cred, Usage, S, E, D>,
}
impl<'cred, Usage, S: SigningState, E: EncryptionState, D: DelegationState> ClientBuilder<'cred, Usage, S, E, D> {
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let inner = self.inner.bind_to_channel(channel)?;
        Ok(Self { inner })
    }
}

#[cfg(windows)]
impl<Usage> ClientBuilder<'_, Usage, NoSigning, NoEncryption, NoDelegation> {
    #[must_use]
    pub fn new_from_credentials<'cred>(
        cred: &'cred Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> ClientBuilder<'cred, Usage, NoSigning, NoEncryption, NoDelegation> {
        let inner = kenobi_windows::client::ClientBuilder::new_from_credentials(&cred.inner, target_principal);
        ClientBuilder { inner }
    }
}

#[cfg(unix)]
impl<Usage: OutboundUsable> ClientBuilder<'_, Usage, NoSigning, NoEncryption, NoDelegation> {
    #[must_use]
    pub fn new_from_credentials<'cred>(
        cred: &'cred Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> ClientBuilder<'cred, Usage, NoSigning, NoEncryption, NoDelegation> {
        let inner = kenobi_unix::client::ClientBuilder::new(&cred.inner, target_principal).unwrap();
        ClientBuilder { inner }
    }
}

impl<'cred, Usage, E: EncryptionState, D: DelegationState> ClientBuilder<'cred, Usage, NoSigning, E, D> {
    #[must_use]
    pub fn request_signing(self) -> ClientBuilder<'cred, Usage, MaybeSigning, E, D> {
        let ClientBuilder { inner } = self;
        let inner = { inner.request_signing() };
        ClientBuilder { inner }
    }
    #[must_use]
    pub fn deny_signing(self) -> ClientBuilder<'cred, Usage, DeniedSigning, E, D> {
        let ClientBuilder { inner } = self;
        let inner = inner.deny_signing();
        ClientBuilder { inner }
    }
}

impl<'cred, Usage, S: SigningState, D: DelegationState> ClientBuilder<'cred, Usage, S, NoEncryption, D> {
    #[must_use]
    pub fn request_encryption(self) -> ClientBuilder<'cred, Usage, S, MaybeEncryption, D> {
        let ClientBuilder { inner } = self;
        let inner = { inner.request_encryption() };
        ClientBuilder { inner }
    }
}

impl<'cred, Usage, S: SigningState, E: EncryptionState> ClientBuilder<'cred, Usage, S, E, NoDelegation> {
    #[must_use]
    pub fn request_delegation(self) -> ClientBuilder<'cred, Usage, S, E, MaybeDelegation> {
        let ClientBuilder { inner } = self;
        let inner = { inner.allow_delegation() };
        ClientBuilder { inner }
    }
}

#[cfg(windows)]
impl<
    'cred,
    Usage: OutboundUsable,
    S: UnfinishedSigningState,
    E: UnfinishedEncryptionState,
    D: UnfinishedDelegationState,
> ClientBuilder<'cred, Usage, S, E, D>
{
    #[must_use]
    pub fn initialize(self) -> StepOut<'cred, Usage, S, E, D> {
        StepOut::from_windows(self.inner.initialize().unwrap())
    }
}

#[cfg(unix)]
impl<
    'cred,
    Usage: OutboundUsable,
    S: UnfinishedSigningState,
    E: UnfinishedEncryptionState,
    D: UnfinishedDelegationState,
> ClientBuilder<'cred, Usage, S, E, D>
{
    #[must_use]
    pub fn initialize(self) -> StepOut<'cred, Usage, S, E> {
        StepOut::from_unix(self.inner.initialize().unwrap())
    }
}
