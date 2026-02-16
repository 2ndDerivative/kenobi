#[cfg(windows)]
use kenobi_windows::{client::NoDelegation, credentials::Credentials as WinCred};

use crate::{
    Credentials,
    client::{
        EncryptionState, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, SigningState, StepOut,
        UnfinishedEncryptionState, UnfinishedSigningState,
    },
};

#[cfg(unix)]
use kenobi_unix::client::NoDelegation;

/// A Builder to setup a signing and encryption policy for a client context.
/// finish setting up with `ClientBuilder::initialize`
pub struct ClientBuilder<S: SigningState, E: EncryptionState> {
    #[cfg(windows)]
    inner: kenobi_windows::client::ClientBuilder<WinCred, E::Win, S::Win, NoDelegation>,
    #[cfg(unix)]
    inner: kenobi_unix::client::ClientBuilder<S::Unix, E::Unix, NoDelegation>,
}

#[cfg(windows)]
impl ClientBuilder<NoSigning, NoEncryption> {
    #[must_use]
    pub fn new_from_credentials(
        cred: Credentials,
        target_principal: Option<&str>,
    ) -> ClientBuilder<NoSigning, NoEncryption> {
        let inner = kenobi_windows::client::ClientBuilder::new_from_credentials(cred.inner, target_principal);
        ClientBuilder { inner }
    }
}

#[cfg(unix)]
impl ClientBuilder<NoSigning, NoEncryption> {
    #[must_use]
    pub fn new_from_credentials(
        cred: Credentials,
        target_principal: Option<&str>,
    ) -> ClientBuilder<NoSigning, NoEncryption> {
        let inner = kenobi_unix::client::ClientBuilder::new_from_credentials(cred.inner, target_principal).unwrap();
        ClientBuilder { inner }
    }
}

impl<E: EncryptionState> ClientBuilder<NoSigning, E> {
    #[must_use]
    pub fn request_signing(self) -> ClientBuilder<MaybeSigning, E> {
        let ClientBuilder { inner } = self;
        let inner = { inner.request_signing() };
        ClientBuilder { inner }
    }
}
impl<S: SigningState> ClientBuilder<S, NoEncryption> {
    #[must_use]
    pub fn request_encryption(self) -> ClientBuilder<S, MaybeEncryption> {
        let ClientBuilder { inner } = self;
        let inner = { inner.request_encryption() };
        ClientBuilder { inner }
    }
}

#[cfg(windows)]
impl<S: UnfinishedSigningState, E: UnfinishedEncryptionState> ClientBuilder<S, E> {
    #[must_use]
    pub fn initialize(self, server_init_token: Option<&[u8]>) -> StepOut<S, E> {
        StepOut::from_windows(self.inner.initialize(server_init_token).unwrap())
    }
}

#[cfg(unix)]
impl<S: UnfinishedSigningState, E: UnfinishedEncryptionState> ClientBuilder<S, E> {
    #[must_use]
    pub fn initialize(self, server_init_token: Option<&[u8]>) -> StepOut<S, E> {
        StepOut::from_unix(self.inner.initialize(server_init_token).unwrap())
    }
}
