#[cfg(unix)]
use kenobi_unix::client::{
    ClientContext as UnixClientContext, NoDelegation, PendingClientContext as UnixPendingClientContext,
    StepOut as UnixStepOut,
};
#[cfg(windows)]
use kenobi_windows::{
    client::{ClientContext as WinContext, PendingClientContext as WinPendingClientContext, StepOut as WinStepOut},
    credentials::Credentials as WinCred,
};

pub use builder::ClientBuilder;
pub use typestate::{
    Encryption, EncryptionState, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing, SigningState,
};

use crate::Credentials;

mod builder;
mod typestate;

pub struct ClientContext<S: SigningState, E: EncryptionState> {
    #[cfg(windows)]
    inner: WinContext<WinCred, E::Win, S::Win>,
    #[cfg(unix)]
    inner: UnixClientContext<S::Unix, E::Unix, NoDelegation>,
}
impl ClientContext<typestate::NoSigning, typestate::NoEncryption> {
    pub fn new_from_cred(
        cred: Credentials,
        target_principal: Option<&str>,
    ) -> StepOut<typestate::NoSigning, typestate::NoEncryption> {
        #[cfg(windows)]
        return StepOut::from_windows(WinContext::new_from_cred(cred.into_platform(), target_principal, None).unwrap());
        #[cfg(unix)]
        StepOut::from_unix(UnixClientContext::new_from_cred(cred.into_platform(), target_principal).unwrap())
    }
}
#[cfg(windows)]
impl<S: SigningState, E: EncryptionState> ClientContext<S, E>
where
    S::Win: kenobi_windows::client::SigningPolicy,
    E::Win: kenobi_windows::client::EncryptionPolicy,
{
    pub fn last_token(&self) -> Option<&[u8]> {
        self.inner.last_token()
    }
}

#[cfg(unix)]
impl<S: SigningState, E: EncryptionState> ClientContext<S, E>
where
    S::Unix: kenobi_unix::client::SignPolicy,
    E::Unix: kenobi_unix::client::EncryptionPolicy,
{
    pub fn last_token(&self) -> Option<&[u8]> {
        self.inner.last_token()
    }
}
#[cfg(windows)]
impl<E: EncryptionState> ClientContext<MaybeSigning, E>
where
    E::Win: kenobi_windows::client::EncryptionPolicy,
{
    pub fn check_signing(self) -> Result<ClientContext<Signing, E>, ClientContext<NoSigning, E>> {
        self.inner
            .check_signing()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(unix)]
impl<E: EncryptionState> ClientContext<MaybeSigning, E>
where
    E::Unix: kenobi_unix::client::EncryptionPolicy,
{
    pub fn check_signing(self) -> Result<ClientContext<Signing, E>, ClientContext<NoSigning, E>> {
        self.inner
            .check_signing()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(windows)]
impl<S: SigningState> ClientContext<S, MaybeEncryption>
where
    S::Win: kenobi_windows::client::SigningPolicy,
{
    pub fn check_encryption(self) -> Result<ClientContext<S, Encryption>, ClientContext<S, NoEncryption>> {
        self.inner
            .check_encryption()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(unix)]
impl<S: SigningState> ClientContext<S, MaybeEncryption>
where
    S::Unix: kenobi_unix::client::SignPolicy,
{
    pub fn check_encryption(self) -> Result<ClientContext<S, Encryption>, ClientContext<S, NoEncryption>> {
        self.inner
            .check_encryption()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}

pub struct PendingClientContext<S: SigningState, E: EncryptionState> {
    #[cfg(windows)]
    inner: WinPendingClientContext<WinCred, E::Win, S::Win>,
    #[cfg(unix)]
    inner: UnixPendingClientContext<S::Unix, E::Unix, NoDelegation>,
}

#[cfg(windows)]
impl<S: SigningState, E: EncryptionState> PendingClientContext<S, E> {
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}
#[cfg(unix)]
impl<S: SigningState, E: EncryptionState> PendingClientContext<S, E> {
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}
#[cfg(windows)]
impl<S: SigningState, E: EncryptionState> PendingClientContext<S, E>
where
    S::Win: kenobi_windows::client::SigningPolicy,
    E::Win: kenobi_windows::client::EncryptionPolicy,
{
    pub fn step(self, token: &[u8]) -> StepOut<S, E> {
        match self.inner.step(token).unwrap() {
            WinStepOut::Completed(inner) => StepOut::Finished(ClientContext { inner }),
            WinStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
}

#[cfg(unix)]
impl<S: SigningState, E: EncryptionState> PendingClientContext<S, E>
where
    S::Unix: kenobi_unix::client::SignPolicy,
    E::Unix: kenobi_unix::client::EncryptionPolicy,
{
    pub fn step(self, token: &[u8]) -> StepOut<S, E> {
        match self.inner.step(token).unwrap() {
            UnixStepOut::Finished(inner) => StepOut::Finished(ClientContext { inner }),
            UnixStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
}

pub enum StepOut<S: SigningState, E: EncryptionState> {
    Pending(PendingClientContext<S, E>),
    Finished(ClientContext<S, E>),
}
impl<S: SigningState, E: EncryptionState> StepOut<S, E> {
    #[cfg(windows)]
    fn from_windows(win: WinStepOut<WinCred, E::Win, S::Win>) -> Self {
        match win {
            WinStepOut::Completed(inner) => Self::Finished(ClientContext { inner }),
            WinStepOut::Pending(inner) => Self::Pending(PendingClientContext { inner }),
        }
    }
    #[cfg(unix)]
    fn from_unix(win: UnixStepOut<S::Unix, E::Unix, NoDelegation>) -> Self {
        match win {
            UnixStepOut::Finished(inner) => Self::Finished(ClientContext { inner }),
            UnixStepOut::Pending(inner) => Self::Pending(PendingClientContext { inner }),
        }
    }
}
