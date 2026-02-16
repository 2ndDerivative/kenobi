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
pub use typestate::{EncryptionState, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, SigningState};

use crate::Credentials;

mod builder;
mod typestate;

pub struct ClientContext<S: SigningState, E: EncryptionState> {
    #[cfg(windows)]
    _inner: WinContext<WinCred, E::Win, S::Win>,
    #[cfg(unix)]
    _inner: UnixClientContext<S::Unix, E::Unix, NoDelegation>,
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

pub struct PendingClientContext<S: SigningState, E: EncryptionState> {
    #[cfg(windows)]
    inner: WinPendingClientContext<WinCred, E::Win, S::Win>,
    #[cfg(unix)]
    inner: UnixPendingClientContext<S::Unix, E::Unix, NoDelegation>,
}

#[cfg(windows)]
impl<S: SigningState, E: EncryptionState> PendingClientContext<S, E>
where
    S::Win: kenobi_windows::client::SigningPolicy,
    E::Win: kenobi_windows::client::EncryptionPolicy,
{
    pub fn step(self, token: &[u8]) -> StepOut<S, E> {
        match self.inner.step(token).unwrap() {
            WinStepOut::Completed(_inner) => StepOut::Finished(ClientContext { _inner }),
            WinStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
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
            UnixStepOut::Finished(_inner) => StepOut::Finished(ClientContext { _inner }),
            UnixStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
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
            WinStepOut::Completed(_inner) => Self::Finished(ClientContext { _inner }),
            WinStepOut::Pending(inner) => Self::Pending(PendingClientContext { inner }),
        }
    }
    #[cfg(unix)]
    fn from_unix(win: UnixStepOut<S::Unix, E::Unix, NoDelegation>) -> Self {
        match win {
            UnixStepOut::Finished(_inner) => Self::Finished(ClientContext { _inner }),
            UnixStepOut::Pending(inner) => Self::Pending(PendingClientContext { inner }),
        }
    }
}
