use kenobi_core::cred::usage::OutboundUsable;
#[cfg(unix)]
use kenobi_unix::client::{
    ClientContext as UnixClientContext, NoDelegation, PendingClientContext as UnixPendingClientContext,
    StepOut as UnixStepOut,
};
#[cfg(windows)]
use kenobi_windows::client::{
    ClientContext as WinContext, PendingClientContext as WinPendingClientContext, StepOut as WinStepOut,
};

pub use builder::ClientBuilder;
pub use typestate::{
    Encryption, EncryptionState, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing, SigningState,
    UnfinishedEncryptionState, UnfinishedSigningState,
};

use crate::{Credentials, CredentialsUsage, sign_encrypt::Signature};

mod builder;
mod typestate;

/// A client context that has finished authentication
///
/// This context represents the client side of the authentication, and may have a last token to be delivered to the server.
/// The final token may be used using `ClientContext::last_token`
pub struct ClientContext<Usage, S: SigningState, E: EncryptionState> {
    #[cfg(windows)]
    inner: WinContext<Usage, E::Win, S::Win>,
    #[cfg(unix)]
    inner: UnixClientContext<S::Unix, E::Unix, NoDelegation>,
}
impl<Usage: CredentialsUsage + OutboundUsable> ClientContext<Usage, typestate::NoSigning, typestate::NoEncryption> {
    pub fn new_from_cred(
        cred: Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> StepOut<Usage, typestate::NoSigning, typestate::NoEncryption> {
        #[cfg(windows)]
        return StepOut::from_windows(WinContext::new_from_cred(cred.into_platform(), target_principal).unwrap());
        #[cfg(unix)]
        StepOut::from_unix(UnixClientContext::new_from_cred(cred.into_platform(), target_principal).unwrap())
    }
}
#[cfg(windows)]
impl<Usage, S: SigningState, E: EncryptionState> ClientContext<Usage, S, E> {
    pub fn last_token(&self) -> Option<&[u8]> {
        self.inner.last_token()
    }
    pub fn session_key(&self) -> impl std::ops::Deref<Target = [u8]> {
        self.inner.get_session_key()
    }
}

#[cfg(unix)]
impl<S: SigningState, E: EncryptionState> ClientContext<S, E> {
    pub fn last_token(&self) -> Option<&[u8]> {
        self.inner.last_token()
    }
    pub fn session_key(&self) -> impl std::ops::Deref<Target = [u8]> {
        self.inner.session_key().unwrap()
    }
}
#[cfg(windows)]
impl<Usage, E: EncryptionState> ClientContext<Usage, MaybeSigning, E> {
    pub fn check_signing(self) -> Result<ClientContext<Usage, Signing, E>, ClientContext<Usage, NoSigning, E>> {
        self.inner
            .check_signing()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(unix)]
impl<E: EncryptionState> ClientContext<MaybeSigning, E> {
    pub fn check_signing(self) -> Result<ClientContext<Signing, E>, ClientContext<NoSigning, E>> {
        self.inner
            .check_signing()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(windows)]
impl<Usage, S: SigningState> ClientContext<Usage, S, MaybeEncryption> {
    pub fn check_encryption(
        self,
    ) -> Result<ClientContext<Usage, S, Encryption>, ClientContext<Usage, S, NoEncryption>> {
        self.inner
            .check_encryption()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(unix)]
impl<S: SigningState> ClientContext<S, MaybeEncryption> {
    pub fn check_encryption(self) -> Result<ClientContext<S, Encryption>, ClientContext<S, NoEncryption>> {
        self.inner
            .check_encryption()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}

impl<Usage, E: EncryptionState> ClientContext<Usage, Signing, E> {
    #[cfg(windows)]
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        Signature::from_inner(self.inner.sign_message(message))
    }
    #[cfg(windows)]
    pub fn verify_message(&self, message: &[u8]) {
        self.inner.verify_message(message).unwrap();
    }
    #[cfg(unix)]
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        Signature::from_inner(self.inner.sign_message(message).unwrap())
    }
    #[cfg(unix)]
    pub fn verify_message(&self, message: &[u8]) {
        self.inner.unwrap_message(message).unwrap();
    }
}

pub struct PendingClientContext<Usage, S: UnfinishedSigningState, E: UnfinishedEncryptionState> {
    #[cfg(windows)]
    inner: WinPendingClientContext<Usage, E::Win, S::Win>,
    #[cfg(unix)]
    inner: UnixPendingClientContext<S::Unix, E::Unix, NoDelegation>,
}

#[cfg(windows)]
impl<Usage, S: UnfinishedSigningState, E: UnfinishedEncryptionState> PendingClientContext<Usage, S, E> {
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}
#[cfg(unix)]
impl<S: UnfinishedSigningState, E: UnfinishedEncryptionState> PendingClientContext<S, E> {
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}
#[cfg(windows)]
impl<Usage: OutboundUsable, S: UnfinishedSigningState, E: UnfinishedEncryptionState> PendingClientContext<Usage, S, E> {
    pub fn step(self, token: &[u8]) -> StepOut<Usage, S, E> {
        match self.inner.step(token).unwrap() {
            WinStepOut::Completed(inner) => StepOut::Finished(ClientContext { inner }),
            WinStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
}

#[cfg(unix)]
impl<S: UnfinishedSigningState, E: UnfinishedEncryptionState> PendingClientContext<S, E> {
    pub fn step(self, token: &[u8]) -> StepOut<S, E> {
        match self.inner.step(token).unwrap() {
            UnixStepOut::Finished(inner) => StepOut::Finished(ClientContext { inner }),
            UnixStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
}

pub enum StepOut<Usage, S: UnfinishedSigningState, E: UnfinishedEncryptionState> {
    Pending(PendingClientContext<Usage, S, E>),
    Finished(ClientContext<Usage, S, E>),
}
impl<Usage, S: UnfinishedSigningState, E: UnfinishedEncryptionState> StepOut<Usage, S, E> {
    #[cfg(windows)]
    fn from_windows(win: WinStepOut<Usage, E::Win, S::Win>) -> Self {
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
