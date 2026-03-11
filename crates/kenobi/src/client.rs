use kenobi_core::{cred::usage::OutboundUsable, typestate::MaybeDelegation};

#[cfg(unix)]
use kenobi_unix::client::{
    ClientContext as UnixClientContext, PendingClientContext as UnixPendingClientContext, StepOut as UnixStepOut,
};
#[cfg(windows)]
use kenobi_windows::client::{
    ClientContext as WinContext, PendingClientContext as WinPendingClientContext, StepOut as WinStepOut,
};

pub use builder::ClientBuilder;
use kenobi_core::typestate::{
    Encryption, MaybeEncryption, MaybeSigning, NoDelegation, NoEncryption, NoSigning, Signing,
};
pub use typestate::{EncryptionState, SigningState};

use crate::{
    client::typestate::DelegationState,
    cred::{Credentials, CredentialsUsage},
    sign_encrypt::{Signature, UnwrapError, WrapError},
};

mod builder;
mod typestate;

/// A client context that has finished authentication
///
/// This context represents the client side of the authentication, and may have a last token to be delivered to the server.
/// The final token may be used using `ClientContext::last_token`
pub struct ClientContext<Usage, S: SigningState, E: EncryptionState, D: DelegationState> {
    #[cfg(windows)]
    inner: WinContext<Usage, S, E, D>,
    #[cfg(unix)]
    inner: UnixClientContext<Usage, S, E, D>,
}
impl<Usage: CredentialsUsage + OutboundUsable> ClientContext<Usage, NoSigning, NoEncryption, NoDelegation> {
    pub fn new_from_cred(cred: Credentials<Usage>, target_principal: Option<&str>) -> StepOut<Usage> {
        #[cfg(windows)]
        return StepOut::from_windows(WinContext::new_from_cred(cred.inner, target_principal).unwrap());
        #[cfg(unix)]
        StepOut::from_unix(UnixClientContext::<Usage, _, _, _>::new(cred.inner, target_principal).unwrap())
    }
}
#[cfg(windows)]
impl<Usage, S: SigningState, E: EncryptionState, D: DelegationState> ClientContext<Usage, S, E, D> {
    #[must_use]
    pub fn last_token(&self) -> Option<&[u8]> {
        self.inner.last_token()
    }
    #[must_use]
    pub fn session_key(&self) -> impl std::ops::Deref<Target = [u8]> + use<Usage, S, E, D> {
        self.inner.get_session_key().unwrap()
    }
}

#[cfg(unix)]
impl<Usage, S: SigningState, E: EncryptionState, D: DelegationState> ClientContext<'_, Usage, S, E, D> {
    #[must_use]
    pub fn last_token(&self) -> Option<&[u8]> {
        self.inner.last_token()
    }
    #[must_use]
    pub fn session_key(&self) -> impl std::ops::Deref<Target = [u8]> + use<Usage, S, E, D> {
        self.inner.session_key().unwrap()
    }
}
#[cfg(windows)]
impl<Usage, E: EncryptionState, D: DelegationState> ClientContext<Usage, MaybeSigning, E, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_signing(self) -> Result<ClientContext<Usage, Signing, E, D>, ClientContext<Usage, NoSigning, E, D>> {
        self.inner
            .check_signing()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(unix)]
impl<Usage, E: EncryptionState, D: DelegationState> ClientContext<Usage, MaybeSigning, E, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_signing(self) -> Result<ClientContext<Usage, Signing, E, D>, ClientContext<Usage, NoSigning, E, D>> {
        self.inner
            .check_signing()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(windows)]
impl<Usage, S: SigningState, D: DelegationState> ClientContext<Usage, S, MaybeEncryption, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_encryption(
        self,
    ) -> Result<ClientContext<Usage, S, Encryption, D>, ClientContext<Usage, S, NoEncryption, D>> {
        self.inner
            .check_encryption()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(unix)]
impl<Usage, S: SigningState, D: DelegationState> ClientContext<Usage, S, MaybeEncryption, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_encryption(
        self,
    ) -> Result<ClientContext<Usage, S, Encryption, D>, ClientContext<Usage, S, NoEncryption, D>> {
        self.inner
            .check_encryption()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}

impl<Usage, E: EncryptionState, D: DelegationState> ClientContext<Usage, Signing, E, D> {
    pub fn sign(&self, message: &[u8]) -> Result<Signature, WrapError> {
        Ok(Signature::from_inner(
            self.inner.sign(message).map_err(WrapError::from_inner)?,
        ))
    }
    pub fn unwrap(
        &self,
        message: &[u8],
    ) -> Result<impl std::ops::Deref<Target = [u8]> + use<Usage, E, D>, UnwrapError> {
        self.inner.unwrap(message).map_err(UnwrapError::from_inner)
    }
}
impl<Usage, D: DelegationState> ClientContext<Usage, Signing, Encryption, D> {
    pub fn encrypt(&self, message: &[u8]) -> Result<impl std::ops::Deref<Target = [u8]> + use<Usage, D>, WrapError> {
        self.inner.encrypt(message).map_err(WrapError::from_inner)
    }
}

pub struct PendingClientContext<Usage> {
    #[cfg(windows)]
    inner: WinPendingClientContext<Usage>,
    #[cfg(unix)]
    inner: UnixPendingClientContext<Usage>,
}

#[cfg(windows)]
impl<Usage> PendingClientContext<Usage> {
    #[must_use]
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}
#[cfg(unix)]
impl<Usage> PendingClientContext<Usage> {
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}
#[cfg(windows)]
impl<Usage: OutboundUsable> PendingClientContext<Usage> {
    pub fn step(self, token: &[u8]) -> StepOut<Usage> {
        match self.inner.step(token).unwrap() {
            WinStepOut::Completed(inner) => StepOut::Finished(ClientContext { inner }),
            WinStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
}

#[cfg(unix)]
impl<Usage: OutboundUsable> PendingClientContext<Usage> {
    pub fn step(self, token: &[u8]) -> StepOut<Usage> {
        match self.inner.step(token).unwrap() {
            UnixStepOut::Finished(inner) => StepOut::Finished(ClientContext { inner }),
            UnixStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
}

pub enum StepOut<Usage> {
    Pending(PendingClientContext<Usage>),
    Finished(ClientContext<Usage, MaybeSigning, MaybeEncryption, MaybeDelegation>),
}
impl<Usage> StepOut<Usage> {
    #[cfg(windows)]
    fn from_windows(win: WinStepOut<Usage>) -> StepOut<Usage> {
        match win {
            WinStepOut::Completed(inner) => Self::Finished(ClientContext { inner }),
            WinStepOut::Pending(inner) => Self::Pending(PendingClientContext { inner }),
        }
    }
    #[cfg(unix)]
    fn from_unix(win: UnixStepOut<Usage>) -> StepOut<Usage> {
        match win {
            UnixStepOut::Finished(inner) => Self::Finished(ClientContext { inner }),
            UnixStepOut::Pending(inner) => Self::Pending(PendingClientContext { inner }),
        }
    }
}
