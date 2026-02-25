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
use kenobi_core::typestate::{
    Encryption, MaybeEncryption, MaybeSigning, NoDelegation, NoEncryption, NoSigning, Signing,
};
pub use typestate::{EncryptionState, SigningState, UnfinishedEncryptionState, UnfinishedSigningState};

use crate::{
    client::typestate::{DelegationState, UnfinishedDelegationState},
    cred::{Credentials, CredentialsUsage},
    sign_encrypt::{Signature, UnwrapError, WrapError},
};

mod builder;
mod typestate;

/// A client context that has finished authentication
///
/// This context represents the client side of the authentication, and may have a last token to be delivered to the server.
/// The final token may be used using `ClientContext::last_token`
pub struct ClientContext<'cred, Usage, S: SigningState, E: EncryptionState, D: DelegationState> {
    #[cfg(windows)]
    inner: WinContext<'cred, Usage, S, E, D>,
    #[cfg(unix)]
    inner: UnixClientContext<'cred, Usage, S, E, D>,
}
impl<'cred, Usage: CredentialsUsage + OutboundUsable>
    ClientContext<'cred, Usage, NoSigning, NoEncryption, NoDelegation>
{
    pub fn new_from_cred(
        cred: &'cred Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> StepOut<'cred, Usage, NoSigning, NoEncryption, NoDelegation> {
        #[cfg(windows)]
        return StepOut::from_windows(WinContext::new_from_cred(&cred.inner, target_principal).unwrap());
        #[cfg(unix)]
        StepOut::from_unix(UnixClientContext::<Usage, _, _, _>::new(&cred.inner, target_principal).unwrap())
    }
}
#[cfg(windows)]
impl<Usage, S: SigningState, E: EncryptionState, D: DelegationState> ClientContext<'_, Usage, S, E, D> {
    #[must_use]
    pub fn last_token(&self) -> Option<&[u8]> {
        self.inner.last_token()
    }
    #[must_use]
    pub fn session_key(&self) -> impl std::ops::Deref<Target = [u8]> {
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
    pub fn session_key(&self) -> impl std::ops::Deref<Target = [u8]> {
        self.inner.session_key().unwrap()
    }
}
#[cfg(windows)]
impl<'cred, Usage, E: EncryptionState, D: DelegationState> ClientContext<'cred, Usage, MaybeSigning, E, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_signing(
        self,
    ) -> Result<ClientContext<'cred, Usage, Signing, E, D>, ClientContext<'cred, Usage, NoSigning, E, D>> {
        self.inner
            .check_signing()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(unix)]
impl<'cred, Usage, E: EncryptionState, D: DelegationState> ClientContext<'cred, Usage, MaybeSigning, E, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_signing(
        self,
    ) -> Result<ClientContext<'cred, Usage, Signing, E, D>, ClientContext<'cred, Usage, NoSigning, E, D>> {
        self.inner
            .check_signing()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(windows)]
impl<'cred, Usage, S: SigningState, D: DelegationState> ClientContext<'cred, Usage, S, MaybeEncryption, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_encryption(
        self,
    ) -> Result<ClientContext<'cred, Usage, S, Encryption, D>, ClientContext<'cred, Usage, S, NoEncryption, D>> {
        self.inner
            .check_encryption()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}
#[cfg(unix)]
impl<'cred, Usage, S: SigningState, D: DelegationState> ClientContext<'cred, Usage, S, MaybeEncryption, D> {
    pub fn check_encryption(
        self,
    ) -> Result<ClientContext<'cred, Usage, S, Encryption, D>, ClientContext<'cred, Usage, S, NoEncryption, D>> {
        self.inner
            .check_encryption()
            .map(|inner| ClientContext { inner })
            .map_err(|inner| ClientContext { inner })
    }
}

impl<Usage, E: EncryptionState, D: DelegationState> ClientContext<'_, Usage, Signing, E, D> {
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
impl<Usage, D: DelegationState> ClientContext<'_, Usage, Signing, Encryption, D> {
    pub fn encrypt(&self, message: &[u8]) -> Result<impl std::ops::Deref<Target = [u8]> + use<Usage, D>, WrapError> {
        self.inner.encrypt(message).map_err(WrapError::from_inner)
    }
}

pub struct PendingClientContext<
    'cred,
    Usage,
    S: UnfinishedSigningState,
    E: UnfinishedEncryptionState,
    D: UnfinishedDelegationState,
> {
    #[cfg(windows)]
    inner: WinPendingClientContext<'cred, Usage, S, E, D>,
    #[cfg(unix)]
    inner: UnixPendingClientContext<'cred, Usage, S, E, D>,
}

#[cfg(windows)]
impl<Usage, S: UnfinishedSigningState, E: UnfinishedEncryptionState, D: UnfinishedDelegationState>
    PendingClientContext<'_, Usage, S, E, D>
{
    #[must_use]
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}
#[cfg(unix)]
impl<Usage, S: UnfinishedSigningState, E: UnfinishedEncryptionState, D: UnfinishedDelegationState>
    PendingClientContext<'_, Usage, S, E, D>
{
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}
#[cfg(windows)]
impl<
    'cred,
    Usage: OutboundUsable,
    S: UnfinishedSigningState,
    E: UnfinishedEncryptionState,
    D: UnfinishedDelegationState,
> PendingClientContext<'cred, Usage, S, E, D>
{
    pub fn step(self, token: &[u8]) -> StepOut<'cred, Usage, S, E, D> {
        match self.inner.step(token).unwrap() {
            WinStepOut::Completed(inner) => StepOut::Finished(ClientContext { inner }),
            WinStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
}

#[cfg(unix)]
impl<'cred, Usage: OutboundUsable, S: UnfinishedSigningState, E: UnfinishedEncryptionState>
    PendingClientContext<'cred, Usage, S, E>
{
    pub fn step(self, token: &[u8]) -> StepOut<'cred, Usage, S, E> {
        match self.inner.step(token).unwrap() {
            UnixStepOut::Finished(inner) => StepOut::Finished(ClientContext { inner }),
            UnixStepOut::Pending(inner) => StepOut::Pending(PendingClientContext { inner }),
        }
    }
}

pub enum StepOut<'cred, Usage, S: UnfinishedSigningState, E: UnfinishedEncryptionState, D: UnfinishedDelegationState> {
    Pending(PendingClientContext<'cred, Usage, S, E, D>),
    Finished(ClientContext<'cred, Usage, S, E, D>),
}
impl<'cred, Usage, S: UnfinishedSigningState, E: UnfinishedEncryptionState, D: UnfinishedDelegationState>
    StepOut<'cred, Usage, S, E, D>
{
    #[cfg(windows)]
    fn from_windows(win: WinStepOut<'cred, Usage, S, E, D>) -> StepOut<'cred, Usage, S, E, D> {
        match win {
            WinStepOut::Completed(inner) => Self::Finished(ClientContext { inner }),
            WinStepOut::Pending(inner) => Self::Pending(PendingClientContext { inner }),
        }
    }
    #[cfg(unix)]
    fn from_unix(win: UnixStepOut<'cred, Usage, S, E, NoDelegation>) -> StepOut<'cred, Usage, S, E> {
        match win {
            UnixStepOut::Finished(inner) => Self::Finished(ClientContext { inner }),
            UnixStepOut::Pending(inner) => Self::Pending(PendingClientContext { inner }),
        }
    }
}
