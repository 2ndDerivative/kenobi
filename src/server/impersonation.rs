use std::{marker::PhantomData, ops::Deref};

use windows::Win32::{
    Foundation::{SEC_E_INVALID_HANDLE, SEC_E_NO_IMPERSONATION},
    Security::Authentication::Identity::{ImpersonateSecurityContext, RevertSecurityContext},
};

use crate::{
    client::ClientBuilder,
    context_handle::ContextHandle,
    credentials::{Credentials, CredentialsUsage},
    server::{ServerContext, typestate::CanDelegate},
};

impl<Cred> ServerContext<Cred, CanDelegate> {
    pub fn impersonate_client(&self) -> Result<ImpersonationGuard<'_, Cred>, ImpersonationError> {
        match unsafe { ImpersonateSecurityContext(self.context.deref()) } {
            Ok(()) => Ok(ImpersonationGuard {
                context: &self.context,
                _enc: PhantomData,
                _not_threadsafe: PhantomData,
            }),
            Err(e) if e.code().0 == SEC_E_NO_IMPERSONATION.0 => Err(ImpersonationError::NoImpersonation),
            Err(e) if e.code().0 == SEC_E_INVALID_HANDLE.0 => Err(ImpersonationError::InvalidHandle),
            _ => unreachable!(),
        }
    }
}

pub struct ImpersonationGuard<'a, Cred> {
    context: &'a ContextHandle,
    _enc: PhantomData<Cred>,
    _not_threadsafe: PhantomData<*mut ()>,
}
impl<Cred> ImpersonationGuard<'_, Cred> {
    pub fn initialize_client_to(&self, target_principal: &str) -> ClientBuilder<ImpersonatedCreds> {
        let creds = Credentials::acquire_default(CredentialsUsage::Outbound, None);
        ClientBuilder::new_from_credentials(ImpersonatedCreds(creds, PhantomData), Some(target_principal))
    }
}
pub struct ImpersonatedCreds(Credentials, PhantomData<*mut ()>);
impl AsRef<Credentials> for ImpersonatedCreds {
    fn as_ref(&self) -> &Credentials {
        &self.0
    }
}
impl<'a, Cred> Drop for ImpersonationGuard<'a, Cred> {
    fn drop(&mut self) {
        let _ = unsafe { RevertSecurityContext(self.context.deref()) };
    }
}

#[derive(Debug)]
pub enum ImpersonationError {
    InvalidHandle,
    NoImpersonation,
}
impl std::error::Error for ImpersonationError {}
impl std::fmt::Display for ImpersonationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHandle => write!(f, "Invalid handle passed to ImpersionateSecurityContext"),
            Self::NoImpersonation => write!(f, "Client could not be impersonated"),
        }
    }
}
