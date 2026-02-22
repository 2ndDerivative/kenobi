use std::{marker::PhantomData, ops::Deref};

use kenobi_core::cred::usage::Both;
use windows::Win32::{
    Foundation::{SEC_E_INVALID_HANDLE, SEC_E_NO_IMPERSONATION},
    Security::Authentication::Identity::{ImpersonateSecurityContext, RevertSecurityContext},
};

use crate::{
    client::ClientBuilder,
    context_handle::ContextHandle,
    cred::Credentials,
    server::{ServerContext, typestate::CanDelegate},
};

impl<S, E> ServerContext<Both, S, E, CanDelegate> {
    pub fn impersonate_client(&self) -> Result<ImpersonationGuard<'_>, ImpersonationError> {
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

pub struct ImpersonationGuard<'a> {
    context: &'a ContextHandle,
    _enc: PhantomData<Credentials<Both>>,
    _not_threadsafe: PhantomData<*mut ()>,
}
impl ImpersonationGuard<'_> {
    pub fn initialize_client_to(&self, target_principal: &str) -> Result<ClientBuilder<Both>, crate::cred::Error> {
        let creds = Credentials::acquire_default(None)?;
        Ok(ClientBuilder::new_from_credentials(creds, Some(target_principal)))
    }
}
pub struct ImpersonatedCreds(Credentials<Both>, PhantomData<*mut ()>);
impl AsRef<Credentials<Both>> for ImpersonatedCreds {
    fn as_ref(&self) -> &Credentials<Both> {
        &self.0
    }
}
impl<'a> Drop for ImpersonationGuard<'a> {
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
