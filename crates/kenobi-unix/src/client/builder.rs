use std::{sync::Arc, time::Duration};

use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable, flags::CapabilityFlags};
use libgssapi_sys::GSS_C_NT_USER_NAME;

use crate::{
    Error,
    client::{StepOut, step},
    cred::Credentials,
    name::NameHandle,
};

#[derive(Debug)]
pub struct ClientBuilder<CU> {
    cred: Arc<Credentials<CU>>,
    target_principal: Option<NameHandle>,
    flags: CapabilityFlags,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
}
impl<CU: OutboundUsable> ClientBuilder<CU> {
    /// # Errors
    /// Returns the error from the underlying Name import
    pub fn new(cred: Arc<Credentials<CU>>, target_principal: Option<&str>) -> Result<ClientBuilder<CU>, Error> {
        let target_principal = target_principal
            .map(|t| unsafe { NameHandle::import(t, GSS_C_NT_USER_NAME) })
            .transpose()?;
        Ok(ClientBuilder {
            cred,
            target_principal,
            flags: CapabilityFlags::default(),
            requested_duration: None,
            channel_bindings: None,
        })
    }
}
impl<CU> ClientBuilder<CU> {
    #[must_use]
    pub fn with_flag(mut self, flags: CapabilityFlags) -> Self {
        self.flags.add_flag(flags);
        self
    }
    #[must_use]
    pub fn request_mutual_auth(self) -> Self {
        self.with_flag(CapabilityFlags::MUTUAL_AUTH)
    }
    #[must_use]
    pub fn request_signing(self) -> Self {
        self.with_flag(CapabilityFlags::INTEGRITY)
    }
    #[must_use]
    pub fn request_encryption(self) -> Self {
        self.with_flag(CapabilityFlags::CONFIDENTIALITY)
    }
    #[must_use]
    pub fn allow_delegation(self) -> Self {
        self.with_flag(CapabilityFlags::DELEGATE)
    }
    #[must_use]
    pub fn request_duration(self, duration: Duration) -> Self {
        Self {
            requested_duration: Some(duration),
            ..self
        }
    }
    /// # Errors
    /// Forwards the failure of the underlying `Channel`
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        match channel.channel_bindings() {
            Err(e) => Err(e),
            Ok(bindings) => Ok(Self {
                channel_bindings: bindings.map(Vec::into_boxed_slice),
                ..self
            }),
        }
    }
}
impl<CU: OutboundUsable> ClientBuilder<CU> {
    pub fn initialize(self) -> Result<StepOut<CU>, Error> {
        step(
            None,
            self.cred,
            self.flags,
            self.target_principal,
            None,
            self.requested_duration,
            self.channel_bindings,
        )
    }
}
