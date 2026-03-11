use std::time::Duration;

use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable, flags::CapabilityFlags};
use libgssapi_sys::GSS_C_NT_USER_NAME;

use crate::{
    Error,
    client::{StepOut, step},
    cred::Credentials,
    name::NameHandle,
};

pub struct ClientBuilder<'cred, CU> {
    cred: &'cred Credentials<CU>,
    target_principal: Option<NameHandle>,
    flags: CapabilityFlags,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
}
impl<CU: OutboundUsable> ClientBuilder<'_, CU> {
    pub fn new<'cred>(
        cred: &'cred Credentials<CU>,
        target_principal: Option<&str>,
    ) -> Result<ClientBuilder<'cred, CU>, Error> {
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
impl<'cred, CU> ClientBuilder<'cred, CU> {
    pub fn with_flag(mut self, flags: CapabilityFlags) -> Self {
        self.flags.add_flag(flags);
        self
    }
    pub fn offer_mutual_auth(self) -> Self {
        self.with_flag(CapabilityFlags::MUTUAL_AUTH)
    }
    pub fn request_signing(self) -> Self {
        self.with_flag(CapabilityFlags::INTEGRITY)
    }
    pub fn request_encryption(self) -> Self {
        self.with_flag(CapabilityFlags::CONFIDENTIALITY)
    }
    pub fn allow_delegation(self) -> Self {
        self.with_flag(CapabilityFlags::DELEGATE)
    }
    pub fn request_duration(self, duration: Duration) -> Self {
        Self {
            requested_duration: Some(duration),
            ..self
        }
    }
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let channel_bindings = channel.channel_bindings()?.map(|v| v.into_boxed_slice());
        Ok(Self {
            channel_bindings,
            ..self
        })
    }
}
impl<'cred, CU: OutboundUsable> ClientBuilder<'cred, CU> {
    pub fn initialize(self) -> Result<StepOut<'cred, CU>, Error> {
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
