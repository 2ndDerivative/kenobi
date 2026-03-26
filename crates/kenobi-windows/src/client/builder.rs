use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    sync::Arc,
};

use crate::{
    buffer::NonResizableVec,
    client::{StepOut, error::InitializeContextError},
    cred::Credentials,
};
use kenobi_core::flags::CapabilityFlags;
use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable};

pub struct ClientBuilder<Usage> {
    cred: Arc<Credentials<Usage>>,
    flags: CapabilityFlags,
    target_principal: Option<Box<[u16]>>,
    channel_bindings: Option<Box<[u8]>>,
}
impl<Usage> Debug for ClientBuilder<Usage> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ClientBuilder")
            .field("cred", &self.cred)
            .field("flags", &self.flags)
            .field(
                "target_principal",
                &self.target_principal.as_ref().map(|b| String::from_utf16_lossy(b)),
            )
            .field("channel_bindings", &self.channel_bindings)
            .finish()
    }
}
impl<Usage> ClientBuilder<Usage> {
    pub fn new_from_credentials(cred: Arc<Credentials<Usage>>, target_principal: Option<&str>) -> ClientBuilder<Usage> {
        let target_principal = target_principal.map(crate::to_wide);
        ClientBuilder {
            cred,
            target_principal,
            flags: CapabilityFlags::default(),
            channel_bindings: None,
        }
    }
    pub fn with_flag(mut self, flag: CapabilityFlags) -> Self {
        self.flags.add_flag(flag);
        self
    }
    pub fn request_mutual_auth(self) -> Self {
        self.with_flag(CapabilityFlags::MUTUAL_AUTH)
    }
    pub fn request_encryption(self) -> Self {
        self.with_flag(CapabilityFlags::CONFIDENTIALITY)
    }
    pub fn request_signing(self) -> Self {
        self.with_flag(CapabilityFlags::INTEGRITY)
    }
    pub fn allow_delegation(self) -> Self {
        self.with_flag(CapabilityFlags::DELEGATE)
    }
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
impl<Usage: OutboundUsable> ClientBuilder<Usage> {
    pub fn initialize(self) -> Result<StepOut<Usage>, InitializeContextError> {
        match super::step(
            self.cred,
            self.target_principal,
            None,
            self.flags,
            0,
            NonResizableVec::new(),
            self.channel_bindings.as_deref(),
            None,
        )? {
            StepOut::Pending(p) => Ok(StepOut::Pending(p)),
            StepOut::Completed(c) => Ok(StepOut::Completed(c)),
        }
    }
}
