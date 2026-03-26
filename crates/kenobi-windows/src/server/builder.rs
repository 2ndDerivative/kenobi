use std::sync::Arc;

use crate::{
    buffer::NonResizableVec,
    cred::Credentials,
    server::{StepOut, error::AcceptContextError},
};
use kenobi_core::{channel_bindings::Channel, cred::usage::InboundUsable, flags::CapabilityFlags};

#[derive(Debug)]
pub struct ServerBuilder<Usage> {
    cred: Arc<Credentials<Usage>>,
    channel_bindings: Option<Box<[u8]>>,
    flags: CapabilityFlags,
}
impl<Usage> ServerBuilder<Usage> {
    pub fn new_from_credentials(cred: Arc<Credentials<Usage>>) -> ServerBuilder<Usage> {
        ServerBuilder {
            cred,
            channel_bindings: None,
            flags: CapabilityFlags::default(),
        }
    }
    pub fn with_flag(mut self, flag: CapabilityFlags) -> Self {
        self.flags.add_flag(flag);
        self
    }
    pub fn offer_mutual_auth(self) -> Self {
        self.with_flag(CapabilityFlags::MUTUAL_AUTH)
    }
    pub fn request_delegation(self) -> Self {
        self.with_flag(CapabilityFlags::DELEGATE)
    }
    pub fn offer_signing(self) -> Self {
        self.with_flag(CapabilityFlags::INTEGRITY)
    }
    pub fn offer_encryption(self) -> Self {
        self.with_flag(CapabilityFlags::CONFIDENTIALITY)
    }
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, impl std::error::Error> {
        match channel.channel_bindings() {
            Err(e) => Err(e),
            Ok(bindings) => Ok(Self {
                channel_bindings: bindings.map(Vec::into_boxed_slice),
                ..self
            }),
        }
    }
}
impl<Usage: InboundUsable> ServerBuilder<Usage> {
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<Usage>, AcceptContextError> {
        super::step(
            self.cred,
            None,
            self.flags,
            0,
            NonResizableVec::new(),
            self.channel_bindings.as_deref(),
            token,
        )
    }
}
