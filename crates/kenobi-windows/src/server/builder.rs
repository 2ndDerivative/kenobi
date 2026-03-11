use crate::{
    buffer::NonResizableVec,
    cred::Credentials,
    server::{StepOut, error::AcceptContextError},
};
use kenobi_core::{channel_bindings::Channel, cred::usage::InboundUsable, flags::CapabilityFlags};

pub struct ServerBuilder<'cred, Usage> {
    cred: &'cred Credentials<Usage>,
    channel_bindings: Option<Box<[u8]>>,
    flags: CapabilityFlags,
}
impl<Usage> ServerBuilder<'_, Usage> {
    pub fn new_from_credentials<'cred>(cred: &'cred Credentials<Usage>) -> ServerBuilder<'cred, Usage> {
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
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let channel_bindings = channel.channel_bindings()?.map(|v| v.into_boxed_slice());
        Ok(Self {
            channel_bindings,
            ..self
        })
    }
}
impl<'cred, Usage: InboundUsable> ServerBuilder<'cred, Usage> {
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<'cred, Usage>, AcceptContextError> {
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
