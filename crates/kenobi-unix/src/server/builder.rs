use std::sync::Arc;

use kenobi_core::{channel_bindings::Channel, cred::usage::InboundUsable};

use crate::{
    Error,
    cred::Credentials,
    server::{StepOut, step},
};

#[derive(Debug)]
pub struct ServerBuilder<CU> {
    cred: Arc<Credentials<CU>>,
    channel_bindings: Option<Box<[u8]>>,
}
impl<CU: InboundUsable> ServerBuilder<CU> {
    #[must_use]
    pub fn new(cred: Arc<Credentials<CU>>) -> ServerBuilder<CU> {
        ServerBuilder {
            cred,
            channel_bindings: None,
        }
    }
}
impl<CU> ServerBuilder<CU> {
    /// # Errors
    /// Forwards the failure of the underlying `Channel`
    pub fn bind_to_channel(self, channel: &impl Channel) -> Result<Self, impl std::error::Error> {
        match channel.channel_bindings() {
            Err(e) => Err(e),
            Ok(bindings) => Ok(Self {
                channel_bindings: bindings.map(Vec::into_boxed_slice),
                ..self
            }),
        }
    }
}
impl<CU: InboundUsable> ServerBuilder<CU> {
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<CU>, Error> {
        step(None, self.cred, token, self.channel_bindings.as_deref())
    }
}
