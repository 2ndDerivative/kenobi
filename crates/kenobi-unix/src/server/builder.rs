use std::sync::Arc;

use kenobi_core::{channel_bindings::Channel, cred::usage::InboundUsable};

use crate::{
    cred::Credentials,
    server::{StepOut, step},
};

#[derive(Debug)]
pub struct ServerBuilder<CU> {
    cred: Arc<Credentials<CU>>,
    channel_bindings: Option<Box<[u8]>>,
}
impl<CU: InboundUsable> ServerBuilder<CU> {
    pub fn new(cred: Arc<Credentials<CU>>) -> ServerBuilder<CU> {
        ServerBuilder {
            cred,
            channel_bindings: None,
        }
    }
}
impl<CU> ServerBuilder<CU> {
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let channel_bindings = channel.channel_bindings()?.map(|v| v.into_boxed_slice());
        Ok(Self {
            channel_bindings,
            ..self
        })
    }
}
impl<CU: InboundUsable> ServerBuilder<CU> {
    pub fn initialize(self, token: &[u8]) -> StepOut<CU> {
        step(None, self.cred, token, self.channel_bindings)
    }
}
