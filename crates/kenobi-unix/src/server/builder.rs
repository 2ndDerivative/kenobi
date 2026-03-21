use std::sync::Arc;

use kenobi_core::{channel_bindings::Channel, cred::usage::InboundUsable};
use libgssapi_sys::GSS_C_NT_HOSTBASED_SERVICE;

use crate::{
    cred::Credentials,
    name::NameHandle,
    server::{StepOut, step},
};

pub struct ServerBuilder<CU> {
    cred: Arc<Credentials<CU>>,
    channel_bindings: Option<Box<[u8]>>,
    principal: Option<NameHandle>,
}
impl<CU: InboundUsable> ServerBuilder<CU> {
    pub fn new(cred: Arc<Credentials<CU>>, principal: Option<&str>) -> ServerBuilder<CU> {
        let principal = principal
            .map(|p| unsafe { NameHandle::import(p, GSS_C_NT_HOSTBASED_SERVICE) })
            .transpose()
            .unwrap();
        ServerBuilder {
            cred,
            principal,
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
        step(None, self.cred, self.principal, token, self.channel_bindings)
    }
}
