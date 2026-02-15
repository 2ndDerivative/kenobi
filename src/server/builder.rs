use std::marker::PhantomData;

use crate::{
    buffer::{RustSecBuffer, RustSecBuffers},
    credentials::Credentials,
    server::{
        StepOut,
        error::AcceptContextError,
        typestate::{DelegationPolicy, NoDelegation, OfferDelegate},
    },
};

pub struct ServerBuilder<Cred, D = NoDelegation> {
    cred: Cred,
    _enc: PhantomData<D>,
}
impl<Cred> ServerBuilder<Cred, NoDelegation> {
    pub fn new_from_credentials(cred: Cred) -> Self {
        Self {
            cred,
            _enc: PhantomData,
        }
    }
    pub fn request_delegation(self) -> ServerBuilder<Cred, OfferDelegate> {
        ServerBuilder {
            cred: self.cred,
            _enc: PhantomData,
        }
    }
}
impl<Cred: AsRef<Credentials>, D: DelegationPolicy> ServerBuilder<Cred, D> {
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<Cred, D>, AcceptContextError> {
        let buf = RustSecBuffer::new_for_token().unwrap();
        let buffers = RustSecBuffers::new(Box::new([buf]));
        super::step(self.cred, None, 0, buffers, token)
    }
}
