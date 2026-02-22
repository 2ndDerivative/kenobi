use std::marker::PhantomData;

use crate::{
    buffer::NonResizableVec,
    cred::Credentials,
    server::{
        StepOut,
        error::AcceptContextError,
        typestate::{DelegationPolicy, MaybeSign, NoDelegation, NoSigning, OfferDelegate, SigningPolicy},
    },
};
use kenobi_core::cred::usage::InboundUsable;

pub struct ServerBuilder<Usage, S, D = NoDelegation> {
    cred: Credentials<Usage>,
    _enc: PhantomData<(S, D)>,
}
impl<Usage> ServerBuilder<Usage, NoSigning, NoDelegation> {
    pub fn new_from_credentials(cred: Credentials<Usage>) -> Self {
        Self {
            cred,
            _enc: PhantomData,
        }
    }
}
impl<Usage, S> ServerBuilder<Usage, S, NoDelegation> {
    pub fn request_delegation(self) -> ServerBuilder<Usage, S, OfferDelegate> {
        ServerBuilder {
            cred: self.cred,
            _enc: PhantomData,
        }
    }
}
impl<Usage, D> ServerBuilder<Usage, NoSigning, D> {
    pub fn offer_signing(self) -> ServerBuilder<Usage, MaybeSign, D> {
        ServerBuilder {
            cred: self.cred,
            _enc: PhantomData,
        }
    }
}
impl<Usage: InboundUsable, S: SigningPolicy, D: DelegationPolicy> ServerBuilder<Usage, S, D> {
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<Usage, S, D>, AcceptContextError> {
        super::step(self.cred, None, 0, NonResizableVec::new(), token)
    }
}
