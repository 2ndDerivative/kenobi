use std::marker::PhantomData;

use crate::{
    buffer::NonResizableVec,
    cred::Credentials,
    server::{
        MaybeEncrypt, StepOut,
        error::AcceptContextError,
        typestate::{
            DelegationPolicy, EncryptionPolicy, MaybeSign, NoDelegation, NoEncryption, NoSigning, OfferDelegate,
            SigningPolicy,
        },
    },
};
use kenobi_core::cred::usage::InboundUsable;

pub struct ServerBuilder<Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    cred: Credentials<Usage>,
    _enc: PhantomData<(S, E, D)>,
}
impl<Usage> ServerBuilder<Usage, NoSigning, NoEncryption, NoDelegation> {
    pub fn new_from_credentials(cred: Credentials<Usage>) -> Self {
        Self {
            cred,
            _enc: PhantomData,
        }
    }
}
impl<Usage, S, E> ServerBuilder<Usage, S, E, NoDelegation> {
    pub fn request_delegation(self) -> ServerBuilder<Usage, S, E, OfferDelegate> {
        ServerBuilder {
            cred: self.cred,
            _enc: PhantomData,
        }
    }
}
impl<Usage, E, D> ServerBuilder<Usage, NoSigning, E, D> {
    pub fn offer_signing(self) -> ServerBuilder<Usage, MaybeSign, E, D> {
        ServerBuilder {
            cred: self.cred,
            _enc: PhantomData,
        }
    }
}
impl<Usage, S, D> ServerBuilder<Usage, S, NoEncryption, D> {
    pub fn offer_encryption(self) -> ServerBuilder<Usage, S, MaybeEncrypt, D> {
        ServerBuilder {
            cred: self.cred,
            _enc: PhantomData,
        }
    }
}
impl<Usage: InboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy> ServerBuilder<Usage, S, E, D> {
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<Usage, S, E, D>, AcceptContextError> {
        super::step(self.cred, None, 0, NonResizableVec::new(), token)
    }
}
