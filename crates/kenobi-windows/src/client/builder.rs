use std::marker::PhantomData;

use crate::{
    buffer::NonResizableVec,
    client::{
        StepOut,
        error::InitializeContextError,
        typestate::{
            CannotEncrypt, CannotSign, Delegatable, DelegationPolicy, EncryptionPolicy, MaybeEncrypt, MaybeSign,
            NoDelegation, SigningPolicy,
        },
    },
    cred::Credentials,
};
use kenobi_core::cred::usage::OutboundUsable;

pub struct ClientBuilder<Usage, E = CannotEncrypt, S = CannotSign, D = NoDelegation> {
    cred: Credentials<Usage>,
    target_principal: Option<Box<[u16]>>,
    _enc: PhantomData<(E, S, D)>,
}
impl<Usage> ClientBuilder<Usage, CannotEncrypt, CannotSign, NoDelegation> {
    pub fn new_from_credentials(cred: Credentials<Usage>, target_principal: Option<&str>) -> Self {
        let target_principal = target_principal.map(crate::to_wide);
        Self {
            cred,
            target_principal,
            _enc: PhantomData,
        }
    }
}
impl<Usage, S, D> ClientBuilder<Usage, CannotEncrypt, S, D> {
    pub fn request_encryption(self) -> ClientBuilder<Usage, MaybeEncrypt, S, D> {
        self.convert_policy()
    }
}
impl<Usage, E, D> ClientBuilder<Usage, E, CannotSign, D> {
    pub fn request_signing(self) -> ClientBuilder<Usage, E, MaybeSign, D> {
        self.convert_policy()
    }
}
impl<Usage, E, S> ClientBuilder<Usage, E, S, NoDelegation> {
    pub fn allow_delegation(self) -> ClientBuilder<Usage, E, S, Delegatable> {
        self.convert_policy()
    }
}
impl<Usage, E1, S1, D1> ClientBuilder<Usage, E1, S1, D1> {
    fn convert_policy<E2, S2, D2>(self) -> ClientBuilder<Usage, E2, S2, D2> {
        ClientBuilder {
            cred: self.cred,
            target_principal: self.target_principal,
            _enc: PhantomData,
        }
    }
}
impl<Usage: OutboundUsable, E: EncryptionPolicy, S: SigningPolicy, D: DelegationPolicy> ClientBuilder<Usage, E, S, D> {
    pub fn initialize(self) -> Result<StepOut<Usage, E, S, D>, InitializeContextError> {
        match super::step(self.cred, self.target_principal, None, 0, NonResizableVec::new(), None)? {
            StepOut::Pending(p) => Ok(StepOut::Pending(p)),
            StepOut::Completed(c) => Ok(StepOut::Completed(c)),
        }
    }
}
