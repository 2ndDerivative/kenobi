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
use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable};

pub struct ClientBuilder<Usage, S = CannotSign, E = CannotEncrypt, D = NoDelegation> {
    cred: Credentials<Usage>,
    target_principal: Option<Box<[u16]>>,
    channel_bindings: Option<Box<[u8]>>,
    _enc: PhantomData<(S, E, D)>,
}
impl<Usage> ClientBuilder<Usage, CannotSign, CannotEncrypt, NoDelegation> {
    pub fn new_from_credentials(cred: Credentials<Usage>, target_principal: Option<&str>) -> Self {
        let target_principal = target_principal.map(crate::to_wide);
        Self {
            cred,
            target_principal,
            channel_bindings: None,
            _enc: PhantomData,
        }
    }
}
impl<Usage, S, D> ClientBuilder<Usage, S, CannotEncrypt, D> {
    pub fn request_encryption(self) -> ClientBuilder<Usage, S, MaybeEncrypt, D> {
        self.convert_policy()
    }
}
impl<Usage, E, D> ClientBuilder<Usage, CannotSign, E, D> {
    pub fn request_signing(self) -> ClientBuilder<Usage, MaybeSign, E, D> {
        self.convert_policy()
    }
}
impl<Usage, S, E> ClientBuilder<Usage, S, E, NoDelegation> {
    pub fn allow_delegation(self) -> ClientBuilder<Usage, S, E, Delegatable> {
        self.convert_policy()
    }
}
impl<Usage, S1, E1, D1> ClientBuilder<Usage, S1, E1, D1> {
    fn convert_policy<S2, E2, D2>(self) -> ClientBuilder<Usage, S2, E2, D2> {
        ClientBuilder {
            cred: self.cred,
            target_principal: self.target_principal,
            channel_bindings: self.channel_bindings,
            _enc: PhantomData,
        }
    }
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let channel_bindings = channel.channel_bindings()?.map(|v| v.into_boxed_slice());
        Ok(Self {
            channel_bindings,
            ..self
        })
    }
}
impl<Usage: OutboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy> ClientBuilder<Usage, S, E, D> {
    pub fn initialize(self) -> Result<StepOut<Usage, S, E, D>, InitializeContextError> {
        match super::step(
            self.cred,
            self.target_principal,
            None,
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
