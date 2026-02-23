use std::marker::PhantomData;

use crate::{
    buffer::NonResizableVec,
    cred::Credentials,
    server::{
        StepOut,
        error::AcceptContextError,
        typestate::{DelegationPolicy, EncryptionPolicy, NoDelegation, OfferDelegate, SigningPolicy},
    },
};
use kenobi_core::{
    channel_bindings::Channel,
    cred::usage::InboundUsable,
    typestate::{MaybeEncryption, MaybeSigning, NoEncryption, NoSigning},
};

pub struct ServerBuilder<Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    cred: Credentials<Usage>,
    channel_bindings: Option<Box<[u8]>>,
    _enc: PhantomData<(S, E, D)>,
}
impl<Usage> ServerBuilder<Usage, NoSigning, NoEncryption, NoDelegation> {
    pub fn new_from_credentials(cred: Credentials<Usage>) -> Self {
        Self {
            cred,
            channel_bindings: None,
            _enc: PhantomData,
        }
    }
}
impl<Usage, S, E> ServerBuilder<Usage, S, E, NoDelegation> {
    pub fn request_delegation(self) -> ServerBuilder<Usage, S, E, OfferDelegate> {
        self.convert_policy()
    }
}
impl<Usage, E, D> ServerBuilder<Usage, NoSigning, E, D> {
    pub fn offer_signing(self) -> ServerBuilder<Usage, MaybeSigning, E, D> {
        self.convert_policy()
    }
}
impl<Usage, S, D> ServerBuilder<Usage, S, NoEncryption, D> {
    pub fn offer_encryption(self) -> ServerBuilder<Usage, S, MaybeEncryption, D> {
        self.convert_policy()
    }
}
impl<Usage, S1, E1, D1> ServerBuilder<Usage, S1, E1, D1> {
    fn convert_policy<S2, E2, D2>(self) -> ServerBuilder<Usage, S2, E2, D2> {
        ServerBuilder {
            cred: self.cred,
            channel_bindings: self.channel_bindings,
            _enc: PhantomData,
        }
    }
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<ServerBuilder<Usage, S1, E1, D1>, C::Error> {
        let channel_bindings = channel.channel_bindings()?.map(|v| v.into_boxed_slice());
        Ok(Self {
            channel_bindings,
            ..self
        })
    }
}
impl<Usage: InboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy> ServerBuilder<Usage, S, E, D> {
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<Usage, S, E, D>, AcceptContextError> {
        super::step(
            self.cred,
            None,
            0,
            NonResizableVec::new(),
            self.channel_bindings.as_deref(),
            token,
        )
    }
}
