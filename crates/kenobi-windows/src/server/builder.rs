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

pub struct ServerBuilder<'cred, Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    cred: &'cred Credentials<Usage>,
    channel_bindings: Option<Box<[u8]>>,
    _enc: PhantomData<(S, E, D)>,
}
impl<Usage> ServerBuilder<'_, Usage, NoSigning, NoEncryption, NoDelegation> {
    pub fn new_from_credentials<'cred>(
        cred: &'cred Credentials<Usage>,
    ) -> ServerBuilder<'cred, Usage, NoSigning, NoEncryption, NoDelegation> {
        ServerBuilder {
            cred,
            channel_bindings: None,
            _enc: PhantomData,
        }
    }
}
impl<'cred, Usage, S, E> ServerBuilder<'cred, Usage, S, E, NoDelegation> {
    pub fn request_delegation(self) -> ServerBuilder<'cred, Usage, S, E, OfferDelegate> {
        self.convert_policy()
    }
}
impl<'cred, Usage, E, D> ServerBuilder<'cred, Usage, NoSigning, E, D> {
    pub fn offer_signing(self) -> ServerBuilder<'cred, Usage, MaybeSigning, E, D> {
        self.convert_policy()
    }
}
impl<'cred, Usage, S, D> ServerBuilder<'cred, Usage, S, NoEncryption, D> {
    pub fn offer_encryption(self) -> ServerBuilder<'cred, Usage, S, MaybeEncryption, D> {
        self.convert_policy()
    }
}
impl<'cred, Usage, S1, E1, D1> ServerBuilder<'cred, Usage, S1, E1, D1> {
    fn convert_policy<S2, E2, D2>(self) -> ServerBuilder<'cred, Usage, S2, E2, D2> {
        ServerBuilder {
            cred: self.cred,
            channel_bindings: self.channel_bindings,
            _enc: PhantomData,
        }
    }
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<ServerBuilder<'cred, Usage, S1, E1, D1>, C::Error> {
        let channel_bindings = channel.channel_bindings()?.map(|v| v.into_boxed_slice());
        Ok(Self {
            channel_bindings,
            ..self
        })
    }
}
impl<'cred, Usage: InboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy>
    ServerBuilder<'cred, Usage, S, E, D>
{
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<'cred, Usage, S, E, D>, AcceptContextError> {
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
