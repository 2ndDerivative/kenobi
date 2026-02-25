use std::marker::PhantomData;

use crate::{
    buffer::NonResizableVec,
    client::{
        StepOut,
        error::InitializeContextError,
        typestate::{DelegationPolicy, EncryptionPolicy, SigningPolicy},
    },
    cred::Credentials,
};
use kenobi_core::typestate::{
    DeniedSigning, MaybeDelegation, MaybeEncryption, MaybeSigning, NoDelegation, NoEncryption, NoSigning,
};
use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable};

pub struct ClientBuilder<'cred, Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    cred: &'cred Credentials<Usage>,
    target_principal: Option<Box<[u16]>>,
    channel_bindings: Option<Box<[u8]>>,
    _enc: PhantomData<(S, E, D)>,
}
impl<Usage> ClientBuilder<'_, Usage, NoSigning, NoEncryption, NoDelegation> {
    pub fn new_from_credentials<'cred>(
        cred: &'cred Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> ClientBuilder<'cred, Usage, NoSigning, NoEncryption, NoDelegation> {
        let target_principal = target_principal.map(crate::to_wide);
        ClientBuilder {
            cred,
            target_principal,
            channel_bindings: None,
            _enc: PhantomData,
        }
    }
}
impl<'cred, Usage, S, D> ClientBuilder<'cred, Usage, S, NoEncryption, D> {
    pub fn request_encryption(self) -> ClientBuilder<'cred, Usage, S, MaybeEncryption, D> {
        self.convert_policy()
    }
}
impl<'cred, Usage, E, D> ClientBuilder<'cred, Usage, NoSigning, E, D> {
    pub fn request_signing(self) -> ClientBuilder<'cred, Usage, MaybeSigning, E, D> {
        self.convert_policy()
    }
    pub fn deny_signing(self) -> ClientBuilder<'cred, Usage, DeniedSigning, E, D> {
        self.convert_policy()
    }
}
impl<'cred, Usage, S, E> ClientBuilder<'cred, Usage, S, E, NoDelegation> {
    pub fn allow_delegation(self) -> ClientBuilder<'cred, Usage, S, E, MaybeDelegation> {
        self.convert_policy()
    }
}
impl<'cred, Usage, S1, E1, D1> ClientBuilder<'cred, Usage, S1, E1, D1> {
    fn convert_policy<S2, E2, D2>(self) -> ClientBuilder<'cred, Usage, S2, E2, D2> {
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
impl<'cred, Usage: OutboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy>
    ClientBuilder<'cred, Usage, S, E, D>
{
    pub fn initialize(self) -> Result<StepOut<'cred, Usage, S, E, D>, InitializeContextError> {
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
