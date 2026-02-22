use std::{marker::PhantomData, time::Duration};

use kenobi_core::{channel_bindings::Channel, cred::usage::OutboundUsable};
use libgssapi_sys::GSS_C_NT_USER_NAME;

use crate::{
    Error,
    client::{
        MaybeSign, StepOut, step,
        typestate::{
            CannotEncrypt, CannotSign, DelegationPolicy, EncryptionPolicy, MaybeEncrypt, NoDelegation, SignPolicy,
        },
    },
    cred::Credentials,
    name::NameHandle,
};

pub struct ClientBuilder<CU, S, E, D> {
    cred: Credentials<CU>,
    target_principal: Option<NameHandle>,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
    marker: PhantomData<(S, E, D)>,
}
impl<CU: OutboundUsable> ClientBuilder<CU, CannotSign, CannotEncrypt, NoDelegation> {
    pub fn new(
        cred: Credentials<CU>,
        target_principal: Option<&str>,
    ) -> Result<ClientBuilder<CU, CannotSign, CannotEncrypt, NoDelegation>, Error> {
        let target_principal = target_principal
            .map(|t| NameHandle::import(t, unsafe { GSS_C_NT_USER_NAME }))
            .transpose()?;
        Ok(ClientBuilder {
            cred,
            target_principal,
            requested_duration: None,
            channel_bindings: None,
            marker: PhantomData,
        })
    }
}
impl<CU, E, D> ClientBuilder<CU, CannotSign, E, D> {
    pub fn request_signing(self) -> ClientBuilder<CU, MaybeSign, E, D> {
        self.convert_policy()
    }
}
impl<CU, S, D> ClientBuilder<CU, S, CannotEncrypt, D> {
    pub fn request_encryption(self) -> ClientBuilder<CU, S, MaybeEncrypt, D> {
        self.convert_policy()
    }
}
impl<CU, S1, E1, D1> ClientBuilder<CU, S1, E1, D1> {
    fn convert_policy<S2, E2, D2>(self) -> ClientBuilder<CU, S2, E2, D2> {
        ClientBuilder {
            cred: self.cred,
            target_principal: self.target_principal,
            requested_duration: self.requested_duration,
            channel_bindings: None,
            marker: PhantomData,
        }
    }
    pub fn request_duration(self, duration: Duration) -> Self {
        Self {
            requested_duration: Some(duration),
            ..self
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
impl<CU, S: SignPolicy, E: EncryptionPolicy, D: DelegationPolicy> ClientBuilder<CU, S, E, D> {
    pub fn initialize(self) -> Result<StepOut<CU, S, E, D>, Error> {
        step(
            None,
            self.cred,
            self.target_principal,
            None,
            self.requested_duration,
            self.channel_bindings,
        )
    }
}
