use std::marker::PhantomData;

use windows::Win32::Security::Authentication::Identity::ISC_REQ_MUTUAL_AUTH;

use crate::{
    client::{
        StepOut,
        error::InitializeContextError,
        typestate::{
            CanEncrypt, CanSign, CannotEncrypt, CannotSign, Delegatable, DelegationPolicy, EncryptionPolicy,
            MaybeEncrypt, MaybeSign, NoDelegation, SigningPolicy,
        },
    },
    credentials::Credentials,
};

pub struct ClientBuilder<Cred, E = CannotEncrypt, S = CannotSign, D = NoDelegation> {
    cred: Cred,
    target_principal: Option<Box<[u16]>>,
    _enc: PhantomData<(E, S, D)>,
}
impl<Cred> ClientBuilder<Cred, CannotEncrypt, CannotSign, NoDelegation> {
    pub fn new_from_credentials(cred: Cred, target_principal: Option<&str>) -> Self {
        let target_principal = target_principal.map(crate::to_wide);
        Self {
            cred,
            target_principal,
            _enc: PhantomData,
        }
    }
}
impl<Cred, S, D> ClientBuilder<Cred, CannotEncrypt, S, D> {
    pub fn request_encryption(self) -> ClientBuilder<Cred, MaybeEncrypt, S, D> {
        self.convert_policy()
    }
}
impl<Cred, E, D> ClientBuilder<Cred, E, CannotSign, D> {
    pub fn request_signing(self) -> ClientBuilder<Cred, E, MaybeSign, D> {
        self.convert_policy()
    }
}
impl<Cred, E, S> ClientBuilder<Cred, E, S, NoDelegation> {
    pub fn allow_delegation(self) -> ClientBuilder<Cred, E, S, Delegatable> {
        self.convert_policy()
    }
}
impl<Cred, E1, S1, D1> ClientBuilder<Cred, E1, S1, D1> {
    fn convert_policy<E2, S2, D2>(self) -> ClientBuilder<Cred, E2, S2, D2> {
        ClientBuilder {
            cred: self.cred,
            target_principal: self.target_principal,
            _enc: PhantomData,
        }
    }
}
impl<Cred: AsRef<Credentials>, E: EncryptionPolicy, S: SigningPolicy, D: DelegationPolicy>
    ClientBuilder<Cred, E, S, D>
{
    pub fn initialize(
        self,
        server_init_token: Option<&[u8]>,
    ) -> Result<StepOut<Cred, E, S, D>, InitializeContextError> {
        let requirements = ISC_REQ_MUTUAL_AUTH | E::ADDED_REQ_FLAGS | S::ADDED_REQ_FLAGS | D::ADDED_REQ_FLAGS;
        match super::step(
            self.cred,
            self.target_principal,
            None,
            requirements,
            0,
            None,
            server_init_token,
        )? {
            StepOut::Pending(p) => Ok(StepOut::Pending(p)),
            StepOut::Completed(c) => Ok(StepOut::Completed(c)),
        }
    }
}
